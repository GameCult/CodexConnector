use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use cultcache_rs::{CacheBackingStore, SingleFileMessagePackBackingStore};
use cultnet_rs::{
    CultNetMessage, CultNetRawDocumentRecord, CultNetRawPayloadEncoding,
    CultNetRudpSocketTransportConnection, CultNetRudpSocketTransportOptions, CultNetWireContract,
    encode_cultnet_message_to_vec,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CODEX_CONNECTOR_IDUNN_HEALTH_CONTRACT: &str =
    "codex-connector.cultnet-rudp-service-health";
const HEALTH_SCHEMA: &str = "idunn.signed_daemon_health.v1";
const IDENTITY_SCHEMA: &str = "gamecult.provider_health_identity.private.v1";
const IDENTITY_TYPE: &str = "gamecult.provider_health_identity.private.v1";
const IDENTITY_KEY: &str = "gamecult-provider-health-identity";
const ID_DOMAIN: &[u8] = b"gamecult.provider-health.identity.v1\0";
const SIGNATURE_DOMAIN: &[u8] = b"gamecult.provider-health.signature.v1\0";
const SIGNATURE_PURPOSE: &[u8] = b"idunn.signed_daemon_health.v1";
const PROTECTOR_CONTEXT: &str = "gamecult-provider-health-identity-v1";
const RUDP_PROTOCOL_ID: &str = "cultnet.transport.rudp.v0";
const DEPLOYMENT_SCHEMA: &str = "gamecult.codex_connector.deployment.v2";
const ACTIVATION_SCHEMA: &str = "gamecult.codex_connector.activation.v2";
const TRAFFIC_ADMISSION_PATH: &str = "/etc/gamecult/codex-connector/runtime/traffic-admission.cc";
const TRAFFIC_ADMISSION_TYPE: &str = "idunn.runtime_traffic_admission";
const TRAFFIC_ADMISSION_SCHEMA: &str = "idunn.runtime_traffic_admission.v2";
const TRAFFIC_ADMISSION_KEY: &str = "yggdrasil-codex-connector";
const TOOLCHAIN_SCHEMA: &str = "gamecult.codex_connector.codex_toolchain.v1";
const SOURCE_TOOLCHAIN_MANIFEST: &str = include_str!("../deployment/codex-linux-x64.manifest");
const BUILD_COMMIT: &str = match option_env!("CODEX_CONNECTOR_BUILD_COMMIT") {
    Some(value) => value,
    None => "development",
};
// Idunn's daemon-health ingress owns one shared RUDP connection contract.
// Publisher identity is carried by the signed record, not by transport IDs.
const RUDP_CONNECTION_ID: u32 = 0x1d0d_0001;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderHealthIdentity {
    schema_version: String,
    identity_id: String,
    #[serde(with = "serde_bytes")]
    public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    protected_private_seed: Vec<u8>,
    protector_kind: String,
    protector_binding: String,
    protector_version: String,
    assurance: String,
    created_at: String,
    #[serde(with = "serde_bytes")]
    enrollment_nonce: Vec<u8>,
}

struct ProviderHealthSigner {
    entry: ProviderHealthIdentity,
    key: SigningKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectorReleaseBinding {
    release_id: String,
    release_witness_sha256: String,
    source_commit: String,
    deployment_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConnectorActivationBinding {
    activation_witness_sha256: String,
}

// Idunn owns and writes this CultCache schema. Connector carries only the
// exact read-side projection needed to consume that root admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrafficAdmissionConsumerProjection {
    schema_version: String,
    daemon_id: String,
    release_id: String,
    release_witness_sha256: String,
    source_commit: String,
    deployment_id: String,
    activation_witness_sha256: String,
    signed_health_sha256: String,
    publisher_incarnation_id: String,
    publisher_sequence: u64,
    signer_identity_id: String,
    runtime_process_id: u32,
    runtime_process_starttime_ticks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RuntimeProcessInstanceBinding {
    process_id: u32,
    starttime_ticks: u64,
}

#[derive(Clone)]
pub(crate) struct ConnectorTrafficAdmissionGate {
    path: PathBuf,
    expected: TrafficAdmissionConsumerProjection,
}

pub(crate) struct PublishedHealthStatementIdentity {
    daemon_id: String,
    signed_health_sha256: String,
    publisher_incarnation_id: String,
    publisher_sequence: u64,
    signer_identity_id: String,
}

impl ConnectorTrafficAdmissionGate {
    pub(crate) fn from_environment(
        release: &ConnectorReleaseBinding,
        activation: &ConnectorActivationBinding,
        published: &PublishedHealthStatementIdentity,
    ) -> Result<Self> {
        let raw_path = std::env::var("CODEX_CONNECTOR_TRAFFIC_ADMISSION")
            .context("CODEX_CONNECTOR_TRAFFIC_ADMISSION is required for signed health")?;
        let path = fixed_traffic_admission_path(&raw_path)?;
        Ok(Self {
            path,
            expected: traffic_admission_expectation(release, activation, published)?,
        })
    }

    pub(crate) fn wait_until_granted(&self, timeout: Duration) -> Result<()> {
        let started = Instant::now();
        let mut last_invalid_observation = None;
        loop {
            match self.is_current() {
                Ok(true) => return Ok(()),
                Ok(false) => last_invalid_observation = None,
                Err(error) => last_invalid_observation = Some(format!("{error:#}")),
            }
            if started.elapsed() >= timeout {
                let detail = last_invalid_observation
                    .as_deref()
                    .unwrap_or("the fixed admission record remained absent");
                bail!(
                    "timed out waiting for exact sealed root traffic admission {}: {}",
                    self.path.display(),
                    detail,
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub(crate) fn require_current(&self) -> Result<()> {
        if !self.is_current()? {
            bail!(
                "root traffic admission disappeared from {}",
                self.path.display()
            );
        }
        Ok(())
    }

    fn is_current(&self) -> Result<bool> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspecting connector traffic admission {}",
                        self.path.display()
                    )
                });
            }
        }
        let lock_path = sibling_lock_path(&self.path)?;
        require_runtime_capability_file(&self.path, "connector traffic admission")?;
        require_runtime_capability_file(&lock_path, "connector traffic admission lock")?;
        // This is a pull-only capability read. Connector never registers,
        // creates, migrates, or writes Idunn's traffic-admission store.
        SingleFileMessagePackBackingStore::new(&self.path)
            .with_read_only_shared_snapshot(|entries| {
                let [envelope] = entries.as_slice() else {
                    bail!("connector traffic admission store must contain exactly one record");
                };
                if envelope.key != TRAFFIC_ADMISSION_KEY
                    || envelope.r#type != TRAFFIC_ADMISSION_TYPE
                    || envelope.schema_id.as_deref() != Some(TRAFFIC_ADMISSION_SCHEMA)
                {
                    bail!("connector traffic admission store has the wrong typed envelope");
                }
                let admitted = decode_traffic_admission_payload(&envelope.payload)?;
                require_exact_traffic_admission(&admitted, &self.expected)?;
                Ok(true)
            })
            .with_context(|| {
                format!(
                    "reading connector traffic admission {}",
                    self.path.display()
                )
            })
    }
}

fn fixed_traffic_admission_path(raw_path: &str) -> Result<PathBuf> {
    if raw_path != TRAFFIC_ADMISSION_PATH {
        bail!("connector traffic admission path is not the fixed root policy path");
    }
    Ok(PathBuf::from(raw_path))
}

impl ConnectorActivationBinding {
    fn validate(&self) -> Result<()> {
        if !self
            .activation_witness_sha256
            .strip_prefix("sha256-")
            .is_some_and(|digest| is_lower_hex(digest, 64))
        {
            bail!("connector activation binding is malformed");
        }
        Ok(())
    }
}

impl ConnectorReleaseBinding {
    fn validate(&self) -> Result<()> {
        require_id(&self.release_id, "release id")?;
        require_deployment_id(&self.deployment_id)?;
        if !self
            .release_witness_sha256
            .strip_prefix("sha256-")
            .is_some_and(|digest| is_lower_hex(digest, 64))
            || !is_lower_hex(&self.source_commit, 40)
        {
            bail!("connector release binding is malformed");
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DeploymentWitness {
    release_id: String,
    source_commit: String,
    connector_binary_sha256: String,
    codex_package_url: String,
    codex_package_sha256: String,
    codex_binary_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ToolchainManifest {
    package_url: String,
    package_sha256: String,
    binary_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActivationWitness {
    activation_id: String,
    config_path: String,
    config_sha256: String,
    config_epoch: u32,
    bind: String,
    codex_executable_path: String,
    codex_executable_sha256: String,
    codex_home_path: String,
    replay_store_path: String,
    max_frame_bytes: usize,
    max_connections: usize,
    socket_timeout_ms: u64,
    max_expiry_skew_ms: u64,
    callers: Vec<ActivationCallerWitness>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActivationCallerWitness {
    runtime_id: String,
    connection_key_path: String,
    connection_key_sha256: String,
    connection_key_epoch: u32,
    allowed_models: Vec<String>,
    max_concurrent_requests: usize,
    max_payload_bytes: usize,
    max_output_tokens: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedDaemonHealth {
    schema_version: String,
    daemon_id: String,
    health_contract: String,
    source_runtime_id: String,
    state: String,
    detail: String,
    signer_identity_id: String,
    publisher_incarnation_id: String,
    publisher_sequence: u64,
    observed_at_unix_millis: u64,
    release_id: Option<String>,
    release_witness_sha256: Option<String>,
    source_commit: Option<String>,
    deployment_id: Option<String>,
    signature_algorithm: String,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    private_state_exposed: bool,
    activation_witness_sha256: Option<String>,
}

impl SignedDaemonHealth {
    fn validate(&self) -> Result<()> {
        for (value, label) in [
            (&self.daemon_id, "daemon id"),
            (&self.health_contract, "health contract"),
            (&self.source_runtime_id, "runtime id"),
            (&self.signer_identity_id, "signer identity"),
            (&self.publisher_incarnation_id, "publisher incarnation"),
        ] {
            require_id(value, label)?;
        }
        if self.schema_version != HEALTH_SCHEMA
            || !matches!(
                self.state.as_str(),
                "active" | "warming" | "degraded" | "failed"
            )
            || self.detail.len() > 512
            || self.detail.chars().any(char::is_control)
            || self.publisher_sequence == 0
            || self.observed_at_unix_millis == 0
            || self.signature_algorithm != "ed25519"
            || self.signature.len() != 64
            || self.private_state_exposed
        {
            bail!("signed daemon health shape is invalid");
        }
        ConnectorReleaseBinding {
            release_id: self
                .release_id
                .clone()
                .ok_or_else(|| anyhow!("signed health release id is absent"))?,
            release_witness_sha256: self
                .release_witness_sha256
                .clone()
                .ok_or_else(|| anyhow!("signed health release witness is absent"))?,
            source_commit: self
                .source_commit
                .clone()
                .ok_or_else(|| anyhow!("signed health source commit is absent"))?,
            deployment_id: self
                .deployment_id
                .clone()
                .ok_or_else(|| anyhow!("signed health deployment id is absent"))?,
        }
        .validate()?;
        ConnectorActivationBinding {
            activation_witness_sha256: self
                .activation_witness_sha256
                .clone()
                .ok_or_else(|| anyhow!("signed health activation witness is absent"))?,
        }
        .validate()?;
        Ok(())
    }
}

pub(crate) struct ProviderHealthPublisher {
    endpoint: SocketAddr,
    daemon_id: String,
    runtime_id: String,
    contract: String,
    signer: ProviderHealthSigner,
    release: ConnectorReleaseBinding,
    activation: ConnectorActivationBinding,
    incarnation: String,
    sequence: u64,
}

impl ProviderHealthPublisher {
    pub(crate) fn open(
        endpoint: SocketAddr,
        daemon_id: impl Into<String>,
        runtime_id: impl Into<String>,
        contract: impl Into<String>,
        identity_store: &Path,
        release: ConnectorReleaseBinding,
        activation: ConnectorActivationBinding,
    ) -> Result<Self> {
        let daemon_id = daemon_id.into();
        let runtime_id = runtime_id.into();
        let contract = contract.into();
        require_id(&daemon_id, "daemon id")?;
        require_id(&runtime_id, "runtime id")?;
        require_id(&contract, "health contract")?;
        release.validate()?;
        activation.validate()?;
        Ok(Self {
            endpoint,
            daemon_id,
            runtime_id,
            contract,
            signer: open_identity(identity_store)?,
            release,
            activation,
            incarnation: uuid::Uuid::new_v4().to_string(),
            sequence: 0,
        })
    }

    pub(crate) fn publish(
        &mut self,
        state: &str,
        detail: &str,
    ) -> Result<PublishedHealthStatementIdentity> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("health publisher sequence overflow"))?;
        let mut record = SignedDaemonHealth {
            schema_version: HEALTH_SCHEMA.into(),
            daemon_id: self.daemon_id.clone(),
            health_contract: self.contract.clone(),
            source_runtime_id: self.runtime_id.clone(),
            state: state.into(),
            detail: detail.into(),
            signer_identity_id: self.signer.entry.identity_id.clone(),
            publisher_incarnation_id: self.incarnation.clone(),
            publisher_sequence: self.sequence,
            observed_at_unix_millis: chrono::Utc::now().timestamp_millis().try_into()?,
            release_id: Some(self.release.release_id.clone()),
            release_witness_sha256: Some(self.release.release_witness_sha256.clone()),
            source_commit: Some(self.release.source_commit.clone()),
            deployment_id: Some(self.release.deployment_id.clone()),
            signature_algorithm: "ed25519".into(),
            signature: Vec::new(),
            private_state_exposed: false,
            activation_witness_sha256: Some(self.activation.activation_witness_sha256.clone()),
        };
        let unsigned = unsigned_record(&record)?;
        record.signature = self
            .signer
            .key
            .sign(&signing_message(&unsigned))
            .to_bytes()
            .to_vec();
        record.validate()?;
        let signed_health_sha256 = publish(self.endpoint, &self.runtime_id, &record)?;
        Ok(PublishedHealthStatementIdentity {
            daemon_id: record.daemon_id,
            signed_health_sha256,
            publisher_incarnation_id: record.publisher_incarnation_id,
            publisher_sequence: record.publisher_sequence,
            signer_identity_id: record.signer_identity_id,
        })
    }
}

pub(crate) fn active_release_binding(
    codex_executable: &Path,
    configured_codex_sha256: &[u8; 32],
) -> Result<ConnectorReleaseBinding> {
    let connector_executable = std::env::current_exe().context("locating active connector")?;
    let release_root = connector_executable
        .parent()
        .ok_or_else(|| anyhow!("active connector has no release directory"))?;
    let witness_path = release_root.join("DEPLOYMENT");
    let expected_codex = release_root.join("codex");
    for (path, label, directory) in [
        (release_root, "connector release directory", true),
        (
            connector_executable.as_path(),
            "active connector executable",
            false,
        ),
        (witness_path.as_path(), "connector release witness", false),
        (expected_codex.as_path(), "active Codex executable", false),
    ] {
        require_root_sealed(path, label, directory)?;
    }
    let source_toolchain = parse_toolchain_manifest(SOURCE_TOOLCHAIN_MANIFEST)?;
    release_binding_from_artifacts(
        &connector_executable,
        codex_executable,
        configured_codex_sha256,
        BUILD_COMMIT,
        &required_runtime_deployment_id()?,
        &source_toolchain,
    )
}

pub(crate) fn active_activation_binding(
    config_path: &Path,
    config_bytes: &[u8],
    config: &crate::daemon::CodexDaemonConfig,
    callers: &[crate::daemon::LoadedCallerKeyBinding],
) -> Result<ConnectorActivationBinding> {
    let witness_path = PathBuf::from(
        std::env::var("CODEX_CONNECTOR_ACTIVATION_WITNESS")
            .context("CODEX_CONNECTOR_ACTIVATION_WITNESS is required for signed health")?,
    );
    if !witness_path.is_absolute() {
        bail!("connector activation witness path is not absolute");
    }
    require_root_controlled_runtime_file(config_path, "connector configuration")?;
    require_root_controlled_runtime_file(&witness_path, "connector activation witness")?;
    for caller in callers {
        require_root_controlled_runtime_file(&caller.connection_key_file, "connector caller key")?;
    }
    activation_binding_from_material(config_path, config_bytes, config, callers, &witness_path)
}

fn activation_binding_from_material(
    config_path: &Path,
    config_bytes: &[u8],
    config: &crate::daemon::CodexDaemonConfig,
    callers: &[crate::daemon::LoadedCallerKeyBinding],
    witness_path: &Path,
) -> Result<ConnectorActivationBinding> {
    let witness_bytes = std::fs::read(witness_path)
        .with_context(|| format!("reading activation witness {}", witness_path.display()))?;
    let witness = parse_activation_witness(&witness_bytes)?;
    let expected = activation_expectation(
        witness.activation_id.clone(),
        config_path,
        config_bytes,
        config,
        callers,
    )?;
    if witness != expected {
        bail!("activation witness does not bind the complete loaded connector policy");
    }
    let binding = ConnectorActivationBinding {
        activation_witness_sha256: format!("sha256-{}", hex(&Sha256::digest(&witness_bytes))),
    };
    binding.validate()?;
    Ok(binding)
}

fn activation_expectation(
    activation_id: String,
    config_path: &Path,
    config_bytes: &[u8],
    config: &crate::daemon::CodexDaemonConfig,
    callers: &[crate::daemon::LoadedCallerKeyBinding],
) -> Result<ActivationWitness> {
    require_deployment_id(&activation_id)
        .context("activation witness launch identity is malformed")?;
    config
        .validate()
        .map_err(|error| anyhow!("loaded connector policy is invalid: {error}"))?;
    if config.callers.len() != callers.len() {
        bail!("loaded connector caller material does not match typed policy");
    }
    let mut expected_callers = Vec::with_capacity(callers.len());
    for (policy, loaded) in config.callers.iter().zip(callers) {
        if policy.caller_runtime_id != loaded.caller_runtime_id
            || policy.connection_key_file != loaded.connection_key_file
            || policy.connection_key_epoch != loaded.connection_key_epoch
        {
            bail!("loaded connector caller material does not match typed policy");
        }
        expected_callers.push(ActivationCallerWitness {
            runtime_id: policy.caller_runtime_id.clone(),
            connection_key_path: absolute_utf8_path(
                &policy.connection_key_file,
                "connector caller key",
            )?,
            connection_key_sha256: hex(&loaded.raw_file_sha256),
            connection_key_epoch: policy.connection_key_epoch,
            allowed_models: policy.allowed_models.clone(),
            max_concurrent_requests: policy.max_concurrent_requests,
            max_payload_bytes: policy.max_payload_bytes,
            max_output_tokens: policy.max_output_tokens,
        });
    }
    Ok(ActivationWitness {
        activation_id,
        config_path: absolute_utf8_path(config_path, "connector configuration")?,
        config_sha256: hex(&Sha256::digest(config_bytes)),
        config_epoch: config.epoch,
        bind: config.bind.clone(),
        codex_executable_path: absolute_utf8_path(&config.codex_executable, "Codex executable")?,
        codex_executable_sha256: hex(&config.codex_executable_sha256),
        codex_home_path: absolute_utf8_path(&config.codex_home, "Codex home")?,
        replay_store_path: absolute_utf8_path(&config.replay_store, "connector replay store")?,
        max_frame_bytes: config.max_frame_bytes,
        max_connections: config.max_connections,
        socket_timeout_ms: config.socket_timeout_ms,
        max_expiry_skew_ms: config.max_expiry_skew_ms,
        callers: expected_callers,
    })
}

fn absolute_utf8_path(path: &Path, label: &str) -> Result<String> {
    if !path.is_absolute() {
        bail!("{label} path is not absolute");
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("{label} path is not UTF-8"))
}

fn release_binding_from_artifacts(
    connector_executable: &Path,
    codex_executable: &Path,
    configured_codex_sha256: &[u8; 32],
    compiled_commit: &str,
    deployment_id: &str,
    source_toolchain: &ToolchainManifest,
) -> Result<ConnectorReleaseBinding> {
    require_deployment_id(deployment_id)?;
    if !is_lower_hex(compiled_commit, 40) {
        bail!("compiled connector source commit is unavailable or malformed");
    }
    let connector_executable = canonical_regular_file(connector_executable, "connector binary")?;
    let release_root = connector_executable
        .parent()
        .ok_or_else(|| anyhow!("active connector has no release directory"))?;
    if connector_executable
        .file_name()
        .and_then(|name| name.to_str())
        != Some("codex-connector")
    {
        bail!("active connector executable has an unexpected name");
    }
    let expected_codex_path = release_root.join("codex");
    if codex_executable != expected_codex_path.as_path() {
        bail!("configured Codex binary is not the active release's direct Codex artifact");
    }
    let expected_codex = canonical_regular_file(&expected_codex_path, "Codex binary")?;
    let configured_codex = canonical_regular_file(codex_executable, "configured Codex binary")?;
    if configured_codex != expected_codex {
        bail!("configured Codex binary is outside the active connector release");
    }
    let witness_path = release_root.join("DEPLOYMENT");
    let witness_bytes = std::fs::read(&witness_path)
        .with_context(|| format!("reading release witness {}", witness_path.display()))?;
    let witness = parse_deployment_witness(&witness_bytes)?;
    if witness.source_commit != compiled_commit {
        bail!("release witness does not bind the compiled connector source commit");
    }
    if witness.codex_package_url != source_toolchain.package_url
        || witness.codex_package_sha256 != source_toolchain.package_sha256
        || witness.codex_binary_sha256 != source_toolchain.binary_sha256
    {
        bail!("release witness does not bind the source-owned Codex toolchain manifest");
    }
    let release_directory = release_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("connector release directory is not UTF-8"))?;
    if witness.release_id != release_directory
        || witness.release_id
            != format!(
                "{}-{}",
                witness.source_commit,
                &witness.codex_binary_sha256[..12]
            )
    {
        bail!("release witness does not bind its release directory");
    }
    let connector_sha256 = sha256_file(&connector_executable)?;
    if witness.connector_binary_sha256 != connector_sha256 {
        bail!("release witness does not bind the active connector executable");
    }
    let codex_sha256 = sha256_file(&configured_codex)?;
    if witness.codex_binary_sha256 != codex_sha256
        || witness.codex_binary_sha256 != hex(configured_codex_sha256)
    {
        bail!("release witness does not bind the active configured Codex executable");
    }
    let release = ConnectorReleaseBinding {
        release_id: witness.release_id,
        release_witness_sha256: format!("sha256-{}", hex(&Sha256::digest(&witness_bytes))),
        source_commit: witness.source_commit,
        deployment_id: deployment_id.to_owned(),
    };
    release.validate()?;
    Ok(release)
}

fn parse_deployment_witness(bytes: &[u8]) -> Result<DeploymentWitness> {
    let text = std::str::from_utf8(bytes).context("release witness is not UTF-8")?;
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| anyhow!("release witness has no canonical final newline"))?;
    if body.contains('\r') {
        bail!("release witness contains noncanonical line endings");
    }
    let lines = body.split('\n').collect::<Vec<_>>();
    let [
        schema,
        release_id,
        source_commit,
        connector_binary_sha256,
        codex_package_url,
        codex_package_sha256,
        codex_binary_sha256,
    ] = lines.as_slice()
    else {
        bail!("release witness has an unexpected field set");
    };
    if exact_manifest_value(schema, "schema_version")? != DEPLOYMENT_SCHEMA {
        bail!("release witness schema is not admitted");
    }
    let witness = DeploymentWitness {
        release_id: exact_manifest_value(release_id, "release_id")?.to_owned(),
        source_commit: exact_manifest_value(source_commit, "source_commit")?.to_owned(),
        connector_binary_sha256: exact_manifest_value(connector_binary_sha256, "binary_sha256")?
            .to_owned(),
        codex_package_url: exact_manifest_value(codex_package_url, "codex_package_url")?.to_owned(),
        codex_package_sha256: exact_manifest_value(codex_package_sha256, "codex_package_sha256")?
            .to_owned(),
        codex_binary_sha256: exact_manifest_value(codex_binary_sha256, "codex_binary_sha256")?
            .to_owned(),
    };
    require_id(&witness.release_id, "release id")?;
    if !is_lower_hex(&witness.source_commit, 40)
        || !is_lower_hex(&witness.connector_binary_sha256, 64)
    {
        bail!("release witness contains malformed artifact identity");
    }
    validate_toolchain_artifacts(
        &witness.codex_package_url,
        &witness.codex_package_sha256,
        &witness.codex_binary_sha256,
    )?;
    Ok(witness)
}

fn parse_activation_witness(bytes: &[u8]) -> Result<ActivationWitness> {
    let text = std::str::from_utf8(bytes).context("activation witness is not UTF-8")?;
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| anyhow!("activation witness has no canonical final newline"))?;
    if body.contains('\r') {
        bail!("activation witness contains noncanonical line endings");
    }
    let lines = body.split('\n').collect::<Vec<_>>();
    let mut cursor = 0;
    if next_manifest_value(&lines, &mut cursor, "schema_version")? != ACTIVATION_SCHEMA {
        bail!("activation witness schema is not admitted");
    }
    let activation_id = next_manifest_value(&lines, &mut cursor, "activation_id")?.to_owned();
    let config_path = next_manifest_value(&lines, &mut cursor, "config_path")?.to_owned();
    let config_sha256 = next_manifest_value(&lines, &mut cursor, "config_sha256")?.to_owned();
    let config_epoch =
        parse_canonical_u32(next_manifest_value(&lines, &mut cursor, "config_epoch")?)?;
    let bind = next_manifest_value(&lines, &mut cursor, "bind")?.to_owned();
    let codex_executable_path =
        next_manifest_value(&lines, &mut cursor, "codex_executable_path")?.to_owned();
    let codex_executable_sha256 =
        next_manifest_value(&lines, &mut cursor, "codex_executable_sha256")?.to_owned();
    let codex_home_path = next_manifest_value(&lines, &mut cursor, "codex_home_path")?.to_owned();
    let replay_store_path =
        next_manifest_value(&lines, &mut cursor, "replay_store_path")?.to_owned();
    let max_frame_bytes =
        parse_canonical_usize(next_manifest_value(&lines, &mut cursor, "max_frame_bytes")?)?;
    let max_connections =
        parse_canonical_usize(next_manifest_value(&lines, &mut cursor, "max_connections")?)?;
    let socket_timeout_ms = parse_canonical_u64(next_manifest_value(
        &lines,
        &mut cursor,
        "socket_timeout_ms",
    )?)?;
    let max_expiry_skew_ms = parse_canonical_u64(next_manifest_value(
        &lines,
        &mut cursor,
        "max_expiry_skew_ms",
    )?)?;
    let caller_count =
        parse_canonical_usize(next_manifest_value(&lines, &mut cursor, "caller_count")?)?;
    require_deployment_id(&activation_id)
        .context("activation witness launch identity is malformed")?;
    if config_epoch == 0
        || max_frame_bytes == 0
        || max_connections == 0
        || socket_timeout_ms == 0
        || max_expiry_skew_ms == 0
        || caller_count == 0
        || caller_count > lines.len()
        || !Path::new(&config_path).is_absolute()
        || !Path::new(&codex_executable_path).is_absolute()
        || !Path::new(&codex_home_path).is_absolute()
        || !Path::new(&replay_store_path).is_absolute()
        || !is_lower_hex(&config_sha256, 64)
        || !is_lower_hex(&codex_executable_sha256, 64)
    {
        bail!("activation witness configuration identity is malformed");
    }
    let mut callers = Vec::with_capacity(caller_count);
    for index in 0..caller_count {
        let runtime_id =
            next_manifest_value(&lines, &mut cursor, &format!("caller.{index}.runtime_id"))?
                .to_owned();
        let connection_key_path = next_manifest_value(
            &lines,
            &mut cursor,
            &format!("caller.{index}.connection_key_path"),
        )?
        .to_owned();
        let connection_key_sha256 = next_manifest_value(
            &lines,
            &mut cursor,
            &format!("caller.{index}.connection_key_sha256"),
        )?
        .to_owned();
        let connection_key_epoch = parse_canonical_u32(next_manifest_value(
            &lines,
            &mut cursor,
            &format!("caller.{index}.connection_key_epoch"),
        )?)?;
        let allowed_model_count = parse_canonical_usize(next_manifest_value(
            &lines,
            &mut cursor,
            &format!("caller.{index}.allowed_model_count"),
        )?)?;
        if allowed_model_count == 0 || allowed_model_count > lines.len().saturating_sub(cursor) {
            bail!("activation witness caller model set is malformed");
        }
        let mut allowed_models = Vec::with_capacity(allowed_model_count);
        for model_index in 0..allowed_model_count {
            let model = next_manifest_value(
                &lines,
                &mut cursor,
                &format!("caller.{index}.allowed_model.{model_index}"),
            )?
            .to_owned();
            require_id(&model, "activation caller model")?;
            allowed_models.push(model);
        }
        let max_concurrent_requests = parse_canonical_usize(next_manifest_value(
            &lines,
            &mut cursor,
            &format!("caller.{index}.max_concurrent_requests"),
        )?)?;
        let max_payload_bytes = parse_canonical_usize(next_manifest_value(
            &lines,
            &mut cursor,
            &format!("caller.{index}.max_payload_bytes"),
        )?)?;
        let max_output_tokens = parse_canonical_u32(next_manifest_value(
            &lines,
            &mut cursor,
            &format!("caller.{index}.max_output_tokens"),
        )?)?;
        require_id(&runtime_id, "activation caller runtime")?;
        if connection_key_epoch == 0
            || max_concurrent_requests == 0
            || max_payload_bytes == 0
            || max_output_tokens == 0
            || !Path::new(&connection_key_path).is_absolute()
            || !is_lower_hex(&connection_key_sha256, 64)
        {
            bail!("activation witness caller identity is malformed");
        }
        callers.push(ActivationCallerWitness {
            runtime_id,
            connection_key_path,
            connection_key_sha256,
            connection_key_epoch,
            allowed_models,
            max_concurrent_requests,
            max_payload_bytes,
            max_output_tokens,
        });
    }
    if cursor != lines.len() {
        bail!("activation witness has an unexpected field set");
    }
    Ok(ActivationWitness {
        activation_id,
        config_path,
        config_sha256,
        config_epoch,
        bind,
        codex_executable_path,
        codex_executable_sha256,
        codex_home_path,
        replay_store_path,
        max_frame_bytes,
        max_connections,
        socket_timeout_ms,
        max_expiry_skew_ms,
        callers,
    })
}

fn next_manifest_value<'a>(
    lines: &'a [&'a str],
    cursor: &mut usize,
    name: &str,
) -> Result<&'a str> {
    let line = lines
        .get(*cursor)
        .ok_or_else(|| anyhow!("manifest field {name} is absent"))?;
    *cursor += 1;
    exact_manifest_value(line, name)
}

fn parse_canonical_u32(value: &str) -> Result<u32> {
    let parsed = value
        .parse::<u32>()
        .context("activation witness integer is malformed")?;
    if parsed.to_string() != value {
        bail!("activation witness integer is noncanonical");
    }
    Ok(parsed)
}

fn parse_canonical_u64(value: &str) -> Result<u64> {
    let parsed = value
        .parse::<u64>()
        .context("activation witness integer is malformed")?;
    if parsed.to_string() != value {
        bail!("activation witness integer is noncanonical");
    }
    Ok(parsed)
}

fn parse_canonical_usize(value: &str) -> Result<usize> {
    let parsed = value
        .parse::<usize>()
        .context("activation witness integer is malformed")?;
    if parsed.to_string() != value {
        bail!("activation witness integer is noncanonical");
    }
    Ok(parsed)
}

fn current_runtime_process_instance() -> Result<RuntimeProcessInstanceBinding> {
    let process_id = std::process::id();
    if process_id == 0 {
        bail!("current connector process id is invalid");
    }
    let stat = std::fs::read_to_string("/proc/self/stat")
        .context("reading current connector /proc starttime")?;
    Ok(RuntimeProcessInstanceBinding {
        process_id,
        starttime_ticks: parse_proc_stat_starttime(&stat, process_id)?,
    })
}

fn parse_proc_stat_starttime(stat: &str, expected_process_id: u32) -> Result<u64> {
    let stat = stat.strip_suffix('\n').unwrap_or(stat);
    if stat.contains('\r') || stat.contains('\n') {
        bail!("current connector /proc stat has noncanonical line endings");
    }
    let prefix = format!("{expected_process_id} (");
    if !stat.starts_with(&prefix) {
        bail!("current connector /proc stat has the wrong process id");
    }
    let command_end = stat
        .rfind(") ")
        .context("current connector /proc stat has no command terminator")?;
    let fields = stat[command_end + 2..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    if fields.len() <= 19 || fields[0].len() != 1 {
        bail!("current connector /proc stat is missing starttime");
    }
    let value = fields[19];
    let starttime_ticks = value
        .parse::<u64>()
        .context("current connector /proc starttime is malformed")?;
    if starttime_ticks == 0 || starttime_ticks.to_string() != value {
        bail!("current connector /proc starttime is noncanonical");
    }
    Ok(starttime_ticks)
}

fn traffic_admission_expectation(
    release: &ConnectorReleaseBinding,
    activation: &ConnectorActivationBinding,
    published: &PublishedHealthStatementIdentity,
) -> Result<TrafficAdmissionConsumerProjection> {
    release.validate()?;
    activation.validate()?;
    require_id(&published.daemon_id, "traffic admission daemon id")?;
    require_id(
        &published.publisher_incarnation_id,
        "traffic admission publisher incarnation",
    )?;
    require_id(
        &published.signer_identity_id,
        "traffic admission signer identity",
    )?;
    if published.daemon_id != TRAFFIC_ADMISSION_KEY
        || published.publisher_sequence == 0
        || !published
            .signed_health_sha256
            .strip_prefix("sha256-")
            .is_some_and(|digest| is_lower_hex(digest, 64))
    {
        bail!("signed health digest for traffic admission is malformed");
    }
    let process = current_runtime_process_instance()?;
    let expected = TrafficAdmissionConsumerProjection {
        schema_version: TRAFFIC_ADMISSION_SCHEMA.into(),
        daemon_id: published.daemon_id.clone(),
        release_id: release.release_id.clone(),
        release_witness_sha256: release.release_witness_sha256.clone(),
        source_commit: release.source_commit.clone(),
        deployment_id: release.deployment_id.clone(),
        activation_witness_sha256: activation.activation_witness_sha256.clone(),
        signed_health_sha256: published.signed_health_sha256.clone(),
        publisher_incarnation_id: published.publisher_incarnation_id.clone(),
        publisher_sequence: published.publisher_sequence,
        signer_identity_id: published.signer_identity_id.clone(),
        runtime_process_id: process.process_id,
        runtime_process_starttime_ticks: process.starttime_ticks,
    };
    validate_traffic_admission_projection(&expected)?;
    Ok(expected)
}

fn decode_traffic_admission_payload(bytes: &[u8]) -> Result<TrafficAdmissionConsumerProjection> {
    let admission: TrafficAdmissionConsumerProjection =
        rmp_serde::from_slice(bytes).context("decoding typed connector traffic admission")?;
    if rmp_serde::to_vec(&admission)? != bytes {
        bail!("connector traffic admission payload is not canonical positional MessagePack");
    }
    validate_traffic_admission_projection(&admission)?;
    Ok(admission)
}

fn validate_traffic_admission_projection(
    admission: &TrafficAdmissionConsumerProjection,
) -> Result<()> {
    if admission.schema_version != TRAFFIC_ADMISSION_SCHEMA
        || admission.daemon_id != TRAFFIC_ADMISSION_KEY
        || admission.publisher_sequence == 0
        || admission.runtime_process_id == 0
        || admission.runtime_process_starttime_ticks == 0
    {
        bail!("connector traffic admission typed identity is invalid");
    }
    require_id(&admission.release_id, "traffic admission release id")?;
    require_deployment_id(&admission.deployment_id)?;
    require_id(
        &admission.signer_identity_id,
        "traffic admission signer identity",
    )?;
    uuid::Uuid::parse_str(&admission.publisher_incarnation_id)
        .context("traffic admission publisher incarnation is malformed")?;
    if !admission
        .release_witness_sha256
        .strip_prefix("sha256-")
        .is_some_and(|digest| is_lower_hex(digest, 64))
        || !is_lower_hex(&admission.source_commit, 40)
        || !admission
            .activation_witness_sha256
            .strip_prefix("sha256-")
            .is_some_and(|digest| is_lower_hex(digest, 64))
        || !admission
            .signed_health_sha256
            .strip_prefix("sha256-")
            .is_some_and(|digest| is_lower_hex(digest, 64))
    {
        bail!("connector traffic admission authority identity is malformed");
    }
    Ok(())
}

fn require_exact_traffic_admission(
    admitted: &TrafficAdmissionConsumerProjection,
    expected: &TrafficAdmissionConsumerProjection,
) -> Result<()> {
    if admitted != expected {
        bail!("root traffic admission does not match the exact startup statement");
    }
    Ok(())
}

fn parse_toolchain_manifest(text: &str) -> Result<ToolchainManifest> {
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| anyhow!("source toolchain manifest has no canonical final newline"))?;
    if body.contains('\r') {
        bail!("source toolchain manifest contains noncanonical line endings");
    }
    let lines = body.split('\n').collect::<Vec<_>>();
    let [schema, package_url, package_sha256, binary_sha256] = lines.as_slice() else {
        bail!("source toolchain manifest has an unexpected field set");
    };
    if exact_manifest_value(schema, "schema_version")? != TOOLCHAIN_SCHEMA {
        bail!("source toolchain manifest schema is not admitted");
    }
    let manifest = ToolchainManifest {
        package_url: exact_manifest_value(package_url, "package_url")?.to_owned(),
        package_sha256: exact_manifest_value(package_sha256, "package_sha256")?.to_owned(),
        binary_sha256: exact_manifest_value(binary_sha256, "binary_sha256")?.to_owned(),
    };
    validate_toolchain_artifacts(
        &manifest.package_url,
        &manifest.package_sha256,
        &manifest.binary_sha256,
    )?;
    Ok(manifest)
}

fn validate_toolchain_artifacts(
    package_url: &str,
    package_sha256: &str,
    binary_sha256: &str,
) -> Result<()> {
    if !is_lower_hex(package_sha256, 64)
        || !is_lower_hex(binary_sha256, 64)
        || !package_url.starts_with("https://registry.npmjs.org/@openai/codex/-/codex-")
        || !package_url.ends_with("-linux-x64.tgz")
    {
        bail!("Codex toolchain artifact identity is malformed");
    }
    Ok(())
}

fn exact_manifest_value<'a>(line: &'a str, name: &str) -> Result<&'a str> {
    let value = line
        .strip_prefix(&format!("{name}="))
        .ok_or_else(|| anyhow!("manifest field {name} is misplaced or absent"))?;
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        bail!("manifest field {name} is malformed");
    }
    Ok(value)
}

fn required_runtime_deployment_id() -> Result<String> {
    let deployment_id = std::env::var("CODEX_CONNECTOR_IDUNN_DEPLOYMENT_REQUEST_ID")
        .context("CODEX_CONNECTOR_IDUNN_DEPLOYMENT_REQUEST_ID is required for signed health")?;
    require_deployment_id(&deployment_id)?;
    Ok(deployment_id)
}

fn require_deployment_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        bail!("Idunn deployment request identity is malformed");
    }
    Ok(())
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf> {
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("locating {label} {}", path.display()))?;
    if !std::fs::metadata(&path)?.is_file() {
        bail!("{label} is not a regular file");
    }
    Ok(path)
}

fn require_root_sealed(path: &Path, label: &str, directory: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    let wrong_kind = if directory {
        !metadata.is_dir()
    } else {
        !metadata.is_file()
    };
    if metadata.file_type().is_symlink()
        || wrong_kind
        || metadata.uid() != 0
        || metadata.mode() & 0o222 != 0
    {
        bail!("{label} is not a root-owned immutable direct artifact");
    }
    Ok(())
}

fn require_root_controlled_runtime_file(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("{label} path is not absolute");
    }

    let mut current = Some(path);
    let mut leaf = true;
    while let Some(component) = current {
        let metadata = std::fs::symlink_metadata(component)
            .with_context(|| format!("inspecting {label} path {}", component.display()))?;
        if metadata.file_type().is_symlink()
            || (leaf && !metadata.is_file())
            || (!leaf && !metadata.is_dir())
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            bail!("{label} path is not directly root-controlled");
        }

        leaf = false;
        current = component.parent().filter(|parent| *parent != component);
    }

    Ok(())
}

fn sibling_lock_path(path: &Path) -> Result<PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| anyhow!("runtime capability path has no file name"))?
        .to_os_string();
    name.push(".lock");
    Ok(path.with_file_name(name))
}

fn require_runtime_capability_file(path: &Path, label: &str) -> Result<()> {
    require_root_controlled_runtime_file(path, label)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{label} has no parent directory"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .with_context(|| format!("inspecting {label} parent {}", parent.display()))?;
    let leaf_metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    if parent_metadata.uid() != 0
        || parent_metadata.mode() & 0o7777 != 0o750
        || leaf_metadata.uid() != 0
        || leaf_metadata.gid() != parent_metadata.gid()
        || leaf_metadata.mode() & 0o7777 != 0o640
    {
        bail!("{label} custody is not the exact root-to-runtime-group read boundary");
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(hex(&Sha256::digest(
        std::fs::read(path).with_context(|| format!("hashing {}", path.display()))?,
    )))
}

fn open_identity(path: &Path) -> Result<ProviderHealthSigner> {
    let binding = machine_binding()?;
    open_identity_with_binding(path, &binding)
}

fn open_identity_with_binding(path: &Path, binding: &str) -> Result<ProviderHealthSigner> {
    let entries = SingleFileMessagePackBackingStore::new(path).pull_all()?;
    let [envelope] = entries.as_slice() else {
        bail!("provider health identity store must contain exactly one record");
    };
    if envelope.key != IDENTITY_KEY
        || envelope.r#type != IDENTITY_TYPE
        || envelope.schema_id.as_deref() != Some(IDENTITY_SCHEMA)
    {
        bail!("provider health identity store has the wrong type");
    }
    let entry: ProviderHealthIdentity = rmp_serde::from_slice(&envelope.payload)?;
    validate_identity(&entry)?;
    if entry.protector_binding != binding {
        bail!("provider health identity belongs to another machine");
    }
    let seed: [u8; 32] = mask_seed(&entry.protected_private_seed, binding)
        .try_into()
        .map_err(|_| anyhow!("provider health identity seed has invalid length"))?;
    let key = SigningKey::from_bytes(&seed);
    if key.verifying_key().to_bytes().as_slice() != entry.public_key.as_slice() {
        bail!("provider health identity seed does not match its public key");
    }
    Ok(ProviderHealthSigner { entry, key })
}

fn validate_identity(entry: &ProviderHealthIdentity) -> Result<()> {
    if entry.schema_version != IDENTITY_SCHEMA
        || entry.public_key.len() != 32
        || entry.protected_private_seed.len() != 32
        || entry.enrollment_nonce.len() != 32
        || entry.protector_kind != "linux_file_mode_machine_id_binding"
        || entry.protector_version != "v1"
        || entry.assurance != "os_installation_file_bound_cloneable_baseline"
        || entry.identity_id != identity_id(&entry.public_key)
    {
        bail!("provider health identity is invalid");
    }
    chrono::DateTime::parse_from_rfc3339(&entry.created_at)?;
    Ok(())
}

fn machine_binding() -> Result<String> {
    let raw = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))?;
    let id = raw.trim();
    if id.is_empty() {
        bail!("Linux machine-id is empty");
    }
    Ok(format!(
        "{PROTECTOR_CONTEXT}:machine-id-sha256:{}",
        hex(&Sha256::digest(id.as_bytes()))
    ))
}

fn mask_seed(seed: &[u8], binding: &str) -> Vec<u8> {
    let mask = Sha256::digest(
        [
            b"gamecult-linux-service-seed-v1\0".as_slice(),
            PROTECTOR_CONTEXT.as_bytes(),
            binding.as_bytes(),
        ]
        .concat(),
    );
    seed.iter()
        .zip(mask)
        .map(|(left, right)| left ^ right)
        .collect()
}

fn identity_id(public_key: &[u8]) -> String {
    hex(&Sha256::digest([ID_DOMAIN, public_key].concat()))
}

fn unsigned_record(record: &SignedDaemonHealth) -> Result<Vec<u8>> {
    let mut unsigned = record.clone();
    unsigned.signature.clear();
    uuid::Uuid::parse_str(&unsigned.publisher_incarnation_id)?;
    Ok(rmp_serde::to_vec(&unsigned)?)
}

fn signing_message(payload: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + SIGNATURE_PURPOSE.len() + payload.len() + 16);
    out.extend_from_slice(SIGNATURE_DOMAIN);
    out.extend_from_slice(&(SIGNATURE_PURPOSE.len() as u64).to_be_bytes());
    out.extend_from_slice(SIGNATURE_PURPOSE);
    out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn publish(endpoint: SocketAddr, runtime_id: &str, record: &SignedDaemonHealth) -> Result<String> {
    let (payload, signed_health_sha256) = canonical_signed_health_payload(record)?;
    let message = CultNetMessage::DocumentPutRaw {
        message_id: format!(
            "codex-connector-health:{}:{}:{}",
            record.daemon_id, record.publisher_incarnation_id, record.publisher_sequence
        ),
        document: CultNetRawDocumentRecord {
            schema_id: HEALTH_SCHEMA.into(),
            record_key: record.daemon_id.clone(),
            stored_at: chrono::DateTime::from_timestamp_millis(
                record.observed_at_unix_millis.try_into()?,
            )
            .context("health observation time is invalid")?
            .to_rfc3339(),
            payload_encoding: CultNetRawPayloadEncoding::Messagepack,
            payload,
            source_runtime_id: Some(runtime_id.into()),
            source_agent_id: Some(record.signer_identity_id.clone()),
            source_role: Some("daemon-health-publisher".into()),
            tags: Some(vec![RUDP_PROTOCOL_ID.into()]),
        },
    };
    let socket = UdpSocket::bind(if endpoint.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut transport = CultNetRudpSocketTransportConnection::new(
        CultNetRudpSocketTransportOptions::client(runtime_id, socket, endpoint, RUDP_CONNECTION_ID),
    )?;
    transport.connect(Vec::new())?;
    let deadline = Instant::now() + Duration::from_millis(500);
    while !transport.connected() {
        let _ = transport.receive_once()?;
        transport.poll_resends()?;
        if Instant::now() >= deadline {
            bail!("timed out connecting provider health to {endpoint}");
        }
    }
    transport.send(
        "schema",
        encode_cultnet_message_to_vec(&message, CultNetWireContract::CultNetSchemaV0)?,
    )?;
    Ok(signed_health_sha256)
}

fn canonical_signed_health_payload(record: &SignedDaemonHealth) -> Result<(Vec<u8>, String)> {
    let payload = rmp_serde::to_vec(record)?;
    if rmp_serde::from_slice::<SignedDaemonHealth>(&payload)? != *record {
        bail!("signed health MessagePack did not round trip");
    }
    let signed_health_sha256 = format!("sha256-{}", hex(&Sha256::digest(&payload)));
    Ok((payload, signed_health_sha256))
}

fn require_id(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > 256
        || value.chars().any(char::is_control)
    {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const DEPLOYMENT_ID: &str = "deploy-codex-connector-42";

    struct ReleaseFixture {
        root: PathBuf,
        connector: PathBuf,
        codex: PathBuf,
        witness: PathBuf,
        codex_sha256: [u8; 32],
        witness_bytes: Vec<u8>,
        release_id: String,
        source_toolchain: ToolchainManifest,
    }

    impl ReleaseFixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "codex-connector-release-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            let connector_bytes = b"exact connector fixture";
            let codex_bytes = b"exact codex fixture";
            let connector_sha256 = hex(&Sha256::digest(connector_bytes));
            let codex_sha256: [u8; 32] = Sha256::digest(codex_bytes).into();
            let codex_sha256_hex = hex(&codex_sha256);
            let release_id = format!("{SOURCE_COMMIT}-{}", &codex_sha256_hex[..12]);
            let release = root.join(&release_id);
            std::fs::create_dir_all(&release).unwrap();
            let connector = release.join("codex-connector");
            let codex = release.join("codex");
            let witness = release.join("DEPLOYMENT");
            std::fs::write(&connector, connector_bytes).unwrap();
            std::fs::write(&codex, codex_bytes).unwrap();
            let package_url =
                "https://registry.npmjs.org/@openai/codex/-/codex-0.150.0-alpha.7-linux-x64.tgz";
            let package_sha256 = "a".repeat(64);
            let witness_bytes = format!(
                "schema_version={DEPLOYMENT_SCHEMA}\nrelease_id={release_id}\nsource_commit={SOURCE_COMMIT}\nbinary_sha256={connector_sha256}\ncodex_package_url={package_url}\ncodex_package_sha256={package_sha256}\ncodex_binary_sha256={codex_sha256_hex}\n",
            )
            .into_bytes();
            std::fs::write(&witness, &witness_bytes).unwrap();
            Self {
                root,
                connector,
                codex,
                witness,
                codex_sha256,
                witness_bytes,
                release_id,
                source_toolchain: ToolchainManifest {
                    package_url: package_url.into(),
                    package_sha256,
                    binary_sha256: codex_sha256_hex,
                },
            }
        }

        fn binding(&self) -> Result<ConnectorReleaseBinding> {
            release_binding_from_artifacts(
                &self.connector,
                &self.codex,
                &self.codex_sha256,
                SOURCE_COMMIT,
                DEPLOYMENT_ID,
                &self.source_toolchain,
            )
        }
    }

    impl Drop for ReleaseFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn exact_release_binding_covers_artifact_witness_and_both_binaries() {
        let fixture = ReleaseFixture::new();
        let binding = fixture.binding().unwrap();
        assert_eq!(binding.release_id, fixture.release_id);
        assert_eq!(binding.source_commit, SOURCE_COMMIT);
        assert_eq!(binding.deployment_id, DEPLOYMENT_ID);
        assert_eq!(
            binding.release_witness_sha256,
            format!("sha256-{}", hex(&Sha256::digest(&fixture.witness_bytes)))
        );
    }

    #[test]
    fn activation_binding_covers_exact_loaded_config_and_caller_key_material() {
        let root = std::env::temp_dir().join(format!(
            "codex-connector-activation-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let config_path = root.join("connector.cc");
        let witness_path = root.join("ACTIVATION");
        let first_key = root.join("ghostlight.key");
        let second_key = root.join("epiphany.key");
        let config_bytes = b"exact CultCache config bytes";
        let first_bytes = b"ghostlight secret\n";
        let second_bytes = b"epiphany secret\n";
        std::fs::write(&config_path, config_bytes).unwrap();
        std::fs::write(&first_key, first_bytes).unwrap();
        std::fs::write(&second_key, second_bytes).unwrap();
        let callers = vec![
            crate::daemon::LoadedCallerKeyBinding {
                caller_runtime_id: "ghostlight-dungeon-yggdrasil".into(),
                connection_key_file: first_key.clone(),
                connection_key_epoch: 3,
                raw_file_sha256: Sha256::digest(first_bytes).into(),
            },
            crate::daemon::LoadedCallerKeyBinding {
                caller_runtime_id: "epiphany-model-runtime".into(),
                connection_key_file: second_key.clone(),
                connection_key_epoch: 7,
                raw_file_sha256: Sha256::digest(second_bytes).into(),
            },
        ];
        let config = crate::daemon::CodexDaemonConfig {
            epoch: 2,
            bind: "127.0.0.1:4103".into(),
            codex_executable: root.join("codex"),
            codex_executable_sha256: [9; 32],
            codex_home: root.join("codex-home"),
            max_frame_bytes: 1_048_576,
            max_connections: 12,
            socket_timeout_ms: 10_000,
            max_expiry_skew_ms: 300_000,
            callers: vec![
                crate::daemon::CodexCallerConfig {
                    caller_runtime_id: "ghostlight-dungeon-yggdrasil".into(),
                    connection_key_file: first_key.clone(),
                    connection_key_epoch: 3,
                    allowed_models: vec!["gpt-5.6-luna".into(), "gpt-5.6-terra".into()],
                    max_concurrent_requests: 4,
                    max_payload_bytes: 524_288,
                    max_output_tokens: 16_384,
                },
                crate::daemon::CodexCallerConfig {
                    caller_runtime_id: "epiphany-model-runtime".into(),
                    connection_key_file: second_key.clone(),
                    connection_key_epoch: 7,
                    allowed_models: vec!["gpt-5.6-luna".into()],
                    max_concurrent_requests: 8,
                    max_payload_bytes: 262_144,
                    max_output_tokens: 8_192,
                },
            ],
            replay_store: root.join("replay.cc"),
        };
        let witness_bytes = format!(
            "schema_version={ACTIVATION_SCHEMA}\nactivation_id=deploy-codex-connector-42:canonical:00000000-0000-4000-8000-000000000042\nconfig_path={}\nconfig_sha256={}\nconfig_epoch=2\nbind=127.0.0.1:4103\ncodex_executable_path={}\ncodex_executable_sha256={}\ncodex_home_path={}\nreplay_store_path={}\nmax_frame_bytes=1048576\nmax_connections=12\nsocket_timeout_ms=10000\nmax_expiry_skew_ms=300000\ncaller_count=2\ncaller.0.runtime_id=ghostlight-dungeon-yggdrasil\ncaller.0.connection_key_path={}\ncaller.0.connection_key_sha256={}\ncaller.0.connection_key_epoch=3\ncaller.0.allowed_model_count=2\ncaller.0.allowed_model.0=gpt-5.6-luna\ncaller.0.allowed_model.1=gpt-5.6-terra\ncaller.0.max_concurrent_requests=4\ncaller.0.max_payload_bytes=524288\ncaller.0.max_output_tokens=16384\ncaller.1.runtime_id=epiphany-model-runtime\ncaller.1.connection_key_path={}\ncaller.1.connection_key_sha256={}\ncaller.1.connection_key_epoch=7\ncaller.1.allowed_model_count=1\ncaller.1.allowed_model.0=gpt-5.6-luna\ncaller.1.max_concurrent_requests=8\ncaller.1.max_payload_bytes=262144\ncaller.1.max_output_tokens=8192\n",
            config_path.display(),
            hex(&Sha256::digest(config_bytes)),
            config.codex_executable.display(),
            hex(&config.codex_executable_sha256),
            config.codex_home.display(),
            config.replay_store.display(),
            first_key.display(),
            hex(&Sha256::digest(first_bytes)),
            second_key.display(),
            hex(&Sha256::digest(second_bytes)),
        )
        .into_bytes();
        std::fs::write(&witness_path, &witness_bytes).unwrap();
        let binding = activation_binding_from_material(
            &config_path,
            config_bytes,
            &config,
            &callers,
            &witness_path,
        )
        .unwrap();
        assert_eq!(
            binding.activation_witness_sha256,
            format!("sha256-{}", hex(&Sha256::digest(&witness_bytes)))
        );
        let next_launch = String::from_utf8(witness_bytes.clone())
            .unwrap()
            .replace("000000000042", "000000000043")
            .into_bytes();
        std::fs::write(&witness_path, &next_launch).unwrap();
        let next_binding = activation_binding_from_material(
            &config_path,
            config_bytes,
            &config,
            &callers,
            &witness_path,
        )
        .unwrap();
        assert_ne!(
            next_binding.activation_witness_sha256, binding.activation_witness_sha256,
            "a new root-issued launch admission must invalidate stale health"
        );
        std::fs::write(&witness_path, &witness_bytes).unwrap();

        for substituted in [
            witness_bytes
                .iter()
                .copied()
                .chain(b"extra=true\n".iter().copied())
                .collect::<Vec<_>>(),
            String::from_utf8(witness_bytes.clone())
                .unwrap()
                .replace(&hex(&Sha256::digest(first_bytes)), &"f".repeat(64))
                .into_bytes(),
        ] {
            std::fs::write(&witness_path, substituted).unwrap();
            assert!(
                activation_binding_from_material(
                    &config_path,
                    config_bytes,
                    &config,
                    &callers,
                    &witness_path,
                )
                .is_err()
            );
        }
        std::fs::write(&witness_path, &witness_bytes).unwrap();
        assert!(
            activation_binding_from_material(
                &config_path,
                b"substituted config bytes",
                &config,
                &callers,
                &witness_path,
            )
            .is_err()
        );
        let mut substituted_callers = callers.clone();
        substituted_callers[1].connection_key_epoch = 8;
        assert!(
            activation_binding_from_material(
                &config_path,
                config_bytes,
                &config,
                &substituted_callers,
                &witness_path,
            )
            .is_err()
        );
        let mut substituted_config = config.clone();
        substituted_config.max_connections += 1;
        assert!(
            activation_binding_from_material(
                &config_path,
                config_bytes,
                &substituted_config,
                &callers,
                &witness_path,
            )
            .is_err()
        );
        let mut substituted_caller_policy = config;
        substituted_caller_policy.callers[0]
            .allowed_models
            .reverse();
        assert!(
            activation_binding_from_material(
                &config_path,
                config_bytes,
                &substituted_caller_policy,
                &callers,
                &witness_path,
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn typed_traffic_admission_binds_the_exact_startup_statement() {
        assert_eq!(
            fixed_traffic_admission_path(TRAFFIC_ADMISSION_PATH).unwrap(),
            PathBuf::from(TRAFFIC_ADMISSION_PATH)
        );
        assert!(fixed_traffic_admission_path("/tmp/traffic-admission.cc").is_err());
        let release = ConnectorReleaseBinding {
            release_id: format!("{SOURCE_COMMIT}-aaaaaaaaaaaa"),
            release_witness_sha256: format!("sha256-{}", "b".repeat(64)),
            source_commit: SOURCE_COMMIT.into(),
            deployment_id: DEPLOYMENT_ID.into(),
        };
        let activation = ConnectorActivationBinding {
            activation_witness_sha256: format!("sha256-{}", "c".repeat(64)),
        };
        let published = PublishedHealthStatementIdentity {
            daemon_id: TRAFFIC_ADMISSION_KEY.into(),
            signed_health_sha256: format!("sha256-{}", "d".repeat(64)),
            publisher_incarnation_id: "00000000-0000-4000-8000-000000000042".into(),
            publisher_sequence: 1,
            signer_identity_id: "e".repeat(64),
        };
        let expected = traffic_admission_expectation(&release, &activation, &published).unwrap();
        let payload = rmp_serde::to_vec(&expected).unwrap();
        assert_eq!(payload.first().copied(), Some(0x9d));
        assert_eq!(expected.runtime_process_id, std::process::id());
        assert!(expected.runtime_process_starttime_ticks > 0);
        assert_eq!(
            decode_traffic_admission_payload(&payload).unwrap(),
            expected
        );

        let named = rmp_serde::to_vec_named(&expected).unwrap();
        assert!(decode_traffic_admission_payload(&named).is_err());
        for mut substituted in [
            {
                let mut value = expected.clone();
                value.signed_health_sha256 = format!("sha256-{}", "f".repeat(64));
                value
            },
            {
                let mut value = expected.clone();
                value.publisher_incarnation_id = "00000000-0000-4000-8000-000000000043".into();
                value
            },
            {
                let mut value = expected.clone();
                value.publisher_sequence = 2;
                value
            },
            {
                let mut value = expected.clone();
                value.activation_witness_sha256 = format!("sha256-{}", "f".repeat(64));
                value
            },
            {
                let mut value = expected.clone();
                value.runtime_process_id = value.runtime_process_id.checked_add(1).unwrap();
                value
            },
            {
                let mut value = expected.clone();
                value.runtime_process_starttime_ticks = value
                    .runtime_process_starttime_ticks
                    .checked_add(1)
                    .unwrap();
                value
            },
        ] {
            validate_traffic_admission_projection(&substituted).unwrap();
            assert!(require_exact_traffic_admission(&substituted, &expected).is_err());
            substituted.schema_version = "idunn.runtime_traffic_admission.v1".into();
            assert!(validate_traffic_admission_projection(&substituted).is_err());
        }
    }

    #[test]
    fn proc_stat_starttime_parser_binds_pid_and_kernel_tick_identity() {
        let stat =
            "4242 (connector ) worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 98765 20\n";
        assert_eq!(parse_proc_stat_starttime(stat, 4242).unwrap(), 98_765);
        assert!(parse_proc_stat_starttime(stat, 4243).is_err());
        assert!(
            parse_proc_stat_starttime(
                "4242 (connector) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 0",
                4242,
            )
            .is_err()
        );
    }

    #[test]
    fn embedded_toolchain_manifest_is_the_exact_source_contract() {
        let manifest = parse_toolchain_manifest(SOURCE_TOOLCHAIN_MANIFEST).unwrap();
        assert_eq!(
            manifest.package_url,
            "https://registry.npmjs.org/@openai/codex/-/codex-0.150.0-alpha.7-linux-x64.tgz"
        );
        assert_eq!(
            manifest.package_sha256,
            "8aca3112aef60127d4ffaf4c6f08e524fa7315279a1d08e7aa9c5e7f1a6943e0"
        );
        assert_eq!(
            manifest.binary_sha256,
            "aca268dc02dcef8b1ea9f528a10173d5071ae76d659a03cce6458bbebe228bee"
        );
    }

    #[test]
    fn malformed_or_mismatched_release_witness_never_authenticates() {
        let fixture = ReleaseFixture::new();
        let malformed = [fixture.witness_bytes.as_slice(), b"deployment_id=stale\n"].concat();
        std::fs::write(&fixture.witness, malformed).unwrap();
        assert!(fixture.binding().is_err());

        std::fs::write(&fixture.witness, &fixture.witness_bytes).unwrap();
        let witness_text = std::str::from_utf8(&fixture.witness_bytes).unwrap();
        for substituted in [
            witness_text.replace(
                fixture.source_toolchain.package_url.as_str(),
                "https://registry.npmjs.org/@openai/codex/-/codex-0.149.0-linux-x64.tgz",
            ),
            witness_text.replace(
                fixture.source_toolchain.package_sha256.as_str(),
                &"b".repeat(64),
            ),
        ] {
            std::fs::write(&fixture.witness, substituted).unwrap();
            assert!(
                fixture
                    .binding()
                    .unwrap_err()
                    .to_string()
                    .contains("source-owned Codex toolchain")
            );
        }
        std::fs::write(&fixture.witness, &fixture.witness_bytes).unwrap();
        assert!(
            release_binding_from_artifacts(
                &fixture.connector,
                &fixture.codex,
                &fixture.codex_sha256,
                "ffffffffffffffffffffffffffffffffffffffff",
                DEPLOYMENT_ID,
                &fixture.source_toolchain,
            )
            .is_err()
        );

        std::fs::write(&fixture.connector, b"substituted connector").unwrap();
        assert!(fixture.binding().is_err());
        std::fs::write(&fixture.connector, b"exact connector fixture").unwrap();

        std::fs::write(&fixture.codex, b"substituted codex").unwrap();
        assert!(fixture.binding().is_err());
        std::fs::write(&fixture.codex, b"exact codex fixture").unwrap();

        assert!(
            release_binding_from_artifacts(
                &fixture.connector,
                &fixture.codex,
                &[7; 32],
                SOURCE_COMMIT,
                DEPLOYMENT_ID,
                &fixture.source_toolchain,
            )
            .is_err()
        );
        assert!(
            release_binding_from_artifacts(
                &fixture.connector,
                &fixture.codex,
                &fixture.codex_sha256,
                SOURCE_COMMIT,
                "not a current/request",
                &fixture.source_toolchain,
            )
            .is_err()
        );
    }

    #[test]
    fn signed_health_requires_the_complete_release_binding() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public_key = key.verifying_key().to_bytes();
        let signer = ProviderHealthSigner {
            entry: ProviderHealthIdentity {
                schema_version: IDENTITY_SCHEMA.into(),
                identity_id: identity_id(&public_key),
                public_key: public_key.to_vec(),
                protected_private_seed: vec![0; 32],
                protector_kind: "linux_file_mode_machine_id_binding".into(),
                protector_binding: "fixture".into(),
                protector_version: "v1".into(),
                assurance: "os_installation_file_bound_cloneable_baseline".into(),
                created_at: "2026-09-02T12:00:00Z".into(),
                enrollment_nonce: vec![1; 32],
            },
            key,
        };
        let mut record = SignedDaemonHealth {
            schema_version: HEALTH_SCHEMA.into(),
            daemon_id: "yggdrasil-codex-connector".into(),
            health_contract: CODEX_CONNECTOR_IDUNN_HEALTH_CONTRACT.into(),
            source_runtime_id: "codex-connector-yggdrasil".into(),
            state: "active".into(),
            detail: "credential-isolated-transport-ready".into(),
            signer_identity_id: signer.entry.identity_id.clone(),
            publisher_incarnation_id: uuid::Uuid::new_v4().to_string(),
            publisher_sequence: 1,
            observed_at_unix_millis: 1_787_315_696_789,
            release_id: Some(format!("{SOURCE_COMMIT}-aaaaaaaaaaaa")),
            release_witness_sha256: Some(format!("sha256-{}", "b".repeat(64))),
            source_commit: Some(SOURCE_COMMIT.into()),
            deployment_id: Some(DEPLOYMENT_ID.into()),
            signature_algorithm: "ed25519".into(),
            signature: Vec::new(),
            private_state_exposed: false,
            activation_witness_sha256: Some(format!("sha256-{}", "c".repeat(64))),
        };
        let unsigned = unsigned_record(&record).unwrap();
        record.signature = signer
            .key
            .sign(&signing_message(&unsigned))
            .to_bytes()
            .to_vec();
        record.validate().unwrap();
        let (encoded, digest) = canonical_signed_health_payload(&record).unwrap();
        assert_eq!(&encoded[..3], &[0xdc, 0, 18]);
        assert_eq!(digest, format!("sha256-{}", hex(&Sha256::digest(&encoded))));
        let public: [u8; 32] = signer.entry.public_key.try_into().unwrap();
        let signature = Signature::from_slice(&record.signature).unwrap();
        VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify(&signing_message(&unsigned), &signature)
            .unwrap();
        assert!(!record.private_state_exposed);

        for missing in 0..5 {
            let mut incomplete = record.clone();
            match missing {
                0 => incomplete.release_id = None,
                1 => incomplete.release_witness_sha256 = None,
                2 => incomplete.source_commit = None,
                3 => incomplete.deployment_id = None,
                _ => incomplete.activation_witness_sha256 = None,
            }
            assert!(incomplete.validate().is_err());
        }
    }
}
