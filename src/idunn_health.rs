use std::fs::{File, OpenOptions};
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail, ensure};
use cultcache_rs::{DatabaseEntry, SingleFileMessagePackBackingStore};
use cultnet_rs::{
    CultNetMessage, CultNetRawDocumentRecord, CultNetRawPayloadEncoding,
    CultNetRudpReliableSendStatus, CultNetRudpSocketTransportConnection,
    CultNetRudpSocketTransportOptions, CultNetWireContract,
    GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA, GameCultProviderHealthIdentity,
    GameCultRuntimeCapability, GameCultRuntimePresenceHealthPurpose,
    GameCultRuntimePresenceHealthRecord, IDUNN_EXPECTED_INCARNATION_SCHEMA,
    IDUNN_PROCESS_WRITE_LEASE_SCHEMA, IDUNN_RUNTIME_ACTIVATION_CREDENTIAL_NAME,
    IDUNN_RUNTIME_ACTIVATION_SCHEMA, IdunnExpectedIncarnationRecord, IdunnProcessWriteLeaseRecord,
    IdunnRuntimeActivationRecord, IdunnRuntimeActivationSigner, ServiceIdentitySigner,
    encode_cultnet_message_to_vec, open_service_identity_credential_reader,
};

pub(crate) const IDUNN_RUNTIME_BUNDLE_ENVIRONMENT: &str = "GAMECULT_IDUNN_RUNTIME_BUNDLE";
pub(crate) const IDUNN_CANDIDATE_BIND_ENVIRONMENT: &str = "GAMECULT_IDUNN_CANDIDATE_BIND";
const IDUNN_PROCESS_WRITE_LEASE_ENVIRONMENT: &str = "GAMECULT_IDUNN_PROCESS_WRITE_LEASE";
const CULTNET_RUDP_ENVIRONMENT: &str = "CODEX_CONNECTOR_CULTNET_RUDP";
const SYSTEMD_LISTEN_PID_ENVIRONMENT: &str = "LISTEN_PID";
const SYSTEMD_LISTEN_FDS_ENVIRONMENT: &str = "LISTEN_FDS";
const SYSTEMD_LISTEN_FDNAMES_ENVIRONMENT: &str = "LISTEN_FDNAMES";
const SYSTEMD_LISTEN_FDS_START: RawFd = 3;
const ACTIVATION_SIGNER_FD_NAME: &str = IDUNN_RUNTIME_ACTIVATION_CREDENTIAL_NAME;
const PROVIDER_SIGNER_FD_NAME: &str = "gamecult-runtime-presence-identity";

const CONNECTOR_TARGET: &str = "codex-connector";
const CONNECTOR_CAPABILITY: &str = "gamecult.codex.subscription-inference";
const CONNECTOR_COMPATIBILITY: &str = "v2";
pub(crate) const CONNECTOR_HEALTH_CONTRACT: &str = "codex-connector.runtime-health.v1";
pub(crate) const CONNECTOR_STATE_SCHEMA_GENERATION: &str = "connector-v1";
// Odin's canonical rmp-serde digest of deployment/idunn/recipe.toml [state].
pub(crate) const CONNECTOR_STATE_CONTRACT_SHA256: &str =
    "sha256-61da5fa6ee0ed2971137a724d6d880e3def273c43e160c5001ea56f57bf11a44";
const ODIN_RENDEZVOUS_CAPABILITY: &str = "odin.verse-rendezvous";
const ODIN_RENDEZVOUS_SCHEMA: &str = "odin.verse-topology.v1";
const ODIN_RENDEZVOUS_COMPATIBILITY: &str = "v1";
const RUDP_PROTOCOL_ID: &str = "cultnet.transport.rudp.v0";
const ODIN_CULTMESH_DOCUMENT_CATALOG_CONNECTION_ID: u32 = 0x0d1d_0002;

pub(crate) fn require_managed_config_store(path: &Path) -> Result<()> {
    require_root_read_only_file(path, "Connector managed configuration")?;
    require_root_read_only_file(
        &sibling_lock_path(path)?,
        "Connector managed configuration lock",
    )?;
    require_root_controlled_directory_chain(
        path.parent()
            .context("managed configuration has no parent")?,
        "Connector managed configuration parent",
    )
}

struct RuntimeAuthorityMaterial {
    expected: IdunnExpectedIncarnationRecord,
    expected_sha256: String,
    activation: IdunnRuntimeActivationRecord,
    activation_sha256: String,
    activation_signer: IdunnRuntimeActivationSigner,
    provider_signer: ServiceIdentitySigner<GameCultProviderHealthIdentity>,
}

struct RuntimeSignerDescriptors {
    activation: File,
    provider: File,
}

pub(crate) struct RuntimePresencePublisher {
    endpoint: SocketAddr,
    authority: RuntimeAuthorityMaterial,
    bound_endpoint: String,
    capabilities: Vec<GameCultRuntimeCapability>,
    write_lease_path: PathBuf,
    write_lease: Option<ProcessWriteLeaseGuard>,
    sequence: u64,
}

#[derive(Clone)]
pub(crate) struct ProcessWriteLeaseGuard {
    held: Arc<HeldProcessWriteLease>,
}

struct HeldProcessWriteLease {
    // Idunn uses this pre-created sibling lock for write-lease replacement.
    // Keeping it shared for the whole process fences both Connector's replay
    // commits and the official app-server's credential refresh writes.
    _lock: File,
    path: PathBuf,
    expected: IdunnExpectedIncarnationRecord,
    expected_sha256: String,
    activation: IdunnRuntimeActivationRecord,
    activation_sha256: String,
    warming_presence_sha256: String,
    lease_sha256: String,
}

impl ProcessWriteLeaseGuard {
    fn sha256(&self) -> &str {
        &self.held.lease_sha256
    }

    fn require_current(&self) -> Result<()> {
        let observed = load_process_write_lease(
            &self.held.path,
            &self.held.expected,
            &self.held.expected_sha256,
            &self.held.activation,
            &self.held.activation_sha256,
            &self.held.warming_presence_sha256,
        )?;
        ensure!(
            observed.as_deref() == Some(self.sha256()),
            "process-write lease is no longer the admitted lifetime grant"
        );
        Ok(())
    }
}

impl RuntimePresencePublisher {
    pub(crate) fn open_from_environment(bound: SocketAddr, capacity: u32) -> Result<Self> {
        ensure!(
            bound.ip().is_loopback() && bound.port() != 0,
            "Connector candidate bind is not a fixed loopback endpoint"
        );
        ensure!(capacity > 0, "Connector capability capacity is zero");
        let bundle = PathBuf::from(required_environment(IDUNN_RUNTIME_BUNDLE_ENVIRONMENT)?);
        let authority = load_runtime_authority(&bundle)?;
        let candidate: SocketAddr = required_environment(IDUNN_CANDIDATE_BIND_ENVIRONMENT)?
            .parse()
            .context("parsing Idunn candidate bind")?;
        ensure!(
            candidate == bound,
            "bound endpoint differs from Idunn candidate bind"
        );
        let bound_endpoint = format!("tcp://{bound}");
        let route = authority
            .expected
            .route
            .as_ref()
            .context("Connector Expected projection has no admitted route")?;
        ensure!(
            route.transport == "tcp" && route.candidate_endpoint == bound_endpoint,
            "Connector bound endpoint differs from Expected"
        );

        let endpoint: SocketAddr = required_environment(CULTNET_RUDP_ENVIRONMENT)?
            .parse()
            .context("parsing Connector CultNet RUDP endpoint")?;
        require_odin_rendezvous(&authority.expected, endpoint)?;

        let capability = GameCultRuntimeCapability {
            capability: CONNECTOR_CAPABILITY.into(),
            schema: crate::ENVELOPE_SCHEMA_ID.into(),
            compatibility: CONNECTOR_COMPATIBILITY.into(),
            capacity,
        };
        require_connector_expected_contract(&authority.expected, &capability)?;
        let write_lease_path =
            PathBuf::from(required_environment(IDUNN_PROCESS_WRITE_LEASE_ENVIRONMENT)?);

        Ok(Self {
            endpoint,
            authority,
            bound_endpoint,
            capabilities: vec![capability],
            write_lease_path,
            write_lease: None,
            sequence: 0,
        })
    }

    pub(crate) fn acquire_process_write_lease(
        &mut self,
        warming_presence_sha256: &str,
        timeout: Duration,
    ) -> Result<()> {
        let path = &self.write_lease_path;
        let started = Instant::now();
        loop {
            let last_error = match acquire_process_write_lease_guard(
                path,
                &self.authority.expected,
                &self.authority.expected_sha256,
                &self.authority.activation,
                &self.authority.activation_sha256,
                warming_presence_sha256,
            ) {
                Ok(Some(guard)) => {
                    self.write_lease = Some(guard);
                    return Ok(());
                }
                Ok(None) => None,
                Err(error) => Some(format!("{error:#}")),
            };
            if started.elapsed() >= timeout {
                let detail = last_error
                    .as_deref()
                    .unwrap_or("the process-write-lease record remained absent");
                bail!(
                    "timed out waiting for Idunn process-write lease {}: {detail}",
                    path.display()
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub(crate) fn process_write_lease_guard(&self) -> Result<ProcessWriteLeaseGuard> {
        self.write_lease
            .clone()
            .context("Connector has not acquired its process-write lease")
    }

    pub(crate) fn publish(&mut self, state: &str, detail: &str) -> Result<String> {
        if let Some(guard) = &self.write_lease {
            guard.require_current()?;
        }
        let record = self.signed_record(state, detail, unix_millis()?)?;
        let payload = rmp_serde::to_vec(&record)?;
        ensure!(
            rmp_serde::from_slice::<GameCultRuntimePresenceHealthRecord>(&payload)? == record,
            "runtime presence did not round-trip canonically"
        );
        let sha256 = record.canonical_sha256()?;
        publish_presence(
            self.endpoint,
            &self.authority.expected.target,
            &self.authority.expected.runtime_id,
            &record,
            payload,
        )?;
        Ok(sha256)
    }

    fn signed_record(
        &mut self,
        state: &str,
        detail: &str,
        observed_at_unix_millis: u64,
    ) -> Result<GameCultRuntimePresenceHealthRecord> {
        if state == "warming" {
            ensure!(
                self.write_lease.is_none(),
                "warming presence cannot carry a process-write lease"
            );
        } else if state == "active" && self.authority.expected.write_lease_required {
            ensure!(
                self.write_lease.is_some(),
                "active stateful presence lacks its process-write lease"
            );
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("runtime presence publisher sequence overflow"))?;
        let expected = &self.authority.expected;
        let activation = &self.authority.activation;
        let mut record = GameCultRuntimePresenceHealthRecord {
            schema_version: GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA.into(),
            target: expected.target.clone(),
            expected_projection_sha256: self.authority.expected_sha256.clone(),
            plan_id: expected.plan_id.clone(),
            incarnation_id: expected.incarnation_id.clone(),
            sealed_release_id: expected.sealed_release_id.clone(),
            activation_witness_sha256: self.authority.activation_sha256.clone(),
            state_schema_generation: expected.state_schema_generation.clone(),
            state_contract_sha256: expected.state_contract_sha256.clone(),
            runtime_id: expected.runtime_id.clone(),
            runtime_instance_id: activation.runtime_instance_id.clone(),
            bound_endpoint: Some(self.bound_endpoint.clone()),
            capabilities: self.capabilities.clone(),
            health_contract: expected.health_contract.clone(),
            state: state.into(),
            detail: detail.into(),
            write_lease_sha256: self
                .write_lease
                .as_ref()
                .map(|guard| guard.sha256().to_string()),
            signer_identity_id: self.authority.provider_signer.entry().identity_id.clone(),
            publisher_sequence: self.sequence,
            observed_at_unix_millis,
            signature_algorithm: "ed25519".into(),
            signature: Vec::new(),
            activation_signer_identity_id: activation.activation_signer_identity_id.clone(),
            activation_signature: Vec::new(),
        };
        let proof_payload = record.canonical_proof_payload()?;
        let provider_proof = self
            .authority
            .provider_signer
            .sign::<GameCultRuntimePresenceHealthPurpose>(&proof_payload);
        ensure!(
            provider_proof.identity_id == record.signer_identity_id,
            "provider signer identity changed after runtime admission"
        );
        record.signature = provider_proof.signature;
        record.activation_signature = self
            .authority
            .activation_signer
            .sign_presence_proof(&record)?;
        record.validate()?;
        Ok(record)
    }
}

fn load_runtime_authority(bundle: &Path) -> Result<RuntimeAuthorityMaterial> {
    require_runtime_bundle(bundle)?;
    let (expected_key, expected_payload) = read_immutable_runtime_record(
        &bundle.join("expected.cc"),
        IdunnExpectedIncarnationRecord::TYPE,
        IDUNN_EXPECTED_INCARNATION_SCHEMA,
    )?;
    let expected = IdunnExpectedIncarnationRecord::decode_canonical(&expected_payload)?;
    ensure!(
        expected_key == expected.target,
        "Expected record key is not its target"
    );
    let (activation_key, activation_payload) = read_immutable_runtime_record(
        &bundle.join("activation.cc"),
        IdunnRuntimeActivationRecord::TYPE,
        IDUNN_RUNTIME_ACTIVATION_SCHEMA,
    )?;
    let activation = IdunnRuntimeActivationRecord::decode_canonical(&activation_payload)?;
    ensure!(
        activation_key == expected.target,
        "activation record key is not the Expected target"
    );
    let expected_sha256 = expected.canonical_sha256()?;
    ensure!(
        activation.expected_projection_sha256 == expected_sha256
            && activation.runtime_id == expected.runtime_id,
        "runtime activation does not bind the bundled Expected projection"
    );

    let RuntimeSignerDescriptors {
        activation: activation_credential,
        provider: provider_identity,
    } = take_runtime_signer_descriptors_from_environment()?;
    let activation_signer =
        IdunnRuntimeActivationSigner::from_credential_reader(activation_credential)?;
    ensure!(
        activation_signer.identity_id() == activation.activation_signer_identity_id
            && activation_signer.public_key() == activation.activation_signer_public_key,
        "runtime activation credential does not belong to the Idunn activation record"
    );

    // The shared signer owns profile validation, platform binding, seed
    // unprotection, and domain-separated signing. Connector never parses or
    // exports stable private key material.
    let provider_signer = open_service_identity_credential_reader::<GameCultProviderHealthIdentity>(
        provider_identity,
    )?;
    ensure!(
        provider_signer.entry().identity_id == expected.expected_signer_identity_id,
        "provider signer is not the identity selected by Expected"
    );

    Ok(RuntimeAuthorityMaterial {
        expected,
        expected_sha256,
        activation_sha256: activation.canonical_sha256()?,
        activation,
        activation_signer,
        provider_signer,
    })
}

fn read_immutable_runtime_record(
    path: &Path,
    expected_type: &str,
    expected_schema: &str,
) -> Result<(String, Vec<u8>)> {
    require_root_read_only_file(path, "runtime authority record")?;
    require_root_read_only_file(&sibling_lock_path(path)?, "runtime authority lock")?;
    SingleFileMessagePackBackingStore::new(path).with_read_only_shared_snapshot(|entries| {
        let [envelope] = entries.as_slice() else {
            bail!("runtime authority store must contain exactly one record");
        };
        ensure!(
            envelope.r#type == expected_type
                && envelope.schema_id.as_deref() == Some(expected_schema),
            "runtime authority store has the wrong typed envelope"
        );
        Ok((envelope.key.clone(), envelope.payload.clone()))
    })
}

fn require_odin_rendezvous(
    expected: &IdunnExpectedIncarnationRecord,
    endpoint: SocketAddr,
) -> Result<()> {
    let dependency = expected
        .dependencies
        .iter()
        .find(|dependency| {
            dependency.capability == ODIN_RENDEZVOUS_CAPABILITY
                && dependency.schema == ODIN_RENDEZVOUS_SCHEMA
                && dependency.compatibility == ODIN_RENDEZVOUS_COMPATIBILITY
        })
        .context("Expected projection has no Odin rendezvous dependency")?;
    ensure!(
        dependency.kind == "bootstrap"
            && dependency.startup == "before-start"
            && dependency.provider_id.is_some()
            && dependency.provider_authority.as_deref() == Some("managed-incarnation")
            && dependency.provider_expected_projection_sha256.is_some(),
        "Odin rendezvous dependency is not a resolved managed bootstrap"
    );
    let provider_endpoint = dependency
        .provider_endpoint
        .as_deref()
        .context("Expected Odin provider has no RUDP endpoint")?;
    let expected_endpoint = parse_expected_rudp_endpoint(provider_endpoint)?;
    ensure!(
        expected_endpoint == endpoint,
        "CultNet RUDP endpoint differs from Expected Odin provider endpoint"
    );
    Ok(())
}

fn parse_expected_rudp_endpoint(value: &str) -> Result<SocketAddr> {
    if let Some(candidate) = value
        .strip_prefix("rudp://")
        .or_else(|| value.strip_prefix("udp://"))
    {
        return candidate
            .parse()
            .context("parsing Expected Odin RUDP endpoint");
    }
    ensure!(
        !value.contains("://"),
        "Expected Odin provider endpoint uses an unsupported transport"
    );
    value
        .parse()
        .context("parsing bare Expected Odin RUDP endpoint")
}

fn require_expected_capability(
    expected: &IdunnExpectedIncarnationRecord,
    actual: &GameCultRuntimeCapability,
) -> Result<()> {
    let required = expected
        .capabilities
        .iter()
        .find(|required| {
            required.capability == actual.capability
                && required.schema == actual.schema
                && required.compatibility == actual.compatibility
        })
        .context("Expected projection does not admit Connector's runtime capability")?;
    ensure!(
        actual.capacity >= required.minimum_capacity,
        "Connector capacity is below Expected"
    );
    Ok(())
}

fn require_connector_expected_contract(
    expected: &IdunnExpectedIncarnationRecord,
    actual: &GameCultRuntimeCapability,
) -> Result<()> {
    require_expected_capability(expected, actual)?;
    ensure!(
        expected.target == CONNECTOR_TARGET,
        "Connector Expected projection names a different target"
    );
    ensure!(
        expected.health_contract == CONNECTOR_HEALTH_CONTRACT,
        "Connector Expected projection names an unimplemented health contract"
    );
    ensure!(
        expected.state_schema_generation.as_deref() == Some(CONNECTOR_STATE_SCHEMA_GENERATION)
            && expected.state_contract_sha256.as_deref() == Some(CONNECTOR_STATE_CONTRACT_SHA256)
            && expected.write_lease_required,
        "Connector Expected projection does not match its compiled state contract"
    );
    Ok(())
}

fn load_process_write_lease(
    path: &Path,
    expected: &IdunnExpectedIncarnationRecord,
    expected_sha256: &str,
    activation: &IdunnRuntimeActivationRecord,
    activation_sha256: &str,
    warming_presence_sha256: &str,
) -> Result<Option<String>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    require_root_controlled_file(path, "process-write-lease record")?;
    require_root_controlled_file(&sibling_lock_path(path)?, "process-write-lease lock")?;
    SingleFileMessagePackBackingStore::new(path).with_read_only_shared_snapshot(|entries| {
        let [envelope] = entries.as_slice() else {
            if entries.is_empty() {
                return Ok(None);
            }
            bail!("process-write-lease store is ambiguous");
        };
        ensure!(
            envelope.r#type == IdunnProcessWriteLeaseRecord::TYPE
                && envelope.schema_id.as_deref() == Some(IDUNN_PROCESS_WRITE_LEASE_SCHEMA),
            "process-write-lease store has the wrong typed envelope"
        );
        let lease = IdunnProcessWriteLeaseRecord::decode_canonical(&envelope.payload)?;
        ensure!(
            envelope.key == lease.target,
            "process-write-lease key is not its target"
        );
        exact_process_write_lease_sha256(
            &lease,
            expected,
            expected_sha256,
            activation,
            activation_sha256,
            warming_presence_sha256,
        )
        .map(Some)
    })
}

fn acquire_process_write_lease_guard(
    path: &Path,
    expected: &IdunnExpectedIncarnationRecord,
    expected_sha256: &str,
    activation: &IdunnRuntimeActivationRecord,
    activation_sha256: &str,
    warming_presence_sha256: &str,
) -> Result<Option<ProcessWriteLeaseGuard>> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    require_root_controlled_file(path, "process-write-lease record")?;
    let lock_path = sibling_lock_path(path)?;
    require_root_controlled_file(&lock_path, "process-write-lease lock")?;
    let lock = OpenOptions::new()
        .read(true)
        .open(&lock_path)
        .with_context(|| format!("opening process-write-lease lock {}", lock_path.display()))?;
    fs2::FileExt::lock_shared(&lock)
        .with_context(|| format!("locking process-write-lease lock {}", lock_path.display()))?;

    // The first shared lock remains held while this exact snapshot is decoded.
    // The backing-store read takes its normal nested shared lock so Connector
    // continues to use CultCache's canonical snapshot decoder.
    let lease_sha256 = load_process_write_lease(
        path,
        expected,
        expected_sha256,
        activation,
        activation_sha256,
        warming_presence_sha256,
    )?;
    let Some(lease_sha256) = lease_sha256 else {
        return Ok(None);
    };
    Ok(Some(ProcessWriteLeaseGuard {
        held: Arc::new(HeldProcessWriteLease {
            _lock: lock,
            path: path.to_path_buf(),
            expected: expected.clone(),
            expected_sha256: expected_sha256.into(),
            activation: activation.clone(),
            activation_sha256: activation_sha256.into(),
            warming_presence_sha256: warming_presence_sha256.into(),
            lease_sha256,
        }),
    }))
}

fn exact_process_write_lease_sha256(
    lease: &IdunnProcessWriteLeaseRecord,
    expected: &IdunnExpectedIncarnationRecord,
    expected_sha256: &str,
    activation: &IdunnRuntimeActivationRecord,
    activation_sha256: &str,
    warming_presence_sha256: &str,
) -> Result<String> {
    lease.validate()?;
    ensure!(
        lease.target == expected.target
            && lease.expected_projection_sha256 == expected_sha256
            && lease.plan_id == expected.plan_id
            && lease.incarnation_id == expected.incarnation_id
            && lease.sealed_release_id == expected.sealed_release_id
            && lease.activation_witness_sha256 == activation_sha256
            && lease.state_schema_generation
                == expected
                    .state_schema_generation
                    .as_deref()
                    .context("Expected has no state schema generation")?
            && lease.state_contract_sha256
                == expected
                    .state_contract_sha256
                    .as_deref()
                    .context("Expected has no state contract")?
            && lease.runtime_id == expected.runtime_id
            && lease.runtime_instance_id == activation.runtime_instance_id
            && lease.warming_presence_sha256 == warming_presence_sha256,
        "process-write lease does not bind this exact warming incarnation"
    );
    lease.canonical_sha256()
}

fn publish_presence(
    endpoint: SocketAddr,
    target: &str,
    runtime_id: &str,
    record: &GameCultRuntimePresenceHealthRecord,
    payload: Vec<u8>,
) -> Result<()> {
    let message = CultNetMessage::DocumentPutRaw {
        message_id: format!(
            "codex-connector-presence:{}:{}:{}",
            target, record.runtime_instance_id, record.publisher_sequence
        ),
        document: CultNetRawDocumentRecord {
            schema_id: GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA.into(),
            record_key: target.into(),
            stored_at: chrono::DateTime::from_timestamp_millis(
                record.observed_at_unix_millis.try_into()?,
            )
            .context("runtime presence observation time is invalid")?
            .to_rfc3339(),
            payload_encoding: CultNetRawPayloadEncoding::Messagepack,
            payload,
            source_runtime_id: Some(runtime_id.into()),
            source_agent_id: Some(record.signer_identity_id.clone()),
            source_role: Some("runtime-presence-health-publisher".into()),
            tags: Some(vec![RUDP_PROTOCOL_ID.into()]),
        },
    };
    let socket = UdpSocket::bind(if endpoint.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut transport =
        CultNetRudpSocketTransportConnection::new(CultNetRudpSocketTransportOptions::client(
            runtime_id,
            socket,
            endpoint,
            ODIN_CULTMESH_DOCUMENT_CATALOG_CONNECTION_ID,
        ))?;
    transport.connect(Vec::new())?;
    let deadline = Instant::now() + Duration::from_millis(500);
    while !transport.connected() {
        let _ = transport.receive_once()?;
        transport.poll_resends()?;
        if Instant::now() >= deadline {
            bail!("timed out connecting runtime presence to {endpoint}");
        }
    }
    let receipt = transport.send_reliable(
        "schema",
        encode_cultnet_message_to_vec(&message, CultNetWireContract::CultNetSchemaV0)?,
    )?;
    let ack_deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match transport.reliable_send_status(&receipt) {
            CultNetRudpReliableSendStatus::Acknowledged => break,
            CultNetRudpReliableSendStatus::Invalidated => {
                bail!("runtime presence send was invalidated before acknowledgement")
            }
            CultNetRudpReliableSendStatus::Pending => {
                let _ = transport.receive_once()?;
                transport.poll_resends()?;
                if Instant::now() >= ack_deadline {
                    bail!("timed out awaiting runtime presence acknowledgement from {endpoint}");
                }
            }
        }
    }
    Ok(())
}

fn require_runtime_bundle(bundle: &Path) -> Result<()> {
    ensure!(
        bundle.is_absolute(),
        "Idunn runtime bundle path is not absolute"
    );
    let metadata = std::fs::symlink_metadata(bundle)
        .with_context(|| format!("inspecting runtime bundle {}", bundle.display()))?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0,
        "Idunn runtime bundle is not a root-owned read-only directory"
    );
    let parent = bundle.parent().context("runtime bundle has no parent")?;
    require_root_controlled_directory_chain(parent, "Idunn runtime bundle parent")
}

fn take_runtime_signer_descriptors_from_environment() -> Result<RuntimeSignerDescriptors> {
    let listen_pid = required_environment(SYSTEMD_LISTEN_PID_ENVIRONMENT)?;
    let listen_fds = required_environment(SYSTEMD_LISTEN_FDS_ENVIRONMENT)?;
    let listen_fd_names = required_environment(SYSTEMD_LISTEN_FDNAMES_ENVIRONMENT)?;
    let (activation_fd, provider_fd) = parse_runtime_signer_descriptor_contract(
        &listen_pid,
        &listen_fds,
        &listen_fd_names,
        std::process::id(),
    )?;
    ensure_descriptor_is_open(activation_fd, "runtime activation signer")?;
    ensure_descriptor_is_open(provider_fd, "stable provider signer")?;

    // SAFETY: systemd's LISTEN_* contract assigns the two verified-open,
    // distinct descriptors starting at SD_LISTEN_FDS_START to this exact PID.
    // This is the first descriptor-consuming step in the managed process and
    // this function takes their sole ownership.
    let activation = unsafe { File::from_raw_fd(activation_fd) };
    // SAFETY: same ownership proof as above; the descriptor indices are
    // distinct because the required names are distinct and occur once.
    let provider = unsafe { File::from_raw_fd(provider_fd) };
    protect_signer_descriptor(&activation, "runtime activation signer")?;
    protect_signer_descriptor(&provider, "stable provider signer")?;
    Ok(RuntimeSignerDescriptors {
        activation,
        provider,
    })
}

fn parse_runtime_signer_descriptor_contract(
    listen_pid: &str,
    listen_fds: &str,
    listen_fd_names: &str,
    process_id: u32,
) -> Result<(RawFd, RawFd)> {
    let declared_pid = listen_pid
        .parse::<u32>()
        .context("parsing systemd LISTEN_PID")?;
    ensure!(
        declared_pid.to_string() == listen_pid && declared_pid == process_id,
        "systemd signer descriptors belong to a different process"
    );
    let descriptor_count = listen_fds
        .parse::<usize>()
        .context("parsing systemd LISTEN_FDS")?;
    ensure!(
        descriptor_count.to_string() == listen_fds && descriptor_count == 2,
        "Connector requires exactly two systemd signer descriptors"
    );
    let names = listen_fd_names.split(':').collect::<Vec<_>>();
    ensure!(
        names.as_slice() == [ACTIVATION_SIGNER_FD_NAME, PROVIDER_SIGNER_FD_NAME],
        "systemd signer descriptor names or order differ from Idunn's contract"
    );
    Ok((SYSTEMD_LISTEN_FDS_START, SYSTEMD_LISTEN_FDS_START + 1))
}

fn ensure_descriptor_is_open(descriptor: RawFd, label: &str) -> Result<()> {
    // SAFETY: F_GETFD accepts an integer descriptor and performs no pointer
    // dereference. A failure leaves the descriptor untouched.
    if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening inherited {label} descriptor"));
    }
    Ok(())
}

fn protect_signer_descriptor(file: &File, label: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {label} descriptor"))?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o777 == 0o400
            && metadata.nlink() == 1
            && metadata.len() > 0,
        "{label} descriptor is not a root-owned 0400 singly-linked regular file"
    );
    // SAFETY: F_GETFL observes integer flags on the live descriptor owned by
    // `file` and does not transfer ownership.
    let status_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if status_flags == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("reading {label} access mode"));
    }
    ensure!(
        status_flags & libc::O_ACCMODE == libc::O_RDONLY,
        "{label} descriptor is not read-only"
    );
    mark_descriptor_close_on_exec(file, label)
}

fn mark_descriptor_close_on_exec(file: &File, label: &str) -> Result<()> {
    let descriptor = file.as_raw_fd();
    // SAFETY: fcntl observes and mutates only the flags of the valid descriptor
    // owned by `file`; it does not dereference a pointer or transfer ownership.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("reading {label} descriptor flags"));
    }
    // Defense in depth: even before the readers consume and close the files,
    // an accidentally spawned child cannot inherit either signing authority.
    // SAFETY: same valid descriptor and integer-only fcntl contract as above.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("protecting {label} descriptor from child inheritance"));
    }
    Ok(())
}

fn require_root_read_only_file(path: &Path, label: &str) -> Result<()> {
    ensure!(path.is_absolute(), "{label} path is not absolute");
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.mode() & 0o222 == 0,
        "{label} is not a root-owned read-only regular file"
    );
    Ok(())
}

fn require_root_controlled_file(path: &Path, label: &str) -> Result<()> {
    ensure!(path.is_absolute(), "{label} path is not absolute");
    let parent = path
        .parent()
        .context("root-controlled path has no parent")?;
    let parent_metadata = std::fs::symlink_metadata(parent)
        .with_context(|| format!("inspecting {label} parent {}", parent.display()))?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {label} {}", path.display()))?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && parent_metadata.is_dir()
            && !parent_metadata.file_type().is_symlink()
            && parent_metadata.uid() == 0
            && parent_metadata.mode() & 0o022 == 0,
        "{label} is not a root-controlled regular file"
    );
    Ok(())
}

fn require_root_controlled_directory_chain(path: &Path, label: &str) -> Result<()> {
    ensure!(path.is_absolute(), "{label} path is not absolute");
    for directory in path.ancestors() {
        let metadata = std::fs::symlink_metadata(directory)
            .with_context(|| format!("inspecting {label} {}", directory.display()))?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "{label} is not entirely root-controlled"
        );
    }
    Ok(())
}

fn sibling_lock_path(path: &Path) -> Result<PathBuf> {
    let mut name = path
        .file_name()
        .context("CultCache authority path has no file name")?
        .to_os_string();
    name.push(".lock");
    Ok(path.with_file_name(name))
}

fn required_environment(name: &'static str) -> Result<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty() && value.trim() == value)
        .ok_or_else(|| anyhow!("{name} is required for an Idunn-managed Connector"))
}

fn unix_millis() -> Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis();
    millis.try_into().context("Unix time exceeds u64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cultnet_rs::{
        IdunnExpectedCapability, IdunnRuntimeActivationLaunch, IdunnServiceIdentity,
        RuntimePresenceAuthenticationContext, authenticate_runtime_presence_claim,
        derive_idunn_runtime_activation_identity_id, enroll_service_identity_at,
        verify_runtime_authority,
    };
    use std::io::{Cursor, Write};
    use std::process::{Command, Stdio};

    fn sha(digit: char) -> String {
        format!("sha256-{}", digit.to_string().repeat(64))
    }

    #[test]
    fn systemd_signer_descriptor_contract_is_exact_and_process_bound() -> Result<()> {
        let pid = 42;
        assert_eq!(
            parse_runtime_signer_descriptor_contract(
                "42",
                "2",
                &format!("{ACTIVATION_SIGNER_FD_NAME}:{PROVIDER_SIGNER_FD_NAME}"),
                pid,
            )?,
            (3, 4)
        );
        for (declared_pid, count, names) in [
            (
                "41",
                "2",
                format!("{ACTIVATION_SIGNER_FD_NAME}:{PROVIDER_SIGNER_FD_NAME}"),
            ),
            (
                "42",
                "2",
                format!("{PROVIDER_SIGNER_FD_NAME}:{ACTIVATION_SIGNER_FD_NAME}"),
            ),
            (
                "42",
                "3",
                format!("{ACTIVATION_SIGNER_FD_NAME}:{PROVIDER_SIGNER_FD_NAME}:unexpected"),
            ),
            ("42", "2", "unexpected:also-unexpected".into()),
            (
                "42",
                "2",
                format!("{ACTIVATION_SIGNER_FD_NAME}:{ACTIVATION_SIGNER_FD_NAME}"),
            ),
        ] {
            assert!(
                parse_runtime_signer_descriptor_contract(&declared_pid, count, &names, pid)
                    .is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn expected_odin_endpoint_is_explicit_rudp_and_exact() -> Result<()> {
        let expected: SocketAddr = "127.0.0.1:17871".parse()?;
        for value in [
            "rudp://127.0.0.1:17871",
            "udp://127.0.0.1:17871",
            "127.0.0.1:17871",
        ] {
            assert_eq!(parse_expected_rudp_endpoint(value)?, expected);
        }
        for value in [
            "tcp://127.0.0.1:17871",
            "http://127.0.0.1:17871",
            "odin.internal:17871",
            "",
        ] {
            assert!(parse_expected_rudp_endpoint(value).is_err());
        }
        Ok(())
    }

    #[test]
    fn signer_descriptors_and_systemd_environment_do_not_reach_a_child() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "codex-connector-signer-fds-{}-{}",
            std::process::id(),
            unix_millis()?
        ));
        std::fs::create_dir_all(&root)?;
        let mut activation = File::create(root.join("activation"))?;
        activation.write_all(&[7; 32])?;
        let mut provider = File::create(root.join("provider"))?;
        provider.write_all(&[8; 32])?;
        mark_descriptor_close_on_exec(&activation, "activation test signer")?;
        mark_descriptor_close_on_exec(&provider, "provider test signer")?;
        let activation_fd = activation.as_raw_fd();
        let provider_fd = provider.as_raw_fd();

        let mut child = Command::new("/bin/sh");
        child
            .arg("-c")
            .arg(format!(
                "test ! -e /proc/self/fd/{activation_fd} && \
                 test ! -e /proc/self/fd/{provider_fd} && \
                 test -z \"${{LISTEN_PID+x}}${{LISTEN_FDS+x}}${{LISTEN_FDNAMES+x}}\""
            ))
            .env(
                SYSTEMD_LISTEN_PID_ENVIRONMENT,
                std::process::id().to_string(),
            )
            .env(SYSTEMD_LISTEN_FDS_ENVIRONMENT, "2")
            .env(
                SYSTEMD_LISTEN_FDNAMES_ENVIRONMENT,
                format!("{ACTIVATION_SIGNER_FD_NAME}:{PROVIDER_SIGNER_FD_NAME}"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        crate::provider_backend::strip_systemd_descriptor_environment(&mut child);
        ensure!(child.status()?.success(), "signer authority reached child");

        drop((activation, provider));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    fn expected(provider_identity_id: String) -> IdunnExpectedIncarnationRecord {
        IdunnExpectedIncarnationRecord {
            schema_version: IDUNN_EXPECTED_INCARNATION_SCHEMA.into(),
            target: CONNECTOR_TARGET.into(),
            plan_id: sha('1'),
            incarnation_id: "codex-connector-test".into(),
            sealed_release_id: sha('2'),
            source_repository: "github.com/GameCult/CodexConnector".into(),
            source_revision: "3".repeat(40),
            recipe_sha256: sha('4'),
            runtime_id: "codex-connector-yggdrasil".into(),
            expected_signer_identity_id: provider_identity_id,
            health_contract: CONNECTOR_HEALTH_CONTRACT.into(),
            artifact_sha256: sha('5'),
            state_schema_generation: Some(CONNECTOR_STATE_SCHEMA_GENERATION.into()),
            state_contract_sha256: Some(CONNECTOR_STATE_CONTRACT_SHA256.into()),
            write_lease_required: true,
            route: Some(cultnet_rs::IdunnExpectedRoute {
                route_id: "codex-connector-private".into(),
                transport: "tcp".into(),
                stable_endpoint: "tcp://127.0.0.1:4103".into(),
                candidate_endpoint: "tcp://127.0.0.1:18831".into(),
            }),
            capabilities: vec![IdunnExpectedCapability {
                capability: CONNECTOR_CAPABILITY.into(),
                schema: crate::ENVELOPE_SCHEMA_ID.into(),
                compatibility: CONNECTOR_COMPATIBILITY.into(),
                minimum_capacity: 1,
            }],
            dependencies: Vec::new(),
        }
    }

    #[test]
    fn presence_is_dual_proved_and_warming_never_claims_the_write_lease() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "codex-connector-presence-{}-{}",
            std::process::id(),
            unix_millis()?
        ));
        std::fs::create_dir_all(&root)?;
        let provider = enroll_service_identity_at::<GameCultProviderHealthIdentity>(
            &root.join("provider.cc"),
        )?;
        let provider_public_key = provider.entry().public_key.clone();
        let idunn = enroll_service_identity_at::<IdunnServiceIdentity>(&root.join("idunn.cc"))?;
        let expected = expected(provider.entry().identity_id.clone());
        let issued_at = unix_millis()?;
        let launch = IdunnRuntimeActivationLaunch::issue(&expected, sha('7'), issued_at, &idunn)?;
        let activation = launch.activation().clone();
        let mut credential = Vec::new();
        assert_eq!(launch.write_credential(&mut credential)?, activation);
        let activation_signer =
            IdunnRuntimeActivationSigner::from_credential_reader(Cursor::new(credential))?;
        let mut publisher = RuntimePresencePublisher {
            endpoint: "127.0.0.1:9".parse()?,
            authority: RuntimeAuthorityMaterial {
                expected_sha256: expected.canonical_sha256()?,
                activation_sha256: activation.canonical_sha256()?,
                expected: expected.clone(),
                activation: activation.clone(),
                activation_signer,
                provider_signer: provider,
            },
            bound_endpoint: "tcp://127.0.0.1:18831".into(),
            capabilities: vec![GameCultRuntimeCapability {
                capability: CONNECTOR_CAPABILITY.into(),
                schema: crate::ENVELOPE_SCHEMA_ID.into(),
                compatibility: CONNECTOR_COMPATIBILITY.into(),
                capacity: 8,
            }],
            write_lease_path: root.join("lease.cc"),
            write_lease: None,
            sequence: 0,
        };

        let warming = publisher.signed_record("warming", "waiting", issued_at)?;
        assert_eq!(warming.publisher_sequence, 1);
        assert_eq!(warming.write_lease_sha256, None);
        let lock_path = root.join("lease.cc.lock");
        File::create(&lock_path)?;
        let lock = OpenOptions::new().read(true).open(lock_path)?;
        fs2::FileExt::lock_shared(&lock)?;
        publisher.write_lease = Some(ProcessWriteLeaseGuard {
            held: Arc::new(HeldProcessWriteLease {
                _lock: lock,
                path: root.join("lease.cc"),
                expected: expected.clone(),
                expected_sha256: expected.canonical_sha256()?,
                activation: activation.clone(),
                activation_sha256: activation.canonical_sha256()?,
                warming_presence_sha256: warming.canonical_sha256()?,
                lease_sha256: sha('8'),
            }),
        });
        let active = publisher.signed_record("active", "ready", issued_at)?;
        assert_eq!(active.publisher_sequence, 2);
        assert_eq!(active.signature.len(), 64);
        assert_eq!(active.activation_signature.len(), 64);

        let authority = verify_runtime_authority(
            &expected,
            &activation,
            &idunn.trust_anchor()?,
            &provider_public_key,
        )?;
        let payload = rmp_serde::to_vec(&active)?;
        let claim = authenticate_runtime_presence_claim(
            &payload,
            &authority,
            RuntimePresenceAuthenticationContext {
                trusted_received_at_unix_millis: issued_at,
                maximum_age_millis: 1_000,
                maximum_future_skew_millis: 1_000,
            },
        )?;
        assert_eq!(claim.record(), &active);
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("lease.cc.lock"))?;
        assert!(fs2::FileExt::try_lock_exclusive(&contender).is_err());
        drop(publisher);
        fs2::FileExt::try_lock_exclusive(&contender)?;
        fs2::FileExt::unlock(&contender)?;
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn expected_must_name_the_connector_implemented_health_and_state_contract() -> Result<()> {
        let mut expected = expected("provider".into());
        let actual = GameCultRuntimeCapability {
            capability: CONNECTOR_CAPABILITY.into(),
            schema: crate::ENVELOPE_SCHEMA_ID.into(),
            compatibility: CONNECTOR_COMPATIBILITY.into(),
            capacity: 1,
        };
        require_connector_expected_contract(&expected, &actual)?;

        expected.health_contract = "configured.health.v1".into();
        assert!(require_connector_expected_contract(&expected, &actual).is_err());
        expected.health_contract = CONNECTOR_HEALTH_CONTRACT.into();
        expected.target = "another-target".into();
        assert!(require_connector_expected_contract(&expected, &actual).is_err());
        expected.target = CONNECTOR_TARGET.into();
        expected.state_contract_sha256 = Some(sha('6'));
        assert!(require_connector_expected_contract(&expected, &actual).is_err());
        expected.state_contract_sha256 = Some(CONNECTOR_STATE_CONTRACT_SHA256.into());
        expected.state_schema_generation = Some("configured-state-v1".into());
        assert!(require_connector_expected_contract(&expected, &actual).is_err());
        Ok(())
    }

    #[test]
    fn write_lease_must_bind_the_exact_warming_incarnation() -> Result<()> {
        let expected = expected("provider".into());
        let expected_sha256 = expected.canonical_sha256()?;
        let activation_public_key = vec![0; 32];
        let activation = IdunnRuntimeActivationRecord {
            schema_version: IDUNN_RUNTIME_ACTIVATION_SCHEMA.into(),
            expected_projection_sha256: expected_sha256.clone(),
            runtime_id: expected.runtime_id.clone(),
            runtime_instance_id: sha('7'),
            activation_signer_identity_id: derive_idunn_runtime_activation_identity_id(
                &activation_public_key,
            )?,
            activation_signer_public_key: activation_public_key,
            issued_at_unix_millis: 1,
            idunn_signer_identity_id: "idunn".into(),
            signature_algorithm: "ed25519".into(),
            signature: vec![0; 64],
        };
        let activation_sha256 = activation.canonical_sha256()?;
        let warming_sha256 = sha('8');
        let mut lease = IdunnProcessWriteLeaseRecord {
            schema_version: IDUNN_PROCESS_WRITE_LEASE_SCHEMA.into(),
            target: expected.target.clone(),
            expected_projection_sha256: expected_sha256.clone(),
            plan_id: expected.plan_id.clone(),
            incarnation_id: expected.incarnation_id.clone(),
            sealed_release_id: expected.sealed_release_id.clone(),
            activation_witness_sha256: activation_sha256.clone(),
            state_schema_generation: expected.state_schema_generation.clone().unwrap(),
            state_contract_sha256: expected.state_contract_sha256.clone().unwrap(),
            runtime_id: expected.runtime_id.clone(),
            runtime_instance_id: activation.runtime_instance_id.clone(),
            warming_presence_sha256: warming_sha256.clone(),
            lease_epoch: 1,
            issued_at_unix_millis: 1,
        };
        assert_eq!(
            exact_process_write_lease_sha256(
                &lease,
                &expected,
                &expected_sha256,
                &activation,
                &activation_sha256,
                &warming_sha256,
            )?,
            lease.canonical_sha256()?
        );
        lease.warming_presence_sha256 = sha('9');
        assert!(
            exact_process_write_lease_sha256(
                &lease,
                &expected,
                &expected_sha256,
                &activation,
                &activation_sha256,
                &warming_sha256,
            )
            .is_err()
        );
        Ok(())
    }
}
