use std::fs::OpenOptions;
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use cultcache_rs::{CacheBackingStore, CultCacheEnvelope, SingleFileMessagePackBackingStore};
use cultnet_rs::{
    CultNetMessage, CultNetRawDocumentRecord, CultNetRawPayloadEncoding,
    CultNetRudpSocketTransportConnection, CultNetRudpSocketTransportOptions, CultNetWireContract,
    encode_cultnet_message_to_vec,
};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
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
// Idunn's daemon-health ingress owns one shared RUDP connection contract.
// Publisher identity is carried by the signed record, not by transport IDs.
const RUDP_CONNECTION_ID: u32 = 0x1d0d_0001;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
            || self.release_id.is_some()
            || self.release_witness_sha256.is_some()
            || self.source_commit.is_some()
            || self.deployment_id.is_some()
            || self.signature_algorithm != "ed25519"
            || self.signature.len() != 64
            || self.private_state_exposed
        {
            bail!("signed daemon health shape is invalid");
        }
        Ok(())
    }
}

pub struct ProviderHealthPublisher {
    endpoint: SocketAddr,
    daemon_id: String,
    runtime_id: String,
    contract: String,
    signer: ProviderHealthSigner,
    incarnation: String,
    sequence: u64,
}

impl ProviderHealthPublisher {
    pub fn open(
        endpoint: SocketAddr,
        daemon_id: impl Into<String>,
        runtime_id: impl Into<String>,
        contract: impl Into<String>,
        identity_store: &Path,
    ) -> Result<Self> {
        let daemon_id = daemon_id.into();
        let runtime_id = runtime_id.into();
        let contract = contract.into();
        require_id(&daemon_id, "daemon id")?;
        require_id(&runtime_id, "runtime id")?;
        require_id(&contract, "health contract")?;
        Ok(Self {
            endpoint,
            daemon_id,
            runtime_id,
            contract,
            signer: open_identity(identity_store)?,
            incarnation: uuid::Uuid::new_v4().to_string(),
            sequence: 0,
        })
    }

    pub fn publish(&mut self, state: &str, detail: &str) -> Result<()> {
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
            release_id: None,
            release_witness_sha256: None,
            source_commit: None,
            deployment_id: None,
            signature_algorithm: "ed25519".into(),
            signature: Vec::new(),
            private_state_exposed: false,
        };
        let unsigned = unsigned_record(&record)?;
        record.signature = self
            .signer
            .key
            .sign(&signing_message(&unsigned))
            .to_bytes()
            .to_vec();
        record.validate()?;
        publish(self.endpoint, &self.runtime_id, &record)
    }
}

pub fn enroll_provider_health_identity(path: &Path) -> Result<String> {
    let binding = machine_binding()?;
    enroll_provider_health_identity_with_binding(path, &binding)
}

fn enroll_provider_health_identity_with_binding(path: &Path, binding: &str) -> Result<String> {
    if path.exists() {
        bail!("provider health identity already exists");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("provider health identity path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    let mut seed = [0_u8; 32];
    OsRng.fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let public_key = key.verifying_key().to_bytes();
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let entry = ProviderHealthIdentity {
        schema_version: IDENTITY_SCHEMA.into(),
        identity_id: identity_id(&public_key),
        public_key: public_key.to_vec(),
        protected_private_seed: mask_seed(&seed, binding),
        protector_kind: "linux_file_mode_machine_id_binding".into(),
        protector_binding: binding.into(),
        protector_version: "v1".into(),
        assurance: "os_installation_file_bound_cloneable_baseline".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
        enrollment_nonce: nonce.to_vec(),
    };
    validate_identity(&entry)?;
    let envelope = CultCacheEnvelope {
        key: IDENTITY_KEY.into(),
        r#type: IDENTITY_TYPE.into(),
        payload: rmp_serde::to_vec(&entry)?,
        stored_at: entry.created_at.clone(),
        schema_id: Some(IDENTITY_SCHEMA.into()),
    };
    let bytes = rmp_serde::to_vec(&vec![envelope])?;
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error.into());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(hex(&open_identity_with_binding(path, binding)?
        .entry
        .public_key))
}

pub fn provider_health_public_key_hex(path: &Path) -> Result<String> {
    Ok(hex(&open_identity(path)?.entry.public_key))
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

fn publish(endpoint: SocketAddr, runtime_id: &str, record: &SignedDaemonHealth) -> Result<()> {
    let payload = rmp_serde::to_vec(record)?;
    if rmp_serde::from_slice::<SignedDaemonHealth>(&payload)? != *record {
        bail!("signed health MessagePack did not round trip");
    }
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
    Ok(())
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

    #[test]
    fn identity_round_trips_and_signed_health_is_private_free() {
        let root = std::env::temp_dir().join(format!(
            "codex-connector-health-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("identity.cc");
        let binding = "fixture-machine-binding";
        let public_key = enroll_provider_health_identity_with_binding(&path, binding).unwrap();
        assert_eq!(
            hex(&open_identity_with_binding(&path, binding)
                .unwrap()
                .entry
                .public_key),
            public_key
        );
        let signer = open_identity_with_binding(&path, binding).unwrap();
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
            release_id: None,
            release_witness_sha256: None,
            source_commit: None,
            deployment_id: None,
            signature_algorithm: "ed25519".into(),
            signature: Vec::new(),
            private_state_exposed: false,
        };
        let unsigned = unsigned_record(&record).unwrap();
        record.signature = signer
            .key
            .sign(&signing_message(&unsigned))
            .to_bytes()
            .to_vec();
        record.validate().unwrap();
        let public: [u8; 32] = signer.entry.public_key.try_into().unwrap();
        let signature = Signature::from_slice(&record.signature).unwrap();
        VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify(&signing_message(&unsigned), &signature)
            .unwrap();
        assert!(!record.private_state_exposed);
        std::fs::remove_dir_all(root).unwrap();
    }
}
