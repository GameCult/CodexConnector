use std::collections::HashSet;
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use std::time::Instant;

use cultcache_rs::{CultCache, DatabaseEntry, SingleFileMessagePackBackingStore};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    CodexAppServerConfig, CodexCallerAdmission, CodexProviderBackend, CodexProviderBackendError,
    CodexTransportAdmission, CodexTransportEnvelope, CodexTransportService, ServiceError,
    TransportFrameError, read_transport_frame, write_transport_frame,
};

const CONFIG_EPOCH: u32 = 2;
const CONFIG_KEY: &str = "runtime";
const FRAME_OVERHEAD_BUDGET: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexCallerConfig {
    pub caller_runtime_id: String,
    pub connection_key_file: PathBuf,
    pub connection_key_epoch: u32,
    pub allowed_models: Vec<String>,
    pub max_concurrent_requests: usize,
    pub max_payload_bytes: usize,
    pub max_output_tokens: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(type = "gamecult.codex.connector_config.v1")]
pub struct CodexDaemonConfig {
    #[cultcache(key = 0)]
    pub epoch: u32,
    #[cultcache(key = 1)]
    pub bind: String,
    #[cultcache(key = 2)]
    pub codex_executable: PathBuf,
    #[cultcache(key = 3)]
    pub codex_executable_sha256: [u8; 32],
    #[cultcache(key = 4)]
    pub codex_home: PathBuf,
    #[cultcache(key = 5)]
    pub max_frame_bytes: usize,
    #[cultcache(key = 6)]
    pub max_connections: usize,
    #[cultcache(key = 7)]
    pub socket_timeout_ms: u64,
    #[cultcache(key = 8)]
    pub max_expiry_skew_ms: u64,
    #[cultcache(key = 9)]
    pub callers: Vec<CodexCallerConfig>,
    #[cultcache(key = 10)]
    pub replay_store: PathBuf,
}

impl CodexDaemonConfig {
    pub fn single_caller(
        bind: impl Into<String>,
        codex_executable: PathBuf,
        codex_executable_sha256: [u8; 32],
        codex_home: PathBuf,
        replay_store: PathBuf,
        caller: CodexCallerConfig,
    ) -> Self {
        Self {
            epoch: CONFIG_EPOCH,
            bind: bind.into(),
            codex_executable,
            codex_executable_sha256,
            codex_home,
            max_frame_bytes: caller
                .max_payload_bytes
                .saturating_add(FRAME_OVERHEAD_BUDGET),
            max_connections: caller.max_concurrent_requests.max(8),
            socket_timeout_ms: 10_000,
            max_expiry_skew_ms: 300_000,
            callers: vec![caller],
            replay_store,
        }
    }

    pub fn validate(&self) -> Result<SocketAddr, CodexDaemonError> {
        if self.epoch != CONFIG_EPOCH {
            return Err(CodexDaemonError::InvalidConfig("epoch"));
        }
        let bind = self
            .bind
            .parse::<SocketAddr>()
            .map_err(|_| CodexDaemonError::InvalidConfig("bind"))?;
        if !bind.ip().is_loopback() {
            return Err(CodexDaemonError::InvalidConfig("bind"));
        }
        if self.codex_executable.as_os_str().is_empty()
            || self.codex_executable_sha256 == [0; 32]
            || self.codex_home.as_os_str().is_empty()
            || self.replay_store.as_os_str().is_empty()
            || self.max_frame_bytes < FRAME_OVERHEAD_BUDGET * 2
            || self.max_frame_bytes > u32::MAX as usize
            || self.max_connections == 0
            || self.socket_timeout_ms == 0
            || self.max_expiry_skew_ms == 0
            || self.callers.is_empty()
        {
            return Err(CodexDaemonError::InvalidConfig("runtime bounds"));
        }
        let required_connections = required_connection_capacity(&self.callers)?;
        if self.max_connections < required_connections {
            return Err(CodexDaemonError::InvalidConfig("connection capacity"));
        }
        let mut caller_ids = HashSet::new();
        for caller in &self.callers {
            let mut allowed_models = HashSet::new();
            if caller.caller_runtime_id.trim().is_empty()
                || caller.caller_runtime_id.trim() != caller.caller_runtime_id
                || !caller_ids.insert(caller.caller_runtime_id.as_str())
                || caller.connection_key_file.as_os_str().is_empty()
                || caller.connection_key_epoch == 0
                || caller.allowed_models.is_empty()
                || caller.allowed_models.iter().any(|model| {
                    model.trim().is_empty()
                        || model.trim() != model
                        || !allowed_models.insert(model.as_str())
                })
                || caller.max_concurrent_requests == 0
                || caller.max_payload_bytes < 4096
                || caller.max_payload_bytes > self.max_frame_bytes - FRAME_OVERHEAD_BUDGET
                || caller.max_output_tokens == 0
            {
                return Err(CodexDaemonError::InvalidConfig("caller admission"));
            }
        }
        Ok(bind)
    }

    pub fn admit_caller(&mut self, caller: CodexCallerConfig) -> Result<(), CodexDaemonError> {
        let mut candidate = self.clone();
        if candidate
            .callers
            .iter()
            .any(|existing| existing.caller_runtime_id == caller.caller_runtime_id)
        {
            return Err(CodexDaemonError::InvalidConfig("duplicate caller"));
        }
        candidate.max_frame_bytes = candidate.max_frame_bytes.max(
            caller
                .max_payload_bytes
                .saturating_add(FRAME_OVERHEAD_BUDGET),
        );
        candidate.callers.push(caller);
        candidate.max_connections = required_connection_capacity(&candidate.callers)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }
}

fn required_connection_capacity(callers: &[CodexCallerConfig]) -> Result<usize, CodexDaemonError> {
    callers
        .iter()
        .try_fold(0_usize, |total, caller| {
            total.checked_add(caller.max_concurrent_requests)
        })
        .map(|total| total.max(8))
        .ok_or(CodexDaemonError::InvalidConfig("connection capacity"))
}

pub fn load_daemon_config(path: &Path) -> Result<CodexDaemonConfig, CodexDaemonError> {
    let mut cache = CultCache::new();
    cache
        .register_entry_type::<CodexDaemonConfig>()
        .map_err(config_store_error)?;
    cache.add_generic_backing_store(SingleFileMessagePackBackingStore::new(path));
    cache
        .pull_all_backing_stores()
        .map_err(config_store_error)?;
    let config = cache
        .get_required::<CodexDaemonConfig>(CONFIG_KEY)
        .map_err(config_store_error)?;
    config.validate()?;
    Ok(config)
}

fn load_daemon_config_snapshot(
    path: &Path,
) -> Result<(CodexDaemonConfig, Vec<u8>), CodexDaemonError> {
    let store = SingleFileMessagePackBackingStore::new(path);
    let (config, snapshot) = store
        .with_read_only_shared_snapshot(|entries| {
            let [envelope] = entries.as_slice() else {
                anyhow::bail!("connector configuration must contain exactly one record");
            };
            if envelope.key != CONFIG_KEY
                || envelope.r#type != CodexDaemonConfig::TYPE
                || envelope.schema_id.as_deref() != Some(CodexDaemonConfig::TYPE)
            {
                anyhow::bail!("connector configuration has the wrong typed envelope");
            }
            let config: CodexDaemonConfig = rmp_serde::from_slice(&envelope.payload)?;
            if rmp_serde::to_vec(&config)? != envelope.payload {
                anyhow::bail!("connector configuration is not canonical positional MessagePack");
            }
            let snapshot = fs::read(path)?;
            Ok((config, snapshot))
        })
        .map_err(config_store_error)?;
    config.validate()?;
    Ok((config, snapshot))
}

pub fn write_daemon_config(
    path: &Path,
    config: &CodexDaemonConfig,
) -> Result<(), CodexDaemonError> {
    config.validate()?;
    let mut cache = CultCache::new();
    cache
        .register_entry_type::<CodexDaemonConfig>()
        .map_err(config_store_error)?;
    cache.add_generic_backing_store(SingleFileMessagePackBackingStore::new(path));
    cache
        .pull_all_backing_stores()
        .map_err(config_store_error)?;
    cache.put(CONFIG_KEY, config).map_err(config_store_error)?;
    Ok(())
}

pub fn serve(config_path: &Path) -> Result<(), CodexDaemonError> {
    let (config, config_bytes) = load_daemon_config_snapshot(config_path)?;
    let bind = config.validate()?;
    let (admissions, caller_key_bindings) = load_admissions(&config)?;
    #[cfg(target_os = "linux")]
    let (traffic_admission, prepared_health_publisher) =
        start_idunn_health_publisher(config_path, &config_bytes, &config, &caller_key_bindings)?;

    // Probation performs only immutable activation verification and its one
    // signed warming publication. Provider process, replay, and socket
    // actuation begin only after Idunn grants that exact startup statement.
    let backend = Arc::new(CodexProviderBackend::start(CodexAppServerConfig {
        executable: config.codex_executable.clone(),
        executable_sha256: config.codex_executable_sha256,
        codex_home: config.codex_home.clone(),
        max_result_bytes: config.max_frame_bytes - FRAME_OVERHEAD_BUDGET,
    })?);
    let readiness = backend.readiness()?;
    let service = Arc::new(Mutex::new(CodexTransportService::open(
        &config.replay_store,
        admissions,
        config.max_expiry_skew_ms,
    )?));
    #[cfg(target_os = "linux")]
    traffic_admission
        .require_current()
        .map_err(CodexDaemonError::Health)?;
    let listener = TcpListener::bind(bind).map_err(CodexDaemonError::Listen)?;
    #[cfg(target_os = "linux")]
    listener
        .set_nonblocking(true)
        .map_err(CodexDaemonError::Listen)?;
    #[cfg(target_os = "linux")]
    start_periodic_idunn_health_publisher(prepared_health_publisher, backend.clone())?;
    let active_connections = Arc::new(AtomicUsize::new(0));
    #[cfg(target_os = "linux")]
    let mut next_traffic_admission_check = Instant::now();
    eprintln!(
        "codex-connector ready at {} for {} callers using {:?}",
        listener.local_addr().map_err(CodexDaemonError::Listen)?,
        config.callers.len(),
        readiness.auth_mode
    );

    loop {
        #[cfg(target_os = "linux")]
        if Instant::now() >= next_traffic_admission_check {
            traffic_admission
                .require_current()
                .map_err(CodexDaemonError::Health)?;
            next_traffic_admission_check = Instant::now() + Duration::from_millis(100);
        }
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(error) => return Err(CodexDaemonError::Listen(error)),
        };
        #[cfg(target_os = "linux")]
        // The polling check terminates an idle process after revocation. This
        // second check is the traffic commit point: an accepted socket receives
        // no request worker under a stale grant.
        traffic_admission
            .require_current()
            .map_err(CodexDaemonError::Health)?;
        if !stream
            .peer_addr()
            .map_err(CodexDaemonError::Connection)?
            .ip()
            .is_loopback()
        {
            continue;
        }
        let Some(permit) =
            ConnectionPermit::acquire(active_connections.clone(), config.max_connections)
        else {
            continue;
        };
        let service = service.clone();
        let backend = backend.clone();
        #[cfg(target_os = "linux")]
        let request_traffic_admission = traffic_admission.clone();
        let max_frame_bytes = config.max_frame_bytes;
        let timeout = Duration::from_millis(config.socket_timeout_ms);
        thread::Builder::new()
            .name("codex-connector-request".to_string())
            .spawn(move || {
                let _permit = permit;
                let _ = serve_connection(
                    stream,
                    &service,
                    &backend,
                    #[cfg(target_os = "linux")]
                    &request_traffic_admission,
                    max_frame_bytes,
                    timeout,
                );
            })
            .map_err(CodexDaemonError::Thread)?;
    }
}

#[cfg(target_os = "linux")]
fn start_idunn_health_publisher(
    config_path: &Path,
    config_bytes: &[u8],
    config: &CodexDaemonConfig,
    caller_key_bindings: &[LoadedCallerKeyBinding],
) -> Result<
    (
        crate::idunn_health::ConnectorTrafficAdmissionGate,
        crate::idunn_health::ProviderHealthPublisher,
    ),
    CodexDaemonError,
> {
    let endpoint = required_environment("CODEX_CONNECTOR_IDUNN_RUDP")?
        .parse::<SocketAddr>()
        .map_err(|_| CodexDaemonError::InvalidConfig("Idunn health endpoint"))?;
    let daemon_id = required_environment("CODEX_CONNECTOR_IDUNN_DAEMON")?;
    let runtime_id = required_environment("CODEX_CONNECTOR_RUNTIME_ID")?;
    let contract = std::env::var("CODEX_CONNECTOR_IDUNN_HEALTH_CONTRACT")
        .unwrap_or_else(|_| crate::idunn_health::CODEX_CONNECTOR_IDUNN_HEALTH_CONTRACT.to_string());
    let identity = PathBuf::from(required_environment(
        "CODEX_CONNECTOR_IDUNN_HEALTH_IDENTITY",
    )?);
    let release = crate::idunn_health::active_release_binding(
        &config.codex_executable,
        &config.codex_executable_sha256,
    )
    .map_err(CodexDaemonError::Health)?;
    let activation = crate::idunn_health::active_activation_binding(
        config_path,
        config_bytes,
        config,
        caller_key_bindings,
    )
    .map_err(CodexDaemonError::Health)?;
    let mut publisher = crate::idunn_health::ProviderHealthPublisher::open(
        endpoint,
        daemon_id,
        runtime_id,
        contract,
        &identity,
        release.clone(),
        activation.clone(),
    )
    .map_err(CodexDaemonError::Health)?;
    let published = publisher
        .publish("warming", "traffic-admission-pending")
        .map_err(CodexDaemonError::Health)?;
    let traffic_admission = crate::idunn_health::ConnectorTrafficAdmissionGate::from_environment(
        &release,
        &activation,
        &published,
    )
    .map_err(CodexDaemonError::Health)?;
    traffic_admission
        .wait_until_granted(Duration::from_secs(120))
        .map_err(CodexDaemonError::Health)?;
    Ok((traffic_admission, publisher))
}

#[cfg(target_os = "linux")]
fn start_periodic_idunn_health_publisher(
    mut publisher: crate::idunn_health::ProviderHealthPublisher,
    backend: Arc<CodexProviderBackend>,
) -> Result<(), CodexDaemonError> {
    thread::Builder::new()
        .name("codex-connector-health".to_string())
        .spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(10));
                let (state, detail) = provider_health_observation(&backend);
                if let Err(error) = publisher.publish(state, detail) {
                    eprintln!("codex-connector health publication failed: {error}");
                }
            }
        })
        .map_err(CodexDaemonError::HealthThread)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn provider_health_observation(backend: &CodexProviderBackend) -> (&'static str, &'static str) {
    provider_health_state(backend.readiness().is_ok())
}

#[cfg(target_os = "linux")]
fn provider_health_state(ready: bool) -> (&'static str, &'static str) {
    if ready {
        ("active", "credential-isolated-transport-ready")
    } else {
        ("degraded", "provider-backend-unready")
    }
}

#[cfg(target_os = "linux")]
fn required_environment(name: &'static str) -> Result<String, CodexDaemonError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty() && value == value.trim())
        .ok_or(CodexDaemonError::InvalidConfig(name))
}

#[derive(Clone)]
pub(crate) struct LoadedCallerKeyBinding {
    pub(crate) caller_runtime_id: String,
    pub(crate) connection_key_file: PathBuf,
    pub(crate) connection_key_epoch: u32,
    pub(crate) raw_file_sha256: [u8; 32],
}

fn load_admissions(
    config: &CodexDaemonConfig,
) -> Result<(Vec<CodexCallerAdmission>, Vec<LoadedCallerKeyBinding>), CodexDaemonError> {
    let mut admissions = Vec::with_capacity(config.callers.len());
    let mut bindings = Vec::with_capacity(config.callers.len());
    for caller in &config.callers {
        let raw = Zeroizing::new(
            fs::read(&caller.connection_key_file).map_err(CodexDaemonError::ConnectionKey)?,
        );
        let secret = std::str::from_utf8(raw.as_slice())
            .map_err(|_| CodexDaemonError::InvalidConfig("caller connection key encoding"))?
            .trim_end_matches(['\r', '\n']);
        admissions.push(
            CodexCallerAdmission::new(
                caller.caller_runtime_id.clone(),
                secret.to_string(),
                caller.connection_key_epoch,
                caller.allowed_models.clone(),
                caller.max_concurrent_requests,
                caller.max_payload_bytes,
                caller.max_output_tokens,
            )
            .map_err(CodexDaemonError::Service)?,
        );
        bindings.push(LoadedCallerKeyBinding {
            caller_runtime_id: caller.caller_runtime_id.clone(),
            connection_key_file: caller.connection_key_file.clone(),
            connection_key_epoch: caller.connection_key_epoch,
            raw_file_sha256: sha2::Sha256::digest(raw.as_slice()).into(),
        });
    }
    Ok((admissions, bindings))
}

fn serve_connection(
    mut stream: TcpStream,
    service: &Mutex<CodexTransportService>,
    backend: &CodexProviderBackend,
    #[cfg(target_os = "linux")]
    traffic_admission: &crate::idunn_health::ConnectorTrafficAdmissionGate,
    max_frame_bytes: usize,
    timeout: Duration,
) -> Result<(), CodexDaemonError> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(CodexDaemonError::Connection)?;
    let request = read_transport_frame(&mut stream, max_frame_bytes).map_err(frame_error)?;
    let envelope: CodexTransportEnvelope =
        rmp_serde::from_slice(&request).map_err(|_| CodexDaemonError::FrameEncoding)?;
    #[cfg(target_os = "linux")]
    // This is the traffic-to-Connector authority transfer. The complete
    // request is inert until the current root grant admits service.begin;
    // backend consequence remains owned by the admitted request claim.
    traffic_admission
        .require_current()
        .map_err(CodexDaemonError::Health)?;
    let admission = service
        .lock()
        .map_err(|_| CodexDaemonError::ServicePoisoned)?
        .begin(&envelope, unix_ms()?)?;
    let response = match admission {
        CodexTransportAdmission::Reply(response) => response,
        CodexTransportAdmission::Execute(claim) => {
            let result = backend.execute(claim.invocation());
            service
                .lock()
                .map_err(|_| CodexDaemonError::ServicePoisoned)?
                .complete(*claim, result)?
        }
    };
    let response = rmp_serde::to_vec(&response).map_err(|_| CodexDaemonError::FrameEncoding)?;
    write_transport_frame(&mut stream, &response, max_frame_bytes).map_err(frame_error)
}

fn frame_error(error: TransportFrameError) -> CodexDaemonError {
    match error {
        TransportFrameError::Connection(error) => CodexDaemonError::Connection(error),
        TransportFrameError::Size => CodexDaemonError::FrameSize,
    }
}

fn unix_ms() -> Result<u64, CodexDaemonError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CodexDaemonError::Clock)?
        .as_millis();
    u64::try_from(millis).map_err(|_| CodexDaemonError::Clock)
}

fn config_store_error(error: impl std::fmt::Display) -> CodexDaemonError {
    CodexDaemonError::ConfigStore(error.to_string())
}

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl ConnectionPermit {
    fn acquire(active: Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        let mut observed = active.load(Ordering::Acquire);
        loop {
            if observed >= limit {
                return None;
            }
            match active.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self { active }),
                Err(current) => observed = current,
            }
        }
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Error)]
pub enum CodexDaemonError {
    #[error("connector config store failed: {0}")]
    ConfigStore(String),
    #[error("invalid connector config field {0}")]
    InvalidConfig(&'static str),
    #[error("connector connection key is unavailable")]
    ConnectionKey(#[source] std::io::Error),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Provider(#[from] CodexProviderBackendError),
    #[error("connector service lock was poisoned")]
    ServicePoisoned,
    #[error("connector listener failed")]
    Listen(#[source] std::io::Error),
    #[error("connector request thread failed")]
    Thread(#[source] std::io::Error),
    #[cfg(target_os = "linux")]
    #[error("connector signed health or traffic authority failed: {0}")]
    Health(#[source] anyhow::Error),
    #[cfg(target_os = "linux")]
    #[error("connector health thread could not start")]
    HealthThread(#[source] std::io::Error),
    #[error("connector connection failed")]
    Connection(#[source] std::io::Error),
    #[error("connector frame exceeded its bound")]
    FrameSize,
    #[error("connector frame was not valid MessagePack")]
    FrameEncoding,
    #[error("system clock is before the Unix epoch")]
    Clock,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn config(root: &Path) -> CodexDaemonConfig {
        CodexDaemonConfig {
            epoch: CONFIG_EPOCH,
            bind: "127.0.0.1:4103".to_string(),
            codex_executable: root.join("codex"),
            codex_executable_sha256: [3; 32],
            codex_home: root.join("codex-home"),
            max_frame_bytes: 1024 * 1024,
            max_connections: 16,
            socket_timeout_ms: 30_000,
            max_expiry_skew_ms: 300_000,
            callers: vec![CodexCallerConfig {
                caller_runtime_id: "epiphany-yggdrasil".to_string(),
                connection_key_file: root.join("epiphany.key"),
                connection_key_epoch: 1,
                allowed_models: vec!["gpt-5.4".to_string()],
                max_concurrent_requests: 4,
                max_payload_bytes: 512 * 1024,
                max_output_tokens: 32_768,
            }],
            replay_store: root.join("replay.cc"),
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn signed_health_never_reports_an_unready_provider_active() {
        assert_eq!(
            provider_health_state(true),
            ("active", "credential-isolated-transport-ready")
        );
        assert_eq!(
            provider_health_state(false),
            ("degraded", "provider-backend-unready")
        );
    }

    #[test]
    fn typed_cultcache_config_round_trips_and_refuses_epoch_substitution() {
        let root = std::env::temp_dir().join(format!(
            "codex-connector-config-{}-{}",
            std::process::id(),
            unix_ms().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("connector.cc");
        let expected = config(&root);
        write_daemon_config(&path, &expected).unwrap();
        assert_eq!(load_daemon_config(&path).unwrap(), expected);
        let exact_bytes = fs::read(&path).unwrap();
        let (loaded, loaded_bytes) = load_daemon_config_snapshot(&path).unwrap();
        assert_eq!(loaded, expected);
        assert_eq!(loaded_bytes, exact_bytes);

        let mut stale = expected;
        stale.epoch = 0;
        assert!(matches!(
            write_daemon_config(&path, &stale),
            Err(CodexDaemonError::InvalidConfig("epoch"))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn production_config_snapshot_never_creates_its_authority_lock() {
        let root = std::env::temp_dir().join(format!(
            "codex-connector-read-only-config-{}-{}",
            std::process::id(),
            unix_ms().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("connector.cc");
        write_daemon_config(&path, &config(&root)).unwrap();
        let before = fs::read(&path).unwrap();
        let lock_path = path.with_file_name("connector.cc.lock");
        fs::remove_file(&lock_path).unwrap();

        assert!(load_daemon_config_snapshot(&path).is_err());
        assert!(!lock_path.exists());
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn single_caller_initializer_derives_daemon_bounds_without_reowning_policy() {
        let root = Path::new("/srv/codex-connector");
        let caller = CodexCallerConfig {
            caller_runtime_id: "ghostlight-dungeon-yggdrasil".to_string(),
            connection_key_file: root.join("ghostlight.key"),
            connection_key_epoch: 3,
            allowed_models: vec!["gpt-5.4".to_string()],
            max_concurrent_requests: 12,
            max_payload_bytes: 1_048_576,
            max_output_tokens: 32_768,
        };
        let config = CodexDaemonConfig::single_caller(
            "127.0.0.1:4103",
            root.join("codex"),
            [7; 32],
            root.join("codex-home"),
            root.join("replay.cc"),
            caller.clone(),
        );

        assert_eq!(config.epoch, CONFIG_EPOCH);
        assert_eq!(config.max_frame_bytes, 1_052_672);
        assert_eq!(config.max_connections, 12);
        assert_eq!(config.callers, vec![caller]);
        config.validate().unwrap();
    }

    #[test]
    fn typed_config_preserves_a_unique_multi_model_caller_allowlist() {
        let root = Path::new("/srv/codex-connector");
        let mut config = config(root);
        config.callers[0].allowed_models =
            vec!["gpt-5.6-luna".to_string(), "gpt-5.6-terra".to_string()];
        config.validate().unwrap();

        config.callers[0]
            .allowed_models
            .push("gpt-5.6-luna".to_string());
        assert!(matches!(
            config.validate(),
            Err(CodexDaemonError::InvalidConfig("caller admission"))
        ));
    }

    #[test]
    fn caller_admission_reserves_every_independently_admitted_request_slot() {
        let root = Path::new("/srv/codex-connector");
        let first = CodexCallerConfig {
            caller_runtime_id: "ghostlight-dungeon-yggdrasil".to_string(),
            connection_key_file: root.join("ghostlight.key"),
            connection_key_epoch: 1,
            allowed_models: vec!["gpt-5.6-luna".to_string()],
            max_concurrent_requests: 8,
            max_payload_bytes: 1_048_576,
            max_output_tokens: 16_384,
        };
        let mut config = CodexDaemonConfig::single_caller(
            "127.0.0.1:4103",
            root.join("codex"),
            [7; 32],
            root.join("codex-home"),
            root.join("replay.cc"),
            first,
        );
        config
            .admit_caller(CodexCallerConfig {
                caller_runtime_id: "epiphany-model-runtime".to_string(),
                connection_key_file: root.join("epiphany.key"),
                connection_key_epoch: 1,
                allowed_models: vec!["gpt-5.6-luna".to_string()],
                max_concurrent_requests: 8,
                max_payload_bytes: 1_048_576,
                max_output_tokens: 16_384,
            })
            .unwrap();

        assert_eq!(config.max_connections, 16);
        config.validate().unwrap();

        config.max_connections = 15;
        assert!(matches!(
            config.validate(),
            Err(CodexDaemonError::InvalidConfig("connection capacity"))
        ));
    }

    #[test]
    fn direct_pipe_frame_is_big_endian_and_refuses_oversize_before_allocation() {
        let mut encoded = Vec::new();
        write_transport_frame(&mut encoded, b"typed", 16).unwrap();
        assert_eq!(&encoded[..4], &5_u32.to_be_bytes());
        assert_eq!(
            read_transport_frame(&mut Cursor::new(encoded), 16).unwrap(),
            b"typed"
        );

        let oversized = 17_u32.to_be_bytes().to_vec();
        assert!(matches!(
            read_transport_frame(&mut Cursor::new(oversized), 16),
            Err(TransportFrameError::Size)
        ));
    }
}
