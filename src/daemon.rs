use std::collections::HashSet;
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

use cultcache_rs::{CultCache, DatabaseEntry, SingleFileMessagePackBackingStore};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use cultnet_rs::{
    CultNetMessage, CultNetWireContract, GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA,
    decode_cultnet_message_from_slice, encode_cultnet_message_to_vec,
};

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
    Ok(caller_request_capacity(callers)?.max(8))
}

fn caller_request_capacity(callers: &[CodexCallerConfig]) -> Result<usize, CodexDaemonError> {
    callers
        .iter()
        .try_fold(0_usize, |total, caller| {
            total.checked_add(caller.max_concurrent_requests)
        })
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

fn load_daemon_config_read_only(path: &Path) -> Result<CodexDaemonConfig, CodexDaemonError> {
    let store = SingleFileMessagePackBackingStore::new(path);
    let config = store
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
            Ok(config)
        })
        .map_err(config_store_error)?;
    config.validate()?;
    Ok(config)
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

pub fn serve(
    config_path: &Path,
    managed_state_root: Option<&Path>,
) -> Result<(), CodexDaemonError> {
    #[cfg(target_os = "linux")]
    if std::env::var_os(crate::idunn_health::IDUNN_RUNTIME_BUNDLE_ENVIRONMENT).is_some() {
        crate::idunn_health::require_managed_config_store(config_path)
            .map_err(CodexDaemonError::Health)?;
    }
    let config = load_daemon_config_read_only(config_path)?;
    let configured_bind = config.validate()?;
    #[cfg(target_os = "linux")]
    let bind = effective_bind_from_environment(configured_bind)?;
    #[cfg(not(target_os = "linux"))]
    let bind = configured_bind;
    #[cfg(target_os = "linux")]
    let (mut codex_executable, mut codex_home, mut replay_store) =
        effective_runtime_paths_from_environment(&config, managed_state_root)?;
    #[cfg(not(target_os = "linux"))]
    let (codex_executable, codex_home, replay_store) = match managed_state_root {
        None => (
            config.codex_executable.clone(),
            config.codex_home.clone(),
            config.replay_store.clone(),
        ),
        Some(_) => {
            return Err(CodexDaemonError::InvalidConfig(
                "Idunn state root on an unmanaged platform",
            ));
        }
    };
    let admissions = load_admissions(&config)?;

    #[cfg(target_os = "linux")]
    // Consume the systemd-owned signer descriptors before opening another
    // process descriptor. Their numeric 3/4 contract is valid only at the
    // managed process entry boundary.
    let mut prepared_presence_publisher = prepare_runtime_presence_publisher(bind, &config)?;

    // Binding the candidate socket is service physiology. Idunn owns whether
    // that candidate receives traffic, so Connector carries no second route
    // or traffic-admission gate.
    let listener = TcpListener::bind(bind).map_err(CodexDaemonError::Listen)?;
    let bound = listener.local_addr().map_err(CodexDaemonError::Listen)?;
    #[cfg(target_os = "linux")]
    if let Some(publisher) = prepared_presence_publisher.as_mut() {
        if bound != bind {
            return Err(CodexDaemonError::InvalidConfig("Idunn candidate bind"));
        }
        let warming_sha256 = publisher
            .publish("warming", "awaiting-process-write-lease")
            .map_err(CodexDaemonError::Health)?;
        publisher
            .acquire_process_write_lease(&warming_sha256, Duration::from_secs(120))
            .map_err(CodexDaemonError::Health)?;
        // The incumbent is fenced only when Idunn can replace the lease under
        // our shared lock. Re-observe every write-capable path after that
        // handoff so a pre-lease filesystem shape cannot survive into Active.
        (codex_executable, codex_home, replay_store) =
            effective_runtime_paths_from_environment(&config, managed_state_root)?;
    }
    #[cfg(target_os = "linux")]
    // Keep the shared lease lock in the main service body as well as the
    // publisher thread. A health-thread failure must not release write
    // authority while replay or the official credential writer remains live.
    let _process_write_lease_guard = prepared_presence_publisher
        .as_ref()
        .map(|publisher| publisher.process_write_lease_guard())
        .transpose()
        .map_err(CodexDaemonError::Health)?;

    // Opening replay state is the first persistent write-capable actuation.
    // Managed launches reach this point only after the exact warming process
    // has received Idunn's typed process-write lease.
    let backend = Arc::new(CodexProviderBackend::start(CodexAppServerConfig {
        executable: codex_executable,
        executable_sha256: config.codex_executable_sha256,
        codex_home,
        max_result_bytes: config.max_frame_bytes - FRAME_OVERHEAD_BUDGET,
    })?);
    let readiness = backend.readiness()?;
    let service = Arc::new(Mutex::new(CodexTransportService::open(
        &replay_store,
        admissions,
        config.max_expiry_skew_ms,
    )?));
    #[cfg(target_os = "linux")]
    let runtime_presence_publisher =
        prepared_presence_publisher.map(|publisher| Arc::new(Mutex::new(publisher)));
    #[cfg(target_os = "linux")]
    if let Some(publisher) = runtime_presence_publisher.as_ref() {
        start_periodic_runtime_presence_publisher(publisher.clone(), backend.clone())?;
    }
    let active_connections = Arc::new(AtomicUsize::new(0));
    eprintln!(
        "codex-connector ready at {} for {} callers using {:?}",
        bound,
        config.callers.len(),
        readiness.auth_mode
    );

    loop {
        let (stream, _) = listener.accept().map_err(CodexDaemonError::Listen)?;
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
        let runtime_presence_publisher = runtime_presence_publisher.clone();
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
                    runtime_presence_publisher.as_deref(),
                    max_frame_bytes,
                    timeout,
                );
            })
            .map_err(CodexDaemonError::Thread)?;
    }
}

#[cfg(target_os = "linux")]
fn prepare_runtime_presence_publisher(
    candidate: SocketAddr,
    config: &CodexDaemonConfig,
) -> Result<Option<crate::idunn_health::RuntimePresencePublisher>, CodexDaemonError> {
    if std::env::var_os(crate::idunn_health::IDUNN_RUNTIME_BUNDLE_ENVIRONMENT).is_none() {
        return Ok(None);
    }
    let capacity = u32::try_from(caller_request_capacity(&config.callers)?)
        .map_err(|_| CodexDaemonError::InvalidConfig("runtime capability capacity"))?;
    let publisher =
        crate::idunn_health::RuntimePresencePublisher::open_from_environment(candidate, capacity)
            .map_err(CodexDaemonError::Health)?;
    Ok(Some(publisher))
}

#[cfg(target_os = "linux")]
fn start_periodic_runtime_presence_publisher(
    publisher: Arc<Mutex<crate::idunn_health::RuntimePresencePublisher>>,
    backend: Arc<CodexProviderBackend>,
) -> Result<(), CodexDaemonError> {
    let (state, detail) = provider_health_observation(&backend);
    publisher
        .lock()
        .map_err(|_| CodexDaemonError::RuntimePresencePoisoned)?
        .publish(state, detail)
        .map_err(CodexDaemonError::Health)?;
    thread::Builder::new()
        .name("codex-connector-health".to_string())
        .spawn(move || {
            loop {
                thread::sleep(Duration::from_secs(10));
                let (state, detail) = provider_health_observation(&backend);
                let publication = publisher
                    .lock()
                    .map_err(|_| anyhow::anyhow!("runtime presence publisher lock was poisoned"))
                    .and_then(|mut publisher| publisher.publish(state, detail));
                if let Err(error) = publication {
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
fn effective_bind_from_environment(configured: SocketAddr) -> Result<SocketAddr, CodexDaemonError> {
    select_effective_bind(
        configured,
        std::env::var(crate::idunn_health::IDUNN_RUNTIME_BUNDLE_ENVIRONMENT).ok(),
        std::env::var(crate::idunn_health::IDUNN_CANDIDATE_BIND_ENVIRONMENT).ok(),
    )
}

#[cfg(target_os = "linux")]
fn effective_runtime_paths_from_environment(
    config: &CodexDaemonConfig,
    managed_state_root: Option<&Path>,
) -> Result<(PathBuf, PathBuf, PathBuf), CodexDaemonError> {
    if std::env::var_os(crate::idunn_health::IDUNN_RUNTIME_BUNDLE_ENVIRONMENT).is_none() {
        if managed_state_root.is_some() {
            return Err(CodexDaemonError::InvalidConfig(
                "Idunn state root outside a managed launch",
            ));
        }
        return Ok((
            config.codex_executable.clone(),
            config.codex_home.clone(),
            config.replay_store.clone(),
        ));
    }
    let managed_state_root =
        managed_state_root.ok_or(CodexDaemonError::InvalidConfig("missing Idunn state root"))?;

    let running = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|_| CodexDaemonError::InvalidConfig("managed Connector executable"))?;
    managed_runtime_paths(config, &running, managed_state_root)
}

#[cfg(target_os = "linux")]
fn managed_runtime_paths(
    config: &CodexDaemonConfig,
    running: &Path,
    state_root: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf), CodexDaemonError> {
    let adjacent_codex = running
        .parent()
        .ok_or(CodexDaemonError::InvalidConfig(
            "managed Connector executable",
        ))?
        .join("codex");
    let adjacent_codex = fs::canonicalize(adjacent_codex)
        .map_err(|_| CodexDaemonError::InvalidConfig("managed Codex executable"))?;
    let configured_codex = fs::canonicalize(&config.codex_executable)
        .map_err(|_| CodexDaemonError::InvalidConfig("managed Codex executable"))?;
    if configured_codex != adjacent_codex {
        return Err(CodexDaemonError::InvalidConfig("managed Codex executable"));
    }

    if !state_root.is_absolute() {
        return Err(CodexDaemonError::InvalidConfig("managed state root"));
    }
    let canonical_state_root = fs::canonicalize(state_root)
        .map_err(|_| CodexDaemonError::InvalidConfig("managed state root"))?;
    let state_root_metadata = fs::symlink_metadata(state_root)
        .map_err(|_| CodexDaemonError::InvalidConfig("managed state root"))?;
    if canonical_state_root != state_root
        || !state_root_metadata.is_dir()
        || state_root_metadata.file_type().is_symlink()
    {
        return Err(CodexDaemonError::InvalidConfig("managed state root"));
    }

    let codex_home = state_root.join("codex-home");
    if config.codex_home != codex_home {
        return Err(CodexDaemonError::InvalidConfig("managed state layout"));
    }
    match fs::symlink_metadata(&codex_home) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(CodexDaemonError::InvalidConfig("managed state layout")),
    }

    let replay_store = state_root.join("replay.cc");
    if config.replay_store != replay_store {
        return Err(CodexDaemonError::InvalidConfig("managed state layout"));
    }
    match fs::symlink_metadata(&replay_store) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.nlink() == 1 => {}
        Ok(_) => return Err(CodexDaemonError::InvalidConfig("managed state layout")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(CodexDaemonError::InvalidConfig("managed state layout")),
    }
    Ok((adjacent_codex, codex_home, replay_store))
}

#[cfg(target_os = "linux")]
fn select_effective_bind(
    configured: SocketAddr,
    runtime_bundle: Option<String>,
    candidate_bind: Option<String>,
) -> Result<SocketAddr, CodexDaemonError> {
    match (runtime_bundle, candidate_bind) {
        (None, None) => Ok(configured),
        (Some(bundle), Some(candidate))
            if !bundle.trim().is_empty()
                && bundle.trim() == bundle
                && candidate.trim() == candidate =>
        {
            let bind = candidate
                .parse::<SocketAddr>()
                .map_err(|_| CodexDaemonError::InvalidConfig("Idunn candidate bind"))?;
            if !bind.ip().is_loopback() {
                return Err(CodexDaemonError::InvalidConfig("Idunn candidate bind"));
            }
            Ok(bind)
        }
        _ => Err(CodexDaemonError::InvalidConfig(
            "partial Idunn managed runtime environment",
        )),
    }
}

fn load_admissions(
    config: &CodexDaemonConfig,
) -> Result<Vec<CodexCallerAdmission>, CodexDaemonError> {
    let mut admissions = Vec::with_capacity(config.callers.len());
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
    }
    Ok(admissions)
}

fn serve_connection(
    mut stream: TcpStream,
    service: &Mutex<CodexTransportService>,
    backend: &CodexProviderBackend,
    #[cfg(target_os = "linux")] runtime_presence_publisher: Option<
        &Mutex<crate::idunn_health::RuntimePresencePublisher>,
    >,
    max_frame_bytes: usize,
    timeout: Duration,
) -> Result<(), CodexDaemonError> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(CodexDaemonError::Connection)?;
    let request = read_transport_frame(&mut stream, max_frame_bytes).map_err(frame_error)?;
    #[cfg(target_os = "linux")]
    let response = dispatch_native_frame(
        &request,
        runtime_presence_publisher.is_some(),
        |message_id| {
            let publisher =
                runtime_presence_publisher.ok_or(CodexDaemonError::RouteObservationRefused)?;
            let mut publisher = publisher
                .lock()
                .map_err(|_| CodexDaemonError::RuntimePresencePoisoned)?;
            let backend_ready = backend.readiness().is_ok();
            let response = publisher
                .route_observation(message_id, backend_ready)
                .map_err(CodexDaemonError::Health)?;
            encode_cultnet_message_to_vec(&response, CultNetWireContract::CultNetSchemaV0)
                .map_err(|_| CodexDaemonError::FrameEncoding)
        },
        |request| execute_inference_frame(request, service, backend),
    )?;
    #[cfg(not(target_os = "linux"))]
    let response = execute_inference_frame(&request, service, backend)?;
    write_transport_frame(&mut stream, &response, max_frame_bytes).map_err(frame_error)
}

fn execute_inference_frame(
    request: &[u8],
    service: &Mutex<CodexTransportService>,
    backend: &CodexProviderBackend,
) -> Result<Vec<u8>, CodexDaemonError> {
    let envelope: CodexTransportEnvelope =
        rmp_serde::from_slice(request).map_err(|_| CodexDaemonError::FrameEncoding)?;
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
    rmp_serde::to_vec(&response).map_err(|_| CodexDaemonError::FrameEncoding)
}

#[cfg(target_os = "linux")]
fn dispatch_native_frame<RouteObservation, Inference>(
    request: &[u8],
    managed: bool,
    route_observation: RouteObservation,
    inference: Inference,
) -> Result<Vec<u8>, CodexDaemonError>
where
    RouteObservation: FnOnce(&str) -> Result<Vec<u8>, CodexDaemonError>,
    Inference: FnOnce(&[u8]) -> Result<Vec<u8>, CodexDaemonError>,
{
    let Ok(message) =
        decode_cultnet_message_from_slice(request, CultNetWireContract::CultNetSchemaV0)
    else {
        return inference(request);
    };
    let CultNetMessage::SnapshotRequest {
        message_id,
        schema_ids,
        record_keys,
    } = message
    else {
        return inference(request);
    };
    let exact_schema = matches!(
        schema_ids.as_deref(),
        Some([schema_id]) if schema_id == GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA
    );
    let exact_record = matches!(
        record_keys.as_deref(),
        Some([record_key]) if record_key == crate::idunn_health::CONNECTOR_TARGET
    );
    if !managed || !exact_schema || !exact_record {
        return Err(CodexDaemonError::RouteObservationRefused);
    }
    route_observation(&message_id)
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
    #[error("connector runtime presence failed: {0}")]
    Health(#[source] anyhow::Error),
    #[cfg(target_os = "linux")]
    #[error("connector health thread could not start")]
    HealthThread(#[source] std::io::Error),
    #[cfg(target_os = "linux")]
    #[error("connector runtime presence publisher lock was poisoned")]
    RuntimePresencePoisoned,
    #[cfg(target_os = "linux")]
    #[error("connector route observation request was refused")]
    RouteObservationRefused,
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
    #[cfg(target_os = "linux")]
    use std::cell::Cell;
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
    #[cfg(target_os = "linux")]
    fn exact_managed_route_probe_bypasses_inference_execution() {
        let request = encode_cultnet_message_to_vec(
            &CultNetMessage::SnapshotRequest {
                message_id: "route-challenge-17".into(),
                schema_ids: Some(vec![GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA.into()]),
                record_keys: Some(vec![crate::idunn_health::CONNECTOR_TARGET.into()]),
            },
            CultNetWireContract::CultNetSchemaV0,
        )
        .unwrap();
        let inference_calls = Cell::new(0);
        let route_calls = Cell::new(0);

        let response = dispatch_native_frame(
            &request,
            true,
            |message_id| {
                route_calls.set(route_calls.get() + 1);
                assert_eq!(message_id, "route-challenge-17");
                Ok(b"signed-route-observation".to_vec())
            },
            |_| {
                inference_calls.set(inference_calls.get() + 1);
                Ok(b"provider-response".to_vec())
            },
        )
        .unwrap();

        assert_eq!(response, b"signed-route-observation");
        assert_eq!(route_calls.get(), 1);
        assert_eq!(inference_calls.get(), 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn route_probe_refuses_broad_foreign_and_unmanaged_requests() {
        let requests = [
            (
                CultNetMessage::SnapshotRequest {
                    message_id: "broad".into(),
                    schema_ids: None,
                    record_keys: None,
                },
                true,
            ),
            (
                CultNetMessage::SnapshotRequest {
                    message_id: "foreign-schema".into(),
                    schema_ids: Some(vec!["gamecult.other.v1".into()]),
                    record_keys: Some(vec![crate::idunn_health::CONNECTOR_TARGET.into()]),
                },
                true,
            ),
            (
                CultNetMessage::SnapshotRequest {
                    message_id: "foreign-record".into(),
                    schema_ids: Some(vec![GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA.into()]),
                    record_keys: Some(vec!["other-target".into()]),
                },
                true,
            ),
            (
                CultNetMessage::SnapshotRequest {
                    message_id: "unmanaged".into(),
                    schema_ids: Some(vec![GAMECULT_RUNTIME_PRESENCE_HEALTH_SCHEMA.into()]),
                    record_keys: Some(vec![crate::idunn_health::CONNECTOR_TARGET.into()]),
                },
                false,
            ),
        ];

        for (request, managed) in requests {
            let request =
                encode_cultnet_message_to_vec(&request, CultNetWireContract::CultNetSchemaV0)
                    .unwrap();
            let route_calls = Cell::new(0);
            let inference_calls = Cell::new(0);
            assert!(matches!(
                dispatch_native_frame(
                    &request,
                    managed,
                    |_| {
                        route_calls.set(route_calls.get() + 1);
                        Ok(Vec::new())
                    },
                    |_| {
                        inference_calls.set(inference_calls.get() + 1);
                        Ok(Vec::new())
                    },
                ),
                Err(CodexDaemonError::RouteObservationRefused)
            ));
            assert_eq!(route_calls.get(), 0);
            assert_eq!(inference_calls.get(), 0);
        }
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
        let loaded = load_daemon_config_read_only(&path).unwrap();
        assert_eq!(loaded, expected);

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

        assert!(load_daemon_config_read_only(&path).is_err());
        assert!(!lock_path.exists());
        assert_eq!(fs::read(&path).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn managed_runtime_refuses_a_mutable_config_authority() {
        let root = std::env::temp_dir().join(format!(
            "codex-connector-managed-config-{}-{}",
            std::process::id(),
            unix_ms().unwrap()
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("connector.cc");
        write_daemon_config(&path, &config(&root)).unwrap();

        assert!(crate::idunn_health::require_managed_config_store(&path).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn idunn_candidate_bind_replaces_config_only_for_a_complete_managed_launch() {
        let configured = "127.0.0.1:4103".parse().unwrap();
        let candidate = "127.0.0.1:18831".parse().unwrap();
        assert_eq!(
            select_effective_bind(configured, None, None).unwrap(),
            configured
        );
        assert_eq!(
            select_effective_bind(
                configured,
                Some("/run/idunn/runtime/instance".into()),
                Some("127.0.0.1:18831".into()),
            )
            .unwrap(),
            candidate
        );
        assert!(
            select_effective_bind(configured, Some("/run/idunn/runtime/instance".into()), None,)
                .is_err()
        );
        assert!(
            select_effective_bind(
                configured,
                Some("/run/idunn/runtime/instance".into()),
                Some("0.0.0.0:18831".into()),
            )
            .is_err()
        );
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
    fn provider_capacity_is_caller_execution_capacity_not_listener_capacity() {
        let root = Path::new("/srv/codex-connector");
        let mut config = config(root);
        config.max_connections = 64;
        assert_eq!(caller_request_capacity(&config.callers).unwrap(), 4);
        assert_eq!(required_connection_capacity(&config.callers).unwrap(), 8);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn managed_runtime_uses_the_sealed_adjacent_codex_and_declared_state_layout() {
        let root = std::env::temp_dir().join(format!(
            "codex-connector-layout-{}-{}",
            std::process::id(),
            unix_ms().unwrap()
        ));
        let release = root.join("release");
        let state = root.join("state");
        fs::create_dir_all(release.clone()).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(release.join("codex-connector"), b"connector").unwrap();
        fs::write(release.join("codex"), b"codex").unwrap();
        let mut config = config(&root);
        config.codex_executable = release.join("codex");
        config.codex_home = state.join("codex-home");
        config.replay_store = state.join("replay.cc");

        let (_, codex_home, replay_store) =
            managed_runtime_paths(&config, &release.join("codex-connector"), &state).unwrap();
        assert_eq!(codex_home, state.join("codex-home"));
        assert_eq!(
            replay_store,
            fs::canonicalize(&state).unwrap().join("replay.cc")
        );

        fs::write(&replay_store, b"replay").unwrap();
        let replay_alias = state.join("replay-alias.cc");
        fs::hard_link(&replay_store, &replay_alias).unwrap();
        assert!(managed_runtime_paths(&config, &release.join("codex-connector"), &state).is_err());
        fs::remove_file(&replay_alias).unwrap();
        fs::remove_file(&replay_store).unwrap();
        std::os::unix::fs::symlink(state.join("missing-replay.cc"), &replay_store).unwrap();
        assert!(managed_runtime_paths(&config, &release.join("codex-connector"), &state).is_err());
        fs::remove_file(&replay_store).unwrap();

        config.codex_executable = root.join("other-codex");
        fs::write(&config.codex_executable, b"other").unwrap();
        assert!(managed_runtime_paths(&config, &release.join("codex-connector"), &state).is_err());

        config.codex_executable = release.join("codex");
        let other_state = root.join("other-state");
        fs::create_dir_all(other_state.join("codex-home")).unwrap();
        assert!(
            managed_runtime_paths(&config, &release.join("codex-connector"), &other_state,)
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
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
