use std::ffi::OsString;
use std::path::PathBuf;

use codex_connector::{CodexCallerConfig, CodexDaemonConfig};

const USAGE: &str = "usage:\n  codex-connector --config PATH.cc\n  codex-connector --initialize-single-caller-config PATH.cc BIND CODEX_EXECUTABLE CODEX_SHA256 CODEX_HOME REPLAY_STORE CALLER_RUNTIME_ID CONNECTION_KEY_FILE CONNECTION_KEY_EPOCH ALLOWED_MODEL MAX_CONCURRENT_REQUESTS MAX_PAYLOAD_BYTES MAX_OUTPUT_TOKENS\n  codex-connector --admit-caller-config SOURCE.cc DESTINATION.cc CALLER_RUNTIME_ID CONNECTION_KEY_FILE CONNECTION_KEY_EPOCH ALLOWED_MODEL MAX_CONCURRENT_REQUESTS MAX_PAYLOAD_BYTES MAX_OUTPUT_TOKENS\n  codex-connector --enroll-provider-health-identity PATH.cc\n  codex-connector --provider-health-public-key PATH.cc";

fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    #[cfg(target_os = "linux")]
    if let [flag, path] = args.as_slice() {
        if flag == "--enroll-provider-health-identity" {
            match codex_connector::enroll_provider_health_identity(&PathBuf::from(path)) {
                Ok(public_key) => println!("{public_key}"),
                Err(error) => {
                    eprintln!("codex-connector health identity enrollment failed: {error}");
                    std::process::exit(2);
                }
            }
            return;
        }
        if flag == "--provider-health-public-key" {
            match codex_connector::provider_health_public_key_hex(&PathBuf::from(path)) {
                Ok(public_key) => println!("{public_key}"),
                Err(error) => {
                    eprintln!("codex-connector health identity read failed: {error}");
                    std::process::exit(2);
                }
            }
            return;
        }
    }
    if args
        .first()
        .is_some_and(|value| value == "--initialize-single-caller-config")
    {
        if let Err(error) = initialize_single_caller_config(&args[1..]) {
            eprintln!("codex-connector config initialization failed: {error}");
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
        return;
    }
    if args
        .first()
        .is_some_and(|value| value == "--admit-caller-config")
    {
        if let Err(error) = admit_caller_config(&args[1..]) {
            eprintln!("codex-connector caller admission failed: {error}");
            std::process::exit(2);
        }
        return;
    }
    let config = match args.as_slice() {
        [flag, path] if flag == "--config" => PathBuf::from(path),
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(error) = codex_connector::serve(&config) {
        eprintln!("codex-connector stopped: {error}");
        std::process::exit(1);
    }
}

fn admit_caller_config(args: &[OsString]) -> Result<(), String> {
    let [
        source,
        destination,
        caller_runtime_id,
        connection_key_file,
        connection_key_epoch,
        allowed_model,
        max_concurrent_requests,
        max_payload_bytes,
        max_output_tokens,
    ] = args
    else {
        return Err("expected exactly nine caller-admission values".to_string());
    };
    let mut config = codex_connector::load_daemon_config(&PathBuf::from(source))
        .map_err(|error| error.to_string())?;
    let caller_runtime_id = os_text(caller_runtime_id, "caller runtime")?;
    let caller = CodexCallerConfig {
        caller_runtime_id,
        connection_key_file: PathBuf::from(connection_key_file),
        connection_key_epoch: parse_number(connection_key_epoch, "connection key epoch")?,
        allowed_models: vec![os_text(allowed_model, "allowed model")?],
        max_concurrent_requests: parse_number(max_concurrent_requests, "max concurrent requests")?,
        max_payload_bytes: parse_number(max_payload_bytes, "max payload bytes")?,
        max_output_tokens: parse_number(max_output_tokens, "max output tokens")?,
    };
    config
        .admit_caller(caller)
        .map_err(|error| error.to_string())?;
    codex_connector::write_daemon_config(&PathBuf::from(destination), &config)
        .map_err(|error| error.to_string())
}

fn initialize_single_caller_config(args: &[OsString]) -> Result<(), String> {
    let [
        path,
        bind,
        executable,
        executable_sha256,
        codex_home,
        replay_store,
        caller_runtime_id,
        connection_key_file,
        connection_key_epoch,
        allowed_model,
        max_concurrent_requests,
        max_payload_bytes,
        max_output_tokens,
    ] = args
    else {
        return Err("expected exactly thirteen configuration values".to_string());
    };
    let config = CodexDaemonConfig::single_caller(
        os_text(bind, "bind")?,
        PathBuf::from(executable),
        parse_sha256(executable_sha256)?,
        PathBuf::from(codex_home),
        PathBuf::from(replay_store),
        CodexCallerConfig {
            caller_runtime_id: os_text(caller_runtime_id, "caller runtime")?,
            connection_key_file: PathBuf::from(connection_key_file),
            connection_key_epoch: parse_number(connection_key_epoch, "connection key epoch")?,
            allowed_models: vec![os_text(allowed_model, "allowed model")?],
            max_concurrent_requests: parse_number(
                max_concurrent_requests,
                "max concurrent requests",
            )?,
            max_payload_bytes: parse_number(max_payload_bytes, "max payload bytes")?,
            max_output_tokens: parse_number(max_output_tokens, "max output tokens")?,
        },
    );
    codex_connector::write_daemon_config(&PathBuf::from(path), &config)
        .map_err(|error| error.to_string())
}

fn os_text(value: &OsString, field: &str) -> Result<String, String> {
    value
        .to_str()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("{field} must be non-empty UTF-8"))
}

fn parse_number<T>(value: &OsString, field: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    os_text(value, field)?
        .parse()
        .map_err(|_| format!("{field} is not a valid integer"))
}

fn parse_sha256(value: &OsString) -> Result<[u8; 32], String> {
    let value = os_text(value, "Codex SHA-256")?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Codex SHA-256 must be exactly 64 hexadecimal characters".to_string());
    }
    let mut digest = [0_u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "Codex SHA-256 is malformed".to_string())?;
    }
    Ok(digest)
}
