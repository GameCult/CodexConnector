use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::CodexTransportEvent;
use crate::CodexTransportEventPayload;
use crate::CodexTransportInvocation;
use crate::CodexTransportOutcome;
use crate::CodexTransportReceipt;
use crate::CodexTransportResult;
use crate::RECEIPT_SCHEMA_ID;
use crate::canonical_responses_body_bytes;

const MAX_APP_SERVER_LINE_BYTES: usize = 1024 * 1024;
const MAX_INTERLEAVED_MESSAGES: usize = 64;
const MAX_SSE_FRAME_BYTES: usize = 2 * 1024 * 1024;
const MAX_STREAM_BYTES: usize = 64 * 1024 * 1024;
const OPENAI_RESPONSES_URL: &str = "https://api.openai.com/v1/responses";
const CHATGPT_RESPONSES_URL: &str = "https://chatgpt.com/backend-api/codex/responses";
const CONNECTOR_ORIGINATOR: &str = "gamecult_codex_connector";
const TRANSPORT_ID: &str = "codex_connector_responses_http_v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexAppServerConfig {
    pub executable: PathBuf,
    pub executable_sha256: [u8; 32],
    pub codex_home: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodexAuthMode {
    ApiKey,
    Chatgpt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexAuthReadiness {
    pub auth_mode: CodexAuthMode,
    pub credential_loaded: bool,
    pub fedramp_routing: bool,
    pub app_server_user_agent: String,
}

pub struct CodexProviderBackend {
    authority: Mutex<CodexAppServerAuthority>,
    http: ureq::Agent,
}

impl CodexProviderBackend {
    pub fn start(config: CodexAppServerConfig) -> Result<Self, CodexProviderBackendError> {
        let http: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_recv_response(Some(Duration::from_secs(30)))
            .timeout_recv_body(Some(Duration::from_secs(300)))
            .max_redirects(0)
            .build()
            .into();
        Ok(Self {
            authority: Mutex::new(CodexAppServerAuthority::spawn(config)?),
            http,
        })
    }

    pub fn readiness(&self) -> Result<CodexAuthReadiness, CodexProviderBackendError> {
        let mut authority = self
            .authority
            .lock()
            .map_err(|_| CodexProviderBackendError::CredentialAuthorityPoisoned)?;
        let credential = authority.read_credential(false)?;
        Ok(credential.redacted(&authority.app_server_user_agent))
    }

    pub fn execute(
        &self,
        invocation: &CodexTransportInvocation,
    ) -> Result<CodexTransportResult, CodexProviderBackendError> {
        let body = canonical_responses_body_bytes(&invocation.request)
            .map_err(|_| CodexProviderBackendError::ProviderRequest)?;
        let (first, user_agent) = {
            let mut authority = self
                .authority
                .lock()
                .map_err(|_| CodexProviderBackendError::CredentialAuthorityPoisoned)?;
            let credential = authority.read_credential(false)?;
            (credential, authority.app_server_user_agent.clone())
        };
        let first_digest = first.auth_file_sha256;
        let response = match send_provider_request(
            &self.http,
            provider_url(first.mode),
            invocation,
            &body,
            &first,
            &user_agent,
        ) {
            Err(ureq::Error::StatusCode(401)) if first.mode == CodexAuthMode::Chatgpt => {
                let (refreshed, user_agent) = {
                    let mut authority = self
                        .authority
                        .lock()
                        .map_err(|_| CodexProviderBackendError::CredentialAuthorityPoisoned)?;
                    let current = authority.read_credential(false)?;
                    let credential = if current.auth_file_sha256 != first_digest {
                        current
                    } else {
                        authority.read_credential(true)?
                    };
                    (credential, authority.app_server_user_agent.clone())
                };
                if refreshed.auth_file_sha256 == first_digest {
                    return Ok(failed_result(
                        invocation,
                        "credential_refresh",
                        "Codex credential refresh did not advance the credential store",
                    ));
                }
                send_provider_request(
                    &self.http,
                    provider_url(refreshed.mode),
                    invocation,
                    &body,
                    &refreshed,
                    &user_agent,
                )
            }
            result => result,
        };
        let response = match response {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(status)) => {
                return Ok(failed_result(
                    invocation,
                    "provider_http_status",
                    &format!("provider returned HTTP {status}"),
                ));
            }
            Err(_) => {
                return Ok(failed_result(
                    invocation,
                    "provider_transport",
                    "provider transport failed",
                ));
            }
        };
        let parsed = match parse_responses_sse(response.into_body().into_reader()) {
            Ok(parsed) => parsed,
            Err(message) => return Ok(failed_result(invocation, "provider_stream", message)),
        };
        let receipt = CodexTransportReceipt {
            schema_id: RECEIPT_SCHEMA_ID.to_string(),
            request_id: invocation.request_id().to_string(),
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            native_request_sha256: invocation.native_request_sha256,
            provider_request_sha256: invocation.provider_request_sha256,
            model: invocation.request.model.clone(),
            transport: TRANSPORT_ID.to_string(),
            outcome: parsed.outcome,
        };
        Ok(CodexTransportResult::transported(
            invocation,
            parsed.events,
            receipt,
        ))
    }
}

fn provider_url(mode: CodexAuthMode) -> &'static str {
    match mode {
        CodexAuthMode::ApiKey => OPENAI_RESPONSES_URL,
        CodexAuthMode::Chatgpt => CHATGPT_RESPONSES_URL,
    }
}

fn send_provider_request(
    http: &ureq::Agent,
    url: &str,
    invocation: &CodexTransportInvocation,
    body: &[u8],
    credential: &CodexCredentialSnapshot,
    user_agent: &str,
) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
    let authorization = Zeroizing::new(format!("Bearer {}", credential.bearer.as_str()));
    let mut request = http
        .post(url)
        .header("authorization", authorization.as_str())
        .header("accept", "text/event-stream")
        .header("content-type", "application/json")
        .header("originator", CONNECTOR_ORIGINATOR)
        .header("user-agent", user_agent)
        .header("session_id", &invocation.request.conversation_id)
        .header("x-client-request-id", invocation.request_id())
        .header("version", env!("CARGO_PKG_VERSION"));
    if let Some(account_id) = &credential.account_id {
        request = request.header("ChatGPT-Account-ID", account_id);
    }
    if credential.is_fedramp {
        request = request.header("X-OpenAI-Fedramp", "true");
    }
    request.send(body)
}

struct ParsedProviderStream {
    events: Vec<CodexTransportEvent>,
    outcome: CodexTransportOutcome,
}

#[derive(Default)]
struct PendingToolCall {
    call_id: Option<String>,
    name: Option<String>,
    arguments: String,
}

struct StreamState {
    events: Vec<CodexTransportEvent>,
    pending_tools: HashMap<String, PendingToolCall>,
    outcome: Option<CodexTransportOutcome>,
}

impl StreamState {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            pending_tools: HashMap::new(),
            outcome: None,
        }
    }

    fn push(&mut self, payload: CodexTransportEventPayload) {
        self.events.push(CodexTransportEvent {
            sequence: self.events.len() as u64,
            payload,
        });
    }

    fn accept_frame(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data == b"[DONE]" {
            return Ok(());
        }
        let event: Value =
            serde_json::from_slice(data).map_err(|_| "provider emitted malformed SSE JSON")?;
        let kind = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or("provider SSE event omitted its type")?;
        match kind {
            "response.output_text.delta" => {
                let text = event
                    .get("delta")
                    .and_then(Value::as_str)
                    .ok_or("provider text delta omitted text")?;
                if !text.is_empty() {
                    self.push(CodexTransportEventPayload::TextDelta {
                        text: text.to_string(),
                    });
                }
            }
            "response.output_item.added" => {
                if let Some(item) = event.get("item") {
                    self.seed_tool(item)?;
                }
            }
            "response.function_call_arguments.delta" => {
                let identity = event
                    .get("item_id")
                    .or_else(|| event.get("call_id"))
                    .and_then(Value::as_str)
                    .ok_or("provider tool delta omitted its identity")?;
                let delta = event
                    .get("delta")
                    .and_then(Value::as_str)
                    .ok_or("provider tool delta omitted arguments")?;
                let pending = self.pending_tools.entry(identity.to_string()).or_default();
                if pending.call_id.is_none() {
                    pending.call_id = event
                        .get("call_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                }
                pending.arguments.push_str(delta);
            }
            "response.output_item.done" => {
                if let Some(item) = event.get("item") {
                    self.finish_tool(item)?;
                }
            }
            "response.completed" => self.complete(event.get("response"))?,
            "response.failed" => {
                self.outcome = Some(CodexTransportOutcome::Failed {
                    failure_kind: "response_failed".to_string(),
                    message: "provider declared response.failed".to_string(),
                });
            }
            "response.incomplete" => {
                self.outcome = Some(CodexTransportOutcome::Failed {
                    failure_kind: "response_incomplete".to_string(),
                    message: "provider declared response.incomplete".to_string(),
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn seed_tool(&mut self, item: &Value) -> Result<(), &'static str> {
        if item.get("type").and_then(Value::as_str) != Some("function_call") {
            return Ok(());
        }
        let identity = item_identity(item).ok_or("provider tool item omitted its identity")?;
        self.pending_tools.insert(
            identity,
            PendingToolCall {
                call_id: item_string(item, "call_id"),
                name: item_string(item, "name"),
                arguments: item_string(item, "arguments").unwrap_or_default(),
            },
        );
        Ok(())
    }

    fn finish_tool(&mut self, item: &Value) -> Result<(), &'static str> {
        if item.get("type").and_then(Value::as_str) != Some("function_call") {
            return Ok(());
        }
        let identity = item_identity(item).ok_or("provider tool item omitted its identity")?;
        let pending = self.pending_tools.remove(&identity).unwrap_or_default();
        let call_id = item_string(item, "call_id")
            .or(pending.call_id)
            .ok_or("provider tool item omitted its call ID")?;
        let name = item_string(item, "name")
            .or(pending.name)
            .ok_or("provider tool item omitted its name")?;
        let arguments = item_string(item, "arguments").unwrap_or(pending.arguments);
        if arguments.is_empty() {
            return Err("provider tool item omitted its arguments");
        }
        self.push(CodexTransportEventPayload::ToolCall {
            call_id,
            name,
            arguments,
        });
        Ok(())
    }

    fn complete(&mut self, response: Option<&Value>) -> Result<(), &'static str> {
        if self.outcome.is_some() {
            return Err("provider emitted more than one terminal event");
        }
        if !self.pending_tools.is_empty() {
            return Err("provider completed with an unfinished tool call");
        }
        let response = response.ok_or("provider completion omitted its response")?;
        let response_id = response
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or("provider completion omitted its response ID")?;
        let usage = response.get("usage");
        self.outcome = Some(CodexTransportOutcome::Completed {
            provider_response_id: Some(response_id.to_string()),
            input_tokens: usage
                .and_then(|value| value.get("input_tokens"))
                .and_then(Value::as_u64),
            output_tokens: usage
                .and_then(|value| value.get("output_tokens"))
                .and_then(Value::as_u64),
            reasoning_output_tokens: usage
                .and_then(|value| value.get("output_tokens_details"))
                .and_then(|value| value.get("reasoning_tokens"))
                .and_then(Value::as_u64),
            cached_input_tokens: usage
                .and_then(|value| value.get("input_tokens_details"))
                .and_then(|value| value.get("cached_tokens"))
                .and_then(Value::as_u64),
        });
        Ok(())
    }
}

fn item_identity(item: &Value) -> Option<String> {
    item_string(item, "id").or_else(|| item_string(item, "call_id"))
}

fn item_string(item: &Value, field: &str) -> Option<String> {
    item.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn parse_responses_sse(reader: impl Read) -> Result<ParsedProviderStream, &'static str> {
    let mut reader = BufReader::new(reader);
    let mut state = StreamState::new();
    let mut data = Vec::new();
    let mut total_bytes = 0_usize;
    loop {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take((MAX_SSE_FRAME_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| "provider SSE read failed")?;
        if read == 0 {
            if !data.is_empty() {
                state.accept_frame(&data)?;
            }
            break;
        }
        total_bytes = total_bytes
            .checked_add(read)
            .filter(|total| *total <= MAX_STREAM_BYTES)
            .ok_or("provider stream exceeded its byte bound")?;
        if line.len() > MAX_SSE_FRAME_BYTES {
            return Err("provider SSE frame exceeded its byte bound");
        }
        let line = line.strip_suffix(b"\n").unwrap_or(&line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            if !data.is_empty() {
                state.accept_frame(&data)?;
                data.clear();
                if state.outcome.is_some() {
                    break;
                }
            }
        } else if let Some(fragment) = line.strip_prefix(b"data:") {
            let fragment = fragment.strip_prefix(b" ").unwrap_or(fragment);
            if !data.is_empty() {
                data.push(b'\n');
            }
            data.extend_from_slice(fragment);
            if data.len() > MAX_SSE_FRAME_BYTES {
                return Err("provider SSE frame exceeded its byte bound");
            }
        }
    }
    let outcome = state
        .outcome
        .ok_or("provider stream closed without a terminal event")?;
    Ok(ParsedProviderStream {
        events: state.events,
        outcome,
    })
}

fn failed_result(
    invocation: &CodexTransportInvocation,
    failure_kind: &str,
    message: &str,
) -> CodexTransportResult {
    CodexTransportResult::transported(
        invocation,
        Vec::new(),
        CodexTransportReceipt {
            schema_id: RECEIPT_SCHEMA_ID.to_string(),
            request_id: invocation.request_id().to_string(),
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            native_request_sha256: invocation.native_request_sha256,
            provider_request_sha256: invocation.provider_request_sha256,
            model: invocation.request.model.clone(),
            transport: TRANSPORT_ID.to_string(),
            outcome: CodexTransportOutcome::Failed {
                failure_kind: failure_kind.to_string(),
                message: message.to_string(),
            },
        },
    )
}

struct CodexAppServerAuthority {
    child: Child,
    rpc: AppServerRpc<BufReader<ChildStdout>, ChildStdin>,
    codex_home: PathBuf,
    app_server_user_agent: String,
}

impl CodexAppServerAuthority {
    fn spawn(config: CodexAppServerConfig) -> Result<Self, CodexProviderBackendError> {
        if config.executable_sha256 == [0; 32] {
            return Err(CodexProviderBackendError::InvalidConfiguration(
                "executable_sha256",
            ));
        }
        let executable = canonical_file(&config.executable)?;
        let observed_sha256 = sha256_file(&executable)?;
        if observed_sha256 != config.executable_sha256 {
            return Err(CodexProviderBackendError::ExecutableDigest);
        }
        let expected_home = canonical_directory(&config.codex_home)?;

        let mut command = Command::new(executable);
        command
            .arg("app-server")
            .arg("--listen")
            .arg("stdio://")
            .current_dir(&expected_home)
            .env("CODEX_HOME", &expected_home)
            .env("CODEX_APP_SERVER_DISABLE_MANAGED_CONFIG", "1")
            .env("RUST_LOG", "warn")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = command.spawn().map_err(CodexProviderBackendError::Spawn)?;
        let stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                terminate_child(&mut child);
                return Err(CodexProviderBackendError::MissingChildPipe("stdin"));
            }
        };
        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                terminate_child(&mut child);
                return Err(CodexProviderBackendError::MissingChildPipe("stdout"));
            }
        };
        let mut rpc = AppServerRpc::new(BufReader::new(stdout), stdin);
        let initialized = match rpc.initialize() {
            Ok(initialized) => initialized,
            Err(error) => {
                terminate_child(&mut child);
                return Err(error);
            }
        };
        let reported_home = match canonical_directory(Path::new(&initialized.codex_home)) {
            Ok(home) => home,
            Err(error) => {
                terminate_child(&mut child);
                return Err(error);
            }
        };
        if reported_home != expected_home {
            terminate_child(&mut child);
            return Err(CodexProviderBackendError::CodexHomeIdentity);
        }

        Ok(Self {
            child,
            rpc,
            codex_home: expected_home,
            app_server_user_agent: initialized.user_agent,
        })
    }

    fn read_credential(
        &mut self,
        refresh_token: bool,
    ) -> Result<CodexCredentialSnapshot, CodexProviderBackendError> {
        let account = self.rpc.read_account(refresh_token)?;
        let auth_bytes = std::fs::read(self.codex_home.join("auth.json"))
            .map_err(CodexProviderBackendError::AuthFile)?;
        parse_auth_file(&auth_bytes, account)
    }
}

impl Drop for CodexAppServerAuthority {
    fn drop(&mut self) {
        terminate_child(&mut self.child);
    }
}

struct AppServerRpc<R, W> {
    reader: R,
    writer: W,
    next_request_id: i64,
}

impl<R: BufRead, W: Write> AppServerRpc<R, W> {
    fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            next_request_id: 0,
        }
    }

    fn initialize(&mut self) -> Result<AppServerInitialization, CodexProviderBackendError> {
        let result = self.request(
            "initialize",
            json!({
                "clientInfo": {
                    "name": "gamecult_codex_connector",
                    "title": "GameCult CodexConnector",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        )?;
        self.notify("initialized")?;
        serde_json::from_value(result).map_err(|_| CodexProviderBackendError::AppServerProtocol)
    }

    fn read_account(
        &mut self,
        refresh_token: bool,
    ) -> Result<AppServerAccount, CodexProviderBackendError> {
        let result = self.request("account/read", json!({ "refreshToken": refresh_token }))?;
        let response: AppServerAccountResponse = serde_json::from_value(result)
            .map_err(|_| CodexProviderBackendError::AppServerProtocol)?;
        if !response.requires_openai_auth {
            return Err(CodexProviderBackendError::AuthNotRequired);
        }
        response
            .account
            .ok_or(CodexProviderBackendError::CredentialUnavailable)
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, CodexProviderBackendError> {
        let request_id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(CodexProviderBackendError::AppServerProtocol)?;
        write_json_line(
            &mut self.writer,
            &json!({ "id": request_id, "method": method, "params": params }),
        )?;

        for _ in 0..MAX_INTERLEAVED_MESSAGES {
            let message = read_json_line(&mut self.reader)?;
            match message.get("id").and_then(Value::as_i64) {
                Some(id) if id == request_id => {
                    if let Some(result) = message.get("result") {
                        return Ok(result.clone());
                    }
                    if message.get("error").is_some() {
                        return Err(CodexProviderBackendError::AppServerRejected);
                    }
                    return Err(CodexProviderBackendError::AppServerProtocol);
                }
                Some(_) => return Err(CodexProviderBackendError::AppServerProtocol),
                None if message.get("method").and_then(Value::as_str).is_some() => continue,
                None => return Err(CodexProviderBackendError::AppServerProtocol),
            }
        }
        Err(CodexProviderBackendError::AppServerProtocol)
    }

    fn notify(&mut self, method: &str) -> Result<(), CodexProviderBackendError> {
        write_json_line(&mut self.writer, &json!({ "method": method }))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppServerInitialization {
    user_agent: String,
    codex_home: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
enum AppServerAccount {
    #[serde(rename = "apiKey")]
    ApiKey,
    #[serde(rename = "chatgpt")]
    Chatgpt,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppServerAccountResponse {
    account: Option<AppServerAccount>,
    requires_openai_auth: bool,
}

struct CodexCredentialSnapshot {
    mode: CodexAuthMode,
    bearer: Zeroizing<String>,
    account_id: Option<String>,
    is_fedramp: bool,
    auth_file_sha256: [u8; 32],
}

impl CodexCredentialSnapshot {
    fn redacted(&self, app_server_user_agent: &str) -> CodexAuthReadiness {
        CodexAuthReadiness {
            auth_mode: self.mode,
            credential_loaded: !self.bearer.is_empty(),
            fedramp_routing: self.is_fedramp,
            app_server_user_agent: app_server_user_agent.to_string(),
        }
    }
}

#[derive(Deserialize)]
struct AuthFile {
    auth_mode: String,
    #[serde(rename = "OPENAI_API_KEY")]
    openai_api_key: Option<String>,
    tokens: Option<AuthTokens>,
}

#[derive(Deserialize)]
struct AuthTokens {
    id_token: String,
    access_token: String,
    account_id: Option<String>,
}

fn parse_auth_file(
    bytes: &[u8],
    account: AppServerAccount,
) -> Result<CodexCredentialSnapshot, CodexProviderBackendError> {
    let auth_file_sha256 = Sha256::digest(bytes).into();
    let auth: AuthFile =
        serde_json::from_slice(bytes).map_err(|_| CodexProviderBackendError::AuthFileShape)?;
    match (auth.auth_mode.as_str(), account) {
        ("apikey", AppServerAccount::ApiKey) => {
            let bearer = required_secret(auth.openai_api_key)?;
            Ok(CodexCredentialSnapshot {
                mode: CodexAuthMode::ApiKey,
                bearer,
                account_id: None,
                is_fedramp: false,
                auth_file_sha256,
            })
        }
        ("chatgpt", AppServerAccount::Chatgpt) => {
            let tokens = auth
                .tokens
                .ok_or(CodexProviderBackendError::CredentialUnavailable)?;
            let bearer = required_secret(Some(tokens.access_token))?;
            let claims = parse_id_token_claims(&tokens.id_token)?;
            let account_id = tokens
                .account_id
                .or(claims.account_id)
                .filter(|value| !value.trim().is_empty() && value.trim() == value)
                .ok_or(CodexProviderBackendError::AccountIdentity)?;
            Ok(CodexCredentialSnapshot {
                mode: CodexAuthMode::Chatgpt,
                bearer,
                account_id: Some(account_id),
                is_fedramp: claims.is_fedramp,
                auth_file_sha256,
            })
        }
        ("chatgptAuthTokens" | "agentIdentity", _) => {
            Err(CodexProviderBackendError::UnsupportedAuthMode)
        }
        _ => Err(CodexProviderBackendError::AuthModeSubstitution),
    }
}

fn required_secret(value: Option<String>) -> Result<Zeroizing<String>, CodexProviderBackendError> {
    let value = value.ok_or(CodexProviderBackendError::CredentialUnavailable)?;
    if value.trim().is_empty() || value.trim() != value {
        return Err(CodexProviderBackendError::CredentialUnavailable);
    }
    Ok(Zeroizing::new(value))
}

struct IdTokenClaims {
    account_id: Option<String>,
    is_fedramp: bool,
}

fn parse_id_token_claims(token: &str) -> Result<IdTokenClaims, CodexProviderBackendError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(CodexProviderBackendError::IdTokenShape);
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(CodexProviderBackendError::IdTokenShape);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| CodexProviderBackendError::IdTokenShape)?;
    let claims: Value =
        serde_json::from_slice(&decoded).map_err(|_| CodexProviderBackendError::IdTokenShape)?;
    let auth = claims
        .get("https://api.openai.com/auth")
        .and_then(Value::as_object);
    Ok(IdTokenClaims {
        account_id: auth
            .and_then(|value| value.get("chatgpt_account_id"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        is_fedramp: auth
            .and_then(|value| value.get("chatgpt_account_is_fedramp"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn write_json_line(
    writer: &mut impl Write,
    value: &Value,
) -> Result<(), CodexProviderBackendError> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|_| CodexProviderBackendError::AppServerProtocol)?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(CodexProviderBackendError::AppServerIo)
}

fn read_json_line(reader: &mut impl BufRead) -> Result<Value, CodexProviderBackendError> {
    let mut line = Vec::new();
    let read = reader
        .take((MAX_APP_SERVER_LINE_BYTES + 1) as u64)
        .read_until(b'\n', &mut line)
        .map_err(CodexProviderBackendError::AppServerIo)?;
    if read == 0 || line.len() > MAX_APP_SERVER_LINE_BYTES {
        return Err(CodexProviderBackendError::AppServerProtocol);
    }
    serde_json::from_slice(&line).map_err(|_| CodexProviderBackendError::AppServerProtocol)
}

fn canonical_directory(path: &Path) -> Result<PathBuf, CodexProviderBackendError> {
    let canonical = path
        .canonicalize()
        .map_err(CodexProviderBackendError::CodexHome)?;
    if !canonical.is_dir() {
        return Err(CodexProviderBackendError::InvalidConfiguration(
            "codex_home",
        ));
    }
    Ok(canonical)
}

fn canonical_file(path: &Path) -> Result<PathBuf, CodexProviderBackendError> {
    let canonical = path
        .canonicalize()
        .map_err(CodexProviderBackendError::Executable)?;
    if !canonical.is_file() {
        return Err(CodexProviderBackendError::InvalidConfiguration(
            "executable",
        ));
    }
    Ok(canonical)
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn sha256_file(path: &Path) -> Result<[u8; 32], CodexProviderBackendError> {
    let mut file = File::open(path).map_err(CodexProviderBackendError::Executable)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(CodexProviderBackendError::Executable)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

#[derive(Debug, Error)]
pub enum CodexProviderBackendError {
    #[error("invalid connector configuration field {0}")]
    InvalidConfiguration(&'static str),
    #[error("failed to read pinned Codex executable")]
    Executable(#[source] io::Error),
    #[error("pinned Codex executable digest mismatch")]
    ExecutableDigest,
    #[error("failed to start pinned Codex app-server")]
    Spawn(#[source] io::Error),
    #[error("pinned Codex app-server did not expose {0}")]
    MissingChildPipe(&'static str),
    #[error("Codex home is unavailable")]
    CodexHome(#[source] io::Error),
    #[error("pinned Codex app-server reported a different Codex home")]
    CodexHomeIdentity,
    #[error("Codex app-server protocol failed")]
    AppServerProtocol,
    #[error("Codex app-server IO failed")]
    AppServerIo(#[source] io::Error),
    #[error("Codex app-server refused the authentication request")]
    AppServerRejected,
    #[error("Codex app-server reports that OpenAI authentication is disabled")]
    AuthNotRequired,
    #[error("Codex credential file is unavailable")]
    AuthFile(#[source] io::Error),
    #[error("Codex credential file has an unexpected shape")]
    AuthFileShape,
    #[error("Codex credential is unavailable")]
    CredentialUnavailable,
    #[error("Codex credential mode disagrees with app-server")]
    AuthModeSubstitution,
    #[error("Codex credential mode is not admitted")]
    UnsupportedAuthMode,
    #[error("ChatGPT account identity is unavailable")]
    AccountIdentity,
    #[error("ChatGPT ID token has an unexpected shape")]
    IdTokenShape,
    #[error("provider request could not be rendered")]
    ProviderRequest,
    #[error("Codex credential authority lock was poisoned")]
    CredentialAuthorityPoisoned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn jwt(payload: Value) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        format!("e30.{payload}.signature")
    }

    #[test]
    fn app_server_rpc_uses_only_initialize_and_account_read() {
        let input = concat!(
            "{\"id\":0,\"result\":{\"userAgent\":\"codex/1.2.3\",\"codexHome\":\"C:/codex\"}}\n",
            "{\"method\":\"account/updated\",\"params\":{}}\n",
            "{\"id\":1,\"result\":{\"account\":{\"type\":\"apiKey\"},\"requiresOpenaiAuth\":true}}\n"
        );
        let reader = BufReader::new(io::Cursor::new(input.as_bytes()));
        let mut written = Vec::new();
        let mut rpc = AppServerRpc::new(reader, &mut written);

        let initialized = rpc.initialize().unwrap();
        assert_eq!(initialized.user_agent, "codex/1.2.3");
        assert_eq!(rpc.read_account(false).unwrap(), AppServerAccount::ApiKey);
        drop(rpc);

        let messages = String::from_utf8(written)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["method"], "initialize");
        assert_eq!(messages[1], json!({"method": "initialized"}));
        assert_eq!(
            messages[2],
            json!({"id": 1, "method": "account/read", "params": {"refreshToken": false}})
        );
        assert!(messages.iter().all(|message| {
            let text = message.to_string();
            !text.contains("prompt") && !text.contains("tool") && !text.contains("model")
        }));
    }

    #[test]
    fn api_key_readiness_exposes_no_credential_identity() {
        let bytes = br#"{
            "auth_mode":"apikey",
            "OPENAI_API_KEY":"secret-api-key",
            "tokens":null
        }"#;
        let credential = parse_auth_file(bytes, AppServerAccount::ApiKey).unwrap();
        let readiness = credential.redacted("codex/1.2.3");
        assert_eq!(readiness.auth_mode, CodexAuthMode::ApiKey);
        assert!(readiness.credential_loaded);
        assert!(!readiness.fedramp_routing);
        assert_eq!(readiness.app_server_user_agent, "codex/1.2.3");
        assert!(!format!("{readiness:?}").contains("secret-api-key"));
    }

    #[test]
    fn chatgpt_readiness_derives_account_and_fedramp_without_exposing_tokens() {
        let id_token = jwt(json!({
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "workspace-7",
                "chatgpt_account_is_fedramp": true
            }
        }));
        let bytes = serde_json::to_vec(&json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": id_token,
                "access_token": "secret-access-token",
                "refresh_token": "secret-refresh-token",
                "account_id": null
            }
        }))
        .unwrap();
        let credential = parse_auth_file(&bytes, AppServerAccount::Chatgpt).unwrap();
        assert!(credential.is_fedramp);
        let readiness = credential.redacted("codex/1.2.3");
        assert_eq!(readiness.auth_mode, CodexAuthMode::Chatgpt);
        assert!(readiness.credential_loaded);
        assert!(readiness.fedramp_routing);
        let debug = format!("{readiness:?}");
        assert!(!debug.contains("secret-access-token"));
        assert!(!debug.contains("secret-refresh-token"));
        assert!(!debug.contains("workspace-7"));
    }

    #[test]
    fn app_server_and_auth_file_mode_must_match() {
        let bytes = br#"{
            "auth_mode":"apikey",
            "OPENAI_API_KEY":"secret-api-key",
            "tokens":null
        }"#;
        assert!(matches!(
            parse_auth_file(bytes, AppServerAccount::Chatgpt),
            Err(CodexProviderBackendError::AuthModeSubstitution)
        ));
    }

    #[test]
    fn responses_stream_preserves_text_tool_and_usage_consequences() {
        let stream = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"answer\"}\n\n",
            "data: {\"type\":\"response.output_item.added\",\"item\":{\"id\":\"fc-1\",\"type\":\"function_call\",\"call_id\":\"call-1\",\"name\":\"read_source\",\"arguments\":\"\"}}\n\n",
            "data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc-1\",\"call_id\":\"call-1\",\"delta\":\"{\\\"path\\\":\"}\n\n",
            "data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc-1\",\"call_id\":\"call-1\",\"delta\":\"\\\"README.md\\\"}\"}\n\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"id\":\"fc-1\",\"type\":\"function_call\",\"call_id\":\"call-1\",\"name\":\"read_source\"}}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-1\",\"usage\":{\"input_tokens\":11,\"input_tokens_details\":{\"cached_tokens\":3},\"output_tokens\":7,\"output_tokens_details\":{\"reasoning_tokens\":2}}}}\n\n"
        );
        let parsed = parse_responses_sse(stream.as_bytes()).unwrap();
        assert_eq!(
            parsed.events,
            vec![
                CodexTransportEvent {
                    sequence: 0,
                    payload: CodexTransportEventPayload::TextDelta {
                        text: "answer".to_string()
                    }
                },
                CodexTransportEvent {
                    sequence: 1,
                    payload: CodexTransportEventPayload::ToolCall {
                        call_id: "call-1".to_string(),
                        name: "read_source".to_string(),
                        arguments: "{\"path\":\"README.md\"}".to_string()
                    }
                }
            ]
        );
        assert_eq!(
            parsed.outcome,
            CodexTransportOutcome::Completed {
                provider_response_id: Some("resp-1".to_string()),
                input_tokens: Some(11),
                output_tokens: Some(7),
                reasoning_output_tokens: Some(2),
                cached_input_tokens: Some(3),
            }
        );
    }

    #[test]
    fn responses_stream_refuses_terminality_with_an_unfinished_tool() {
        let stream = concat!(
            "data: {\"type\":\"response.output_item.added\",\"item\":{\"id\":\"fc-1\",\"type\":\"function_call\",\"call_id\":\"call-1\",\"name\":\"read_source\",\"arguments\":\"\"}}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-1\"}}\n\n"
        );
        assert_eq!(
            parse_responses_sse(stream.as_bytes()).err(),
            Some("provider completed with an unfinished tool call")
        );
    }

    #[test]
    fn provider_http_transmits_exact_body_and_required_identity_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut received = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = socket.read(&mut buffer).unwrap();
                assert!(read > 0);
                received.extend_from_slice(&buffer[..read]);
                let Some(headers_end) = received.windows(4).position(|part| part == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&received[..headers_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap();
                if received.len() >= headers_end + 4 + content_length {
                    break;
                }
            }
            let response_body = concat!(
                "data: {\"type\":\"response.completed\",",
                "\"response\":{\"id\":\"resp-local\"}}\n\n"
            );
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            )
            .unwrap();
            received
        });

        let mut request = crate::CodexProviderRequest::new(
            "request-http",
            "conversation-http",
            "gpt-test",
            "Return a result.",
        );
        request.input.push(crate::CodexInputItem::UserText {
            text: "projected state".to_string(),
        });
        let invocation =
            CodexTransportInvocation::new("caller-http", 2_000, [9; 32], request).unwrap();
        let expected_body = canonical_responses_body_bytes(&invocation.request).unwrap();
        let credential = CodexCredentialSnapshot {
            mode: CodexAuthMode::ApiKey,
            bearer: Zeroizing::new("secret-http-token".to_string()),
            account_id: None,
            is_fedramp: false,
            auth_file_sha256: [7; 32],
        };
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .max_redirects(0)
            .build()
            .into();
        let response = send_provider_request(
            &agent,
            &format!("http://{address}/v1/responses"),
            &invocation,
            &expected_body,
            &credential,
            "codex/test",
        )
        .unwrap();
        let parsed = parse_responses_sse(response.into_body().into_reader()).unwrap();
        assert!(matches!(
            parsed.outcome,
            CodexTransportOutcome::Completed {
                provider_response_id: Some(ref id),
                ..
            } if id == "resp-local"
        ));

        let received = server.join().unwrap();
        let headers_end = received
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap();
        let headers = String::from_utf8_lossy(&received[..headers_end]).to_ascii_lowercase();
        assert!(headers.contains("authorization: bearer secret-http-token"));
        assert!(headers.contains("originator: gamecult_codex_connector"));
        assert!(headers.contains("session_id: conversation-http"));
        assert!(headers.contains("x-client-request-id: request-http"));
        assert_eq!(&received[headers_end + 4..], expected_body);
    }
}
