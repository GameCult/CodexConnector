use std::collections::HashSet;
#[cfg(feature = "client")]
use std::io::{Read, Write};
#[cfg(feature = "client")]
use std::net::{SocketAddr, TcpStream};
#[cfg(feature = "client")]
use std::time::Duration;

#[cfg(feature = "daemon")]
use std::collections::HashMap;
#[cfg(feature = "daemon")]
use std::path::Path;

#[cfg(feature = "client")]
use aes_gcm::aead::{Aead, Payload};
#[cfg(feature = "client")]
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
#[cfg(feature = "daemon")]
use cultcache_rs::{CultCache, DatabaseEntry, OwnedRedbMessagePackBackingStore};
#[cfg(feature = "client")]
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
#[cfg(feature = "client")]
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "daemon")]
mod daemon;
#[cfg(all(feature = "daemon", target_os = "linux"))]
mod idunn_health;
#[cfg(feature = "daemon")]
mod provider_backend;

#[cfg(feature = "daemon")]
pub use daemon::CodexCallerConfig;
#[cfg(feature = "daemon")]
pub use daemon::CodexDaemonConfig;
#[cfg(feature = "daemon")]
pub use daemon::CodexDaemonError;
#[cfg(feature = "daemon")]
pub use daemon::load_daemon_config;
#[cfg(feature = "daemon")]
pub use daemon::serve;
#[cfg(feature = "daemon")]
pub use daemon::write_daemon_config;
#[cfg(all(feature = "daemon", target_os = "linux"))]
pub use idunn_health::{
    CODEX_CONNECTOR_IDUNN_HEALTH_CONTRACT, ProviderHealthPublisher,
    enroll_provider_health_identity, provider_health_public_key_hex,
};
#[cfg(feature = "daemon")]
pub use provider_backend::CodexAppServerConfig;
#[cfg(feature = "daemon")]
pub use provider_backend::CodexAuthMode;
#[cfg(feature = "daemon")]
pub use provider_backend::CodexAuthReadiness;
#[cfg(feature = "daemon")]
pub use provider_backend::CodexProviderBackend;
#[cfg(feature = "daemon")]
pub use provider_backend::CodexProviderBackendError;

pub const PROVIDER_REQUEST_SCHEMA_ID: &str = "gamecult.codex.provider_request.v2";
pub const INVOCATION_SCHEMA_ID: &str = "gamecult.codex.transport_invocation.v2";
pub const RESULT_SCHEMA_ID: &str = "gamecult.codex.transport_result.v2";
pub const RECEIPT_SCHEMA_ID: &str = "gamecult.codex.transport_receipt.v2";
pub const ENVELOPE_SCHEMA_ID: &str = "gamecult.codex.transport_envelope.v2";

#[cfg(feature = "client")]
#[derive(Clone, PartialEq, Eq)]
pub struct CodexTransportKey([u8; 32]);

#[cfg(feature = "client")]
impl CodexTransportKey {
    pub fn from_connection_secret(secret: &str) -> Result<Self, ServiceError> {
        if secret.trim().is_empty() || secret.trim() != secret {
            return Err(ServiceError::InvalidAdmission);
        }
        Ok(Self(Sha256::digest(secret.as_bytes()).into()))
    }
}

#[cfg(feature = "client")]
impl Drop for CodexTransportKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexProviderRequest {
    pub schema_id: String,
    pub request_id: String,
    pub conversation_id: String,
    pub model: String,
    pub instructions: String,
    pub input: Vec<CodexInputItem>,
    pub reasoning_effort: Option<String>,
    pub reasoning_summary: Option<String>,
    pub service_tier: Option<String>,
    pub output_format_name: Option<String>,
    pub previous_response_id: Option<String>,
    pub tools: Vec<CodexToolDefinition>,
    pub tool_choice: CodexToolChoice,
    pub parallel_tool_calls: bool,
    pub output_schema_json: Option<String>,
    pub max_output_tokens: Option<u32>,
    pub prompt_cache_key: Option<String>,
}

impl CodexProviderRequest {
    pub fn new(
        request_id: impl Into<String>,
        conversation_id: impl Into<String>,
        model: impl Into<String>,
        instructions: impl Into<String>,
    ) -> Self {
        Self {
            schema_id: PROVIDER_REQUEST_SCHEMA_ID.to_string(),
            request_id: request_id.into(),
            conversation_id: conversation_id.into(),
            model: model.into(),
            instructions: instructions.into(),
            input: Vec::new(),
            reasoning_effort: None,
            reasoning_summary: None,
            service_tier: None,
            output_format_name: None,
            previous_response_id: None,
            tools: Vec::new(),
            tool_choice: CodexToolChoice::Auto,
            parallel_tool_calls: false,
            output_schema_json: None,
            max_output_tokens: None,
            prompt_cache_key: None,
        }
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_id != PROVIDER_REQUEST_SCHEMA_ID {
            return Err(ContractError::Schema);
        }
        require_id(&self.request_id, "request_id")?;
        require_id(&self.conversation_id, "conversation_id")?;
        require_id(&self.model, "model")?;
        require_content(&self.instructions, "instructions")?;
        if matches!(self.max_output_tokens, Some(0)) {
            return Err(ContractError::Invalid("max_output_tokens"));
        }
        if self
            .prompt_cache_key
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(ContractError::Invalid("prompt_cache_key"));
        }
        for (value, field) in [
            (self.reasoning_effort.as_deref(), "reasoning_effort"),
            (self.reasoning_summary.as_deref(), "reasoning_summary"),
            (self.service_tier.as_deref(), "service_tier"),
            (self.output_format_name.as_deref(), "output_format_name"),
            (self.previous_response_id.as_deref(), "previous_response_id"),
        ] {
            if let Some(value) = value {
                require_id(value, field)?;
            }
        }
        if let Some(schema) = &self.output_schema_json {
            require_content(schema, "output_schema_json")?;
            require_json_object(schema, "output_schema_json")?;
            require_provider_name(
                self.output_format_name
                    .as_deref()
                    .ok_or(ContractError::Invalid("output_format_name"))?,
                "output_format_name",
            )?;
        } else if self.output_format_name.is_some() {
            return Err(ContractError::Invalid("output_schema_json"));
        }

        if self.tools.is_empty() && self.tool_choice == CodexToolChoice::Required {
            return Err(ContractError::Invalid("tool_choice"));
        }

        let mut tool_names = HashSet::new();
        for tool in &self.tools {
            require_provider_name(&tool.name, "tool.name")?;
            require_content(&tool.description, "tool.description")?;
            require_content(&tool.parameters_json, "tool.parameters_json")?;
            require_json_object(&tool.parameters_json, "tool.parameters_json")?;
            if !tool_names.insert(tool.name.as_str()) {
                return Err(ContractError::DuplicateTool(tool.name.clone()));
            }
        }
        for item in &self.input {
            match item {
                CodexInputItem::UserText { text } | CodexInputItem::AssistantText { text } => {
                    require_content(text, "input.text")?;
                }
                CodexInputItem::ToolCall {
                    call_id,
                    name,
                    arguments,
                } => {
                    require_provider_call_id(call_id, "input.call_id")?;
                    require_provider_name(name, "input.tool_name")?;
                    require_content(arguments, "input.arguments")?;
                }
                CodexInputItem::ToolResult { call_id, output } => {
                    require_provider_call_id(call_id, "input.call_id")?;
                    require_content(output, "input.output")?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexToolChoice {
    Auto,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodexInputItem {
    UserText {
        text: String,
    },
    AssistantText {
        text: String,
    },
    ToolCall {
        call_id: String,
        name: String,
        arguments: String,
    },
    ToolResult {
        call_id: String,
        output: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexTransportInvocation {
    pub schema_id: String,
    pub caller_runtime_id: String,
    pub expires_at_unix_ms: u64,
    pub native_request_sha256: [u8; 32],
    pub provider_request_sha256: [u8; 32],
    pub request: CodexProviderRequest,
}

impl CodexTransportInvocation {
    pub fn new(
        caller_runtime_id: impl Into<String>,
        expires_at_unix_ms: u64,
        native_request_sha256: [u8; 32],
        request: CodexProviderRequest,
    ) -> Result<Self, ContractError> {
        let provider_request_sha256 = provider_request_sha256(&request)?;
        Ok(Self {
            schema_id: INVOCATION_SCHEMA_ID.to_string(),
            caller_runtime_id: caller_runtime_id.into(),
            expires_at_unix_ms,
            native_request_sha256,
            provider_request_sha256,
            request,
        })
    }

    pub fn validate(&self, now_unix_ms: u64, max_expiry_skew_ms: u64) -> Result<(), ContractError> {
        if self.schema_id != INVOCATION_SCHEMA_ID {
            return Err(ContractError::Schema);
        }
        require_id(&self.caller_runtime_id, "caller_runtime_id")?;
        if self.native_request_sha256 == [0; 32] {
            return Err(ContractError::Invalid("native_request_sha256"));
        }
        self.request.validate()?;
        if self.provider_request_sha256 != provider_request_sha256(&self.request)? {
            return Err(ContractError::ProviderDigest);
        }
        if self.expires_at_unix_ms < now_unix_ms
            || self.expires_at_unix_ms > now_unix_ms.saturating_add(max_expiry_skew_ms)
        {
            return Err(ContractError::Expiry);
        }
        Ok(())
    }

    pub fn request_id(&self) -> &str {
        &self.request.request_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexTransportResult {
    pub schema_id: String,
    pub request_id: String,
    pub caller_runtime_id: String,
    pub disposition: CodexTransportDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodexTransportDisposition {
    Refused(CodexRefusal),
    Transported {
        events: Vec<CodexTransportEvent>,
        receipt: Box<CodexTransportReceipt>,
    },
}

impl CodexTransportResult {
    pub fn refused(invocation: &CodexTransportInvocation, reason: CodexRefusal) -> Self {
        Self {
            schema_id: RESULT_SCHEMA_ID.to_string(),
            request_id: invocation.request_id().to_string(),
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            disposition: CodexTransportDisposition::Refused(reason),
        }
    }

    pub fn transported(
        invocation: &CodexTransportInvocation,
        events: Vec<CodexTransportEvent>,
        receipt: CodexTransportReceipt,
    ) -> Self {
        Self {
            schema_id: RESULT_SCHEMA_ID.to_string(),
            request_id: invocation.request_id().to_string(),
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            disposition: CodexTransportDisposition::Transported {
                events,
                receipt: Box::new(receipt),
            },
        }
    }

    pub fn validate_against(
        &self,
        invocation: &CodexTransportInvocation,
    ) -> Result<(), ContractError> {
        if self.schema_id != RESULT_SCHEMA_ID {
            return Err(ContractError::Schema);
        }
        if self.request_id != invocation.request_id()
            || self.caller_runtime_id != invocation.caller_runtime_id
        {
            return Err(ContractError::Identity);
        }

        if let CodexTransportDisposition::Transported { events, receipt } = &self.disposition {
            for (expected, event) in events.iter().enumerate() {
                if event.sequence != expected as u64 {
                    return Err(ContractError::EventSequence);
                }
                event.validate()?;
            }
            receipt.validate_against(invocation)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodexTransportEventPayload {
    TextDelta {
        text: String,
    },
    ToolCall {
        call_id: String,
        name: String,
        arguments: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexTransportEvent {
    pub sequence: u64,
    pub payload: CodexTransportEventPayload,
}

impl CodexTransportEvent {
    fn validate(&self) -> Result<(), ContractError> {
        match &self.payload {
            CodexTransportEventPayload::TextDelta { text } => require_content(text, "event.text"),
            CodexTransportEventPayload::ToolCall {
                call_id,
                name,
                arguments,
            } => {
                require_id(call_id, "event.call_id")?;
                require_id(name, "event.tool_name")?;
                require_content(arguments, "event.arguments")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexTransportReceipt {
    pub schema_id: String,
    pub request_id: String,
    pub caller_runtime_id: String,
    pub native_request_sha256: [u8; 32],
    pub provider_request_sha256: [u8; 32],
    pub model: String,
    pub transport: String,
    pub outcome: CodexTransportOutcome,
}

impl CodexTransportReceipt {
    pub fn validate_against(
        &self,
        invocation: &CodexTransportInvocation,
    ) -> Result<(), ContractError> {
        if self.schema_id != RECEIPT_SCHEMA_ID {
            return Err(ContractError::Schema);
        }
        if self.request_id != invocation.request_id()
            || self.caller_runtime_id != invocation.caller_runtime_id
            || self.model != invocation.request.model
        {
            return Err(ContractError::Identity);
        }
        if self.provider_request_sha256 != invocation.provider_request_sha256 {
            return Err(ContractError::ProviderDigest);
        }
        if self.native_request_sha256 != invocation.native_request_sha256 {
            return Err(ContractError::NativeDigest);
        }
        require_id(&self.transport, "receipt.transport")?;
        match &self.outcome {
            CodexTransportOutcome::Completed {
                provider_response_id: Some(value),
                ..
            } => require_id(value, "receipt.provider_response_id")?,
            CodexTransportOutcome::Failed {
                failure_kind,
                message,
            } => {
                require_id(failure_kind, "receipt.failure_kind")?;
                require_content(message, "receipt.failure_message")?;
            }
            CodexTransportOutcome::Completed {
                provider_response_id: None,
                ..
            } => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodexTransportOutcome {
    Completed {
        provider_response_id: Option<String>,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        reasoning_output_tokens: Option<u64>,
        cached_input_tokens: Option<u64>,
    },
    Failed {
        failure_kind: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodexRefusal {
    Expired,
    IdentitySubstitution,
    ProviderDigestSubstitution,
    Policy,
    Capacity,
    InFlight,
    Indeterminate,
    ReplayConflict,
    Malformed,
}

pub fn canonical_provider_request_bytes(
    request: &CodexProviderRequest,
) -> Result<Vec<u8>, ContractError> {
    request.validate()?;
    rmp_serde::to_vec(request).map_err(|_| ContractError::Encoding)
}

pub fn provider_request_sha256(request: &CodexProviderRequest) -> Result<[u8; 32], ContractError> {
    Ok(Sha256::digest(canonical_provider_request_bytes(request)?).into())
}

pub fn canonical_responses_body(
    request: &CodexProviderRequest,
) -> Result<serde_json::Value, ContractError> {
    request.validate()?;
    let input = request
        .input
        .iter()
        .map(|item| match item {
            CodexInputItem::UserText { text } => serde_json::json!({
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": text}],
            }),
            CodexInputItem::AssistantText { text } => serde_json::json!({
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": text}],
            }),
            CodexInputItem::ToolCall {
                call_id,
                name,
                arguments,
            } => serde_json::json!({
                "type": "function_call",
                "call_id": call_id,
                "name": name,
                "arguments": arguments,
            }),
            CodexInputItem::ToolResult { call_id, output } => serde_json::json!({
                "type": "function_call_output",
                "call_id": call_id,
                "output": output,
            }),
        })
        .collect::<Vec<_>>();
    let tools = request
        .tools
        .iter()
        .map(|tool| {
            Ok(serde_json::json!({
                "type": "function",
                "name": tool.name,
                "description": tool.description,
                "parameters": serde_json::from_str::<serde_json::Value>(&tool.parameters_json)
                    .map_err(|_| ContractError::Invalid("tool.parameters_json"))?,
                "strict": true,
            }))
        })
        .collect::<Result<Vec<_>, ContractError>>()?;
    let mut body = serde_json::json!({
        "model": request.model,
        "instructions": request.instructions,
        "input": input,
        "tools": tools,
        "tool_choice": match request.tool_choice {
            CodexToolChoice::Auto => "auto",
            CodexToolChoice::Required => "required",
        },
        "parallel_tool_calls": request.parallel_tool_calls,
        "store": false,
        "stream": true,
        "include": [],
    });
    let object = body
        .as_object_mut()
        .expect("the statically constructed Responses body is an object");
    if request.reasoning_effort.is_some() || request.reasoning_summary.is_some() {
        let mut reasoning = serde_json::Map::new();
        if let Some(effort) = &request.reasoning_effort {
            reasoning.insert("effort".to_string(), serde_json::json!(effort));
        }
        if let Some(summary) = &request.reasoning_summary {
            reasoning.insert("summary".to_string(), serde_json::json!(summary));
        }
        object.insert("reasoning".to_string(), reasoning.into());
    }
    for (name, value) in [
        (
            "service_tier",
            request
                .service_tier
                .as_ref()
                .map(|value| serde_json::json!(value)),
        ),
        (
            "previous_response_id",
            request
                .previous_response_id
                .as_ref()
                .map(|value| serde_json::json!(value)),
        ),
        (
            "prompt_cache_key",
            request
                .prompt_cache_key
                .as_ref()
                .map(|value| serde_json::json!(value)),
        ),
        (
            "max_output_tokens",
            request
                .max_output_tokens
                .map(|value| serde_json::json!(value)),
        ),
    ] {
        if let Some(value) = value {
            object.insert(name.to_string(), value);
        }
    }
    if let (Some(name), Some(schema)) = (
        request.output_format_name.as_ref(),
        request.output_schema_json.as_ref(),
    ) {
        object.insert(
            "text".to_string(),
            serde_json::json!({
                "format": {
                    "type": "json_schema",
                    "name": name,
                    "strict": true,
                    "schema": serde_json::from_str::<serde_json::Value>(schema)
                        .map_err(|_| ContractError::Invalid("output_schema_json"))?,
                }
            }),
        );
    }
    Ok(body)
}

pub fn canonical_responses_body_bytes(
    request: &CodexProviderRequest,
) -> Result<Vec<u8>, ContractError> {
    serde_json::to_vec(&canonical_responses_body(request)?).map_err(|_| ContractError::Encoding)
}

pub fn canonical_invocation_bytes(
    invocation: &CodexTransportInvocation,
) -> Result<Vec<u8>, ContractError> {
    invocation.request.validate()?;
    if invocation.provider_request_sha256 != provider_request_sha256(&invocation.request)? {
        return Err(ContractError::ProviderDigest);
    }
    rmp_serde::to_vec(invocation).map_err(|_| ContractError::Encoding)
}

#[cfg(feature = "client")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodexEnvelopeKind {
    Invocation,
    Result,
}

#[cfg(feature = "client")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexTransportEnvelope {
    pub schema_id: String,
    pub caller_runtime_id: String,
    pub request_id: String,
    pub message_kind: CodexEnvelopeKind,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[cfg(feature = "client")]
pub fn encrypt_invocation(
    invocation: &CodexTransportInvocation,
    security: &CodexTransportKey,
) -> Result<CodexTransportEnvelope, ServiceError> {
    let plaintext = canonical_invocation_bytes(invocation)?;
    encrypt_message(
        &invocation.caller_runtime_id,
        invocation.request_id(),
        CodexEnvelopeKind::Invocation,
        &plaintext,
        security,
    )
}

#[cfg(feature = "client")]
pub fn decrypt_invocation(
    envelope: &CodexTransportEnvelope,
    security: &CodexTransportKey,
) -> Result<CodexTransportInvocation, ServiceError> {
    validate_envelope(envelope, CodexEnvelopeKind::Invocation)?;
    let plaintext = decrypt_message(envelope, security)?;
    let invocation: CodexTransportInvocation =
        rmp_serde::from_slice(&plaintext).map_err(|_| ServiceError::Encoding)?;
    if invocation.caller_runtime_id != envelope.caller_runtime_id
        || invocation.request_id() != envelope.request_id
    {
        return Err(ServiceError::OuterIdentity);
    }
    Ok(invocation)
}

#[cfg(feature = "client")]
pub fn encrypt_result(
    result: &CodexTransportResult,
    security: &CodexTransportKey,
) -> Result<CodexTransportEnvelope, ServiceError> {
    let plaintext = rmp_serde::to_vec(result).map_err(|_| ServiceError::Encoding)?;
    encrypt_message(
        &result.caller_runtime_id,
        &result.request_id,
        CodexEnvelopeKind::Result,
        &plaintext,
        security,
    )
}

#[cfg(feature = "client")]
pub fn decrypt_result(
    envelope: &CodexTransportEnvelope,
    security: &CodexTransportKey,
    invocation: &CodexTransportInvocation,
) -> Result<CodexTransportResult, ServiceError> {
    validate_envelope(envelope, CodexEnvelopeKind::Result)?;
    let plaintext = decrypt_message(envelope, security)?;
    let result: CodexTransportResult =
        rmp_serde::from_slice(&plaintext).map_err(|_| ServiceError::Encoding)?;
    if result.caller_runtime_id != envelope.caller_runtime_id
        || result.request_id != envelope.request_id
    {
        return Err(ServiceError::OuterIdentity);
    }
    result.validate_against(invocation)?;
    Ok(result)
}

#[cfg(feature = "client")]
#[derive(Clone)]
pub struct CodexConnectorClient {
    endpoint: SocketAddr,
    security: CodexTransportKey,
    max_frame_bytes: usize,
    response_timeout: Option<Duration>,
}

#[cfg(feature = "client")]
impl CodexConnectorClient {
    pub fn new(
        endpoint: SocketAddr,
        connection_key: impl Into<String>,
        max_frame_bytes: usize,
        response_timeout: Option<Duration>,
    ) -> Result<Self, CodexConnectorClientError> {
        if !endpoint.ip().is_loopback()
            || endpoint.port() == 0
            || !(4096..=u32::MAX as usize).contains(&max_frame_bytes)
            || response_timeout.is_some_and(|timeout| timeout.is_zero())
        {
            return Err(CodexConnectorClientError::InvalidConfig);
        }
        let connection_key = Zeroizing::new(connection_key.into());
        let security = CodexTransportKey::from_connection_secret(connection_key.as_str())?;
        Ok(Self {
            endpoint,
            security,
            max_frame_bytes,
            response_timeout,
        })
    }

    pub fn execute(
        &self,
        invocation: &CodexTransportInvocation,
    ) -> Result<CodexTransportResult, CodexConnectorClientError> {
        let request = rmp_serde::to_vec(&encrypt_invocation(invocation, &self.security)?)
            .map_err(|_| CodexConnectorClientError::Encoding)?;
        let connect_timeout = self
            .response_timeout
            .unwrap_or(Duration::from_secs(10))
            .min(Duration::from_secs(10));
        let mut stream = TcpStream::connect_timeout(&self.endpoint, connect_timeout)
            .map_err(CodexConnectorClientError::Connection)?;
        stream
            .set_read_timeout(self.response_timeout)
            .and_then(|()| stream.set_write_timeout(self.response_timeout))
            .map_err(CodexConnectorClientError::Connection)?;
        write_transport_frame(&mut stream, &request, self.max_frame_bytes)
            .map_err(client_frame_error)?;
        let response =
            read_transport_frame(&mut stream, self.max_frame_bytes).map_err(client_frame_error)?;
        let envelope =
            rmp_serde::from_slice(&response).map_err(|_| CodexConnectorClientError::Encoding)?;
        decrypt_result(&envelope, &self.security, invocation).map_err(Into::into)
    }
}

#[cfg(feature = "client")]
#[derive(Debug, Error)]
pub enum CodexConnectorClientError {
    #[error("invalid connector client configuration")]
    InvalidConfig,
    #[error("connector client connection failed")]
    Connection(#[source] std::io::Error),
    #[error("connector frame exceeded its bound")]
    FrameSize,
    #[error("connector MessagePack encoding failed")]
    Encoding,
    #[error(transparent)]
    Transport(#[from] ServiceError),
}

#[cfg(feature = "client")]
#[derive(Debug)]
enum TransportFrameError {
    Connection(std::io::Error),
    Size,
}

#[cfg(feature = "client")]
fn client_frame_error(error: TransportFrameError) -> CodexConnectorClientError {
    match error {
        TransportFrameError::Connection(error) => CodexConnectorClientError::Connection(error),
        TransportFrameError::Size => CodexConnectorClientError::FrameSize,
    }
}

#[cfg(feature = "client")]
fn read_transport_frame(
    reader: &mut impl Read,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, TransportFrameError> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(TransportFrameError::Connection)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > max_frame_bytes {
        return Err(TransportFrameError::Size);
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(TransportFrameError::Connection)?;
    Ok(payload)
}

#[cfg(feature = "client")]
fn write_transport_frame(
    writer: &mut impl Write,
    payload: &[u8],
    max_frame_bytes: usize,
) -> Result<(), TransportFrameError> {
    if payload.is_empty() || payload.len() > max_frame_bytes || payload.len() > u32::MAX as usize {
        return Err(TransportFrameError::Size);
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .and_then(|()| writer.write_all(payload))
        .and_then(|()| writer.flush())
        .map_err(TransportFrameError::Connection)
}

#[cfg(feature = "client")]
fn encrypt_message(
    caller_runtime_id: &str,
    request_id: &str,
    message_kind: CodexEnvelopeKind,
    plaintext: &[u8],
    security: &CodexTransportKey,
) -> Result<CodexTransportEnvelope, ServiceError> {
    require_id(caller_runtime_id, "caller_runtime_id")?;
    require_id(request_id, "request_id")?;
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&security.0).map_err(|_| ServiceError::Encryption)?;
    let aad = envelope_aad(
        ENVELOPE_SCHEMA_ID,
        caller_runtime_id,
        request_id,
        message_kind,
    )?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| ServiceError::Encryption)?;
    Ok(CodexTransportEnvelope {
        schema_id: ENVELOPE_SCHEMA_ID.to_string(),
        caller_runtime_id: caller_runtime_id.to_string(),
        request_id: request_id.to_string(),
        message_kind,
        nonce,
        ciphertext,
    })
}

#[cfg(feature = "client")]
fn decrypt_message(
    envelope: &CodexTransportEnvelope,
    security: &CodexTransportKey,
) -> Result<Vec<u8>, ServiceError> {
    let cipher = Aes256Gcm::new_from_slice(&security.0).map_err(|_| ServiceError::Encryption)?;
    let aad = envelope_aad(
        &envelope.schema_id,
        &envelope.caller_runtime_id,
        &envelope.request_id,
        envelope.message_kind,
    )?;
    cipher
        .decrypt(
            Nonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| ServiceError::Encryption)
}

#[cfg(feature = "client")]
fn envelope_aad(
    schema_id: &str,
    caller_runtime_id: &str,
    request_id: &str,
    message_kind: CodexEnvelopeKind,
) -> Result<Vec<u8>, ServiceError> {
    rmp_serde::to_vec(&(schema_id, caller_runtime_id, request_id, message_kind))
        .map_err(|_| ServiceError::Encoding)
}

#[cfg(feature = "client")]
fn validate_envelope(
    envelope: &CodexTransportEnvelope,
    expected_kind: CodexEnvelopeKind,
) -> Result<(), ServiceError> {
    if envelope.schema_id != ENVELOPE_SCHEMA_ID || envelope.message_kind != expected_kind {
        return Err(ServiceError::Envelope);
    }
    require_id(&envelope.caller_runtime_id, "caller_runtime_id")?;
    require_id(&envelope.request_id, "request_id")?;
    if envelope.ciphertext.is_empty() {
        return Err(ServiceError::Envelope);
    }
    Ok(())
}

#[cfg(feature = "daemon")]
pub struct CodexCallerAdmission {
    caller_runtime_id: String,
    connection_key_epoch: u32,
    security: CodexTransportKey,
    allowed_models: HashSet<String>,
    max_concurrent_requests: usize,
    max_payload_bytes: usize,
    max_output_tokens: u32,
}

#[cfg(feature = "daemon")]
impl CodexCallerAdmission {
    pub fn new(
        caller_runtime_id: impl Into<String>,
        connection_key: impl Into<String>,
        connection_key_epoch: u32,
        allowed_models: impl IntoIterator<Item = String>,
        max_concurrent_requests: usize,
        max_payload_bytes: usize,
        max_output_tokens: u32,
    ) -> Result<Self, ServiceError> {
        let caller_runtime_id = caller_runtime_id.into();
        require_id(&caller_runtime_id, "caller_runtime_id")?;
        let allowed_models = allowed_models.into_iter().collect::<HashSet<_>>();
        if connection_key_epoch == 0
            || allowed_models.is_empty()
            || allowed_models
                .iter()
                .any(|model| require_id(model, "allowed_model").is_err())
            || max_concurrent_requests == 0
            || max_payload_bytes == 0
            || max_output_tokens == 0
        {
            return Err(ServiceError::InvalidAdmission);
        }
        let connection_key = Zeroizing::new(connection_key.into());
        let security = CodexTransportKey::from_connection_secret(connection_key.as_str())?;
        Ok(Self {
            caller_runtime_id,
            connection_key_epoch,
            security,
            allowed_models,
            max_concurrent_requests,
            max_payload_bytes,
            max_output_tokens,
        })
    }

    pub fn caller_runtime_id(&self) -> &str {
        &self.caller_runtime_id
    }
}

#[cfg(feature = "daemon")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestIdentity {
    caller_runtime_id: String,
    request_id: String,
}

#[cfg(feature = "daemon")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum CodexReplayState {
    Active,
    Completed { response: CodexTransportEnvelope },
}

#[cfg(feature = "daemon")]
#[derive(Clone, Debug, PartialEq, Eq, DatabaseEntry)]
#[cultcache(type = "gamecult.codex.replay_record.v1")]
struct CodexReplayRecord {
    #[cultcache(key = 0)]
    caller_runtime_id: String,
    #[cultcache(key = 1)]
    request_id: String,
    #[cultcache(key = 2)]
    connection_key_epoch: u32,
    #[cultcache(key = 3)]
    invocation_sha256: [u8; 32],
    #[cultcache(key = 4)]
    expires_at_unix_ms: u64,
    #[cultcache(key = 5)]
    state: CodexReplayState,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexExecutionClaim {
    invocation: CodexTransportInvocation,
    invocation_sha256: [u8; 32],
}

#[cfg(feature = "daemon")]
impl CodexExecutionClaim {
    pub fn invocation(&self) -> &CodexTransportInvocation {
        &self.invocation
    }
}

#[cfg(feature = "daemon")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexTransportAdmission {
    Execute(Box<CodexExecutionClaim>),
    Reply(CodexTransportEnvelope),
}

#[cfg(feature = "daemon")]
pub struct CodexTransportService {
    callers: HashMap<String, CodexCallerAdmission>,
    live: HashSet<RequestIdentity>,
    replay_store: CultCache,
    max_expiry_skew_ms: u64,
}

#[cfg(feature = "daemon")]
impl CodexTransportService {
    pub fn open(
        replay_store_path: &Path,
        admissions: impl IntoIterator<Item = CodexCallerAdmission>,
        max_expiry_skew_ms: u64,
    ) -> Result<Self, ServiceError> {
        if max_expiry_skew_ms == 0 {
            return Err(ServiceError::InvalidAdmission);
        }
        let mut callers = HashMap::new();
        let mut keys = HashSet::new();
        for admission in admissions {
            if !keys.insert(admission.security.0) {
                return Err(ServiceError::SharedCallerKey);
            }
            let caller_runtime_id = admission.caller_runtime_id.clone();
            if callers.insert(caller_runtime_id, admission).is_some() {
                return Err(ServiceError::DuplicateCaller);
            }
        }
        if callers.is_empty() {
            return Err(ServiceError::InvalidAdmission);
        }

        let mut replay_store = CultCache::new();
        replay_store
            .register_entry_type::<CodexReplayRecord>()
            .map_err(replay_store_error)?;
        replay_store.add_generic_backing_store(
            OwnedRedbMessagePackBackingStore::new(replay_store_path).map_err(replay_store_error)?,
        );
        replay_store
            .pull_all_backing_stores()
            .map_err(replay_store_error)?;

        for (key, record) in replay_store
            .get_all_with_keys::<CodexReplayRecord>()
            .map_err(replay_store_error)?
        {
            let identity = RequestIdentity {
                caller_runtime_id: record.caller_runtime_id.clone(),
                request_id: record.request_id.clone(),
            };
            if key != replay_key(&identity)
                || record.invocation_sha256 == [0; 32]
                || record.expires_at_unix_ms == 0
            {
                return Err(ServiceError::InvalidReplayRecord);
            }
            let Some(caller) = callers.get(&record.caller_runtime_id) else {
                continue;
            };
            if record.connection_key_epoch != caller.connection_key_epoch {
                return Err(ServiceError::ReplayCallerKeyMismatch);
            }
        }
        Ok(Self {
            callers,
            live: HashSet::new(),
            replay_store,
            max_expiry_skew_ms,
        })
    }

    pub fn begin(
        &mut self,
        envelope: &CodexTransportEnvelope,
        now_unix_ms: u64,
    ) -> Result<CodexTransportAdmission, ServiceError> {
        validate_envelope(envelope, CodexEnvelopeKind::Invocation)?;
        let caller = self
            .callers
            .get(&envelope.caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        if envelope.ciphertext.len() > caller.max_payload_bytes {
            return Err(ServiceError::PayloadTooLarge);
        }
        let security = caller.security.clone();
        let max_concurrent_requests = caller.max_concurrent_requests;
        let invocation = decrypt_invocation(envelope, &security)?;
        if let Err(error) = invocation.validate(now_unix_ms, self.max_expiry_skew_ms) {
            return self.reply_refusal(&invocation, contract_refusal(&error), &security);
        }
        if !caller.allowed_models.contains(&invocation.request.model)
            || invocation
                .request
                .max_output_tokens
                .is_some_and(|limit| limit > caller.max_output_tokens)
        {
            return self.reply_refusal(&invocation, CodexRefusal::Policy, &security);
        }

        let identity = RequestIdentity {
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            request_id: invocation.request_id().to_string(),
        };
        let invocation_sha256: [u8; 32] =
            Sha256::digest(canonical_invocation_bytes(&invocation)?).into();
        if let Some(record) = self
            .replay_store
            .get::<CodexReplayRecord>(&replay_key(&identity))
            .map_err(replay_store_error)?
        {
            if record.invocation_sha256 != invocation_sha256 {
                return self.reply_refusal(&invocation, CodexRefusal::ReplayConflict, &security);
            }
            return match record.state {
                CodexReplayState::Completed { response } => {
                    Ok(CodexTransportAdmission::Reply(response))
                }
                CodexReplayState::Active => {
                    let refusal = if self.live.contains(&identity) {
                        CodexRefusal::InFlight
                    } else {
                        CodexRefusal::Indeterminate
                    };
                    self.reply_refusal(&invocation, refusal, &security)
                }
            };
        }
        let active_for_caller = self
            .live
            .iter()
            .filter(|key| key.caller_runtime_id == invocation.caller_runtime_id)
            .count();
        if active_for_caller >= max_concurrent_requests {
            return self.reply_refusal(&invocation, CodexRefusal::Capacity, &security);
        }

        let replay_record = CodexReplayRecord {
            caller_runtime_id: identity.caller_runtime_id.clone(),
            request_id: identity.request_id.clone(),
            connection_key_epoch: caller.connection_key_epoch,
            invocation_sha256,
            expires_at_unix_ms: invocation.expires_at_unix_ms,
            state: CodexReplayState::Active,
        };
        self.replay_store
            .put(replay_key(&identity), &replay_record)
            .map_err(replay_store_error)?;
        self.live.insert(identity);
        Ok(CodexTransportAdmission::Execute(Box::new(
            CodexExecutionClaim {
                invocation,
                invocation_sha256,
            },
        )))
    }

    pub fn complete(
        &mut self,
        claim: CodexExecutionClaim,
        result: CodexTransportResult,
    ) -> Result<CodexTransportEnvelope, ServiceError> {
        if !matches!(
            &result.disposition,
            CodexTransportDisposition::Transported { .. }
        ) {
            return Err(ServiceError::InvalidCompletion);
        }
        result.validate_against(&claim.invocation)?;
        let identity = RequestIdentity {
            caller_runtime_id: claim.invocation.caller_runtime_id.clone(),
            request_id: claim.invocation.request_id().to_string(),
        };
        if !self.live.contains(&identity) {
            return Err(ServiceError::NoActiveRequest);
        }
        let active = self
            .replay_store
            .get::<CodexReplayRecord>(&replay_key(&identity))
            .map_err(replay_store_error)?
            .ok_or(ServiceError::NoActiveRequest)?;
        if active.invocation_sha256 != claim.invocation_sha256
            || !matches!(active.state, CodexReplayState::Active)
        {
            return Err(ServiceError::ActiveRequestMismatch);
        }
        let caller = self
            .callers
            .get(&identity.caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        let response = encrypt_result(&result, &caller.security)?;
        let replay_record = CodexReplayRecord {
            caller_runtime_id: identity.caller_runtime_id.clone(),
            request_id: identity.request_id.clone(),
            connection_key_epoch: caller.connection_key_epoch,
            invocation_sha256: claim.invocation_sha256,
            expires_at_unix_ms: claim.invocation.expires_at_unix_ms,
            state: CodexReplayState::Completed {
                response: response.clone(),
            },
        };
        self.replay_store
            .put(replay_key(&identity), &replay_record)
            .map_err(replay_store_error)?;
        self.live.remove(&identity);
        Ok(response)
    }

    fn reply_refusal(
        &self,
        invocation: &CodexTransportInvocation,
        refusal: CodexRefusal,
        security: &CodexTransportKey,
    ) -> Result<CodexTransportAdmission, ServiceError> {
        Ok(CodexTransportAdmission::Reply(encrypt_result(
            &CodexTransportResult::refused(invocation, refusal),
            security,
        )?))
    }
}

#[cfg(feature = "daemon")]
fn replay_key(identity: &RequestIdentity) -> String {
    let mut hasher = Sha256::new();
    hasher.update((identity.caller_runtime_id.len() as u64).to_be_bytes());
    hasher.update(identity.caller_runtime_id.as_bytes());
    hasher.update((identity.request_id.len() as u64).to_be_bytes());
    hasher.update(identity.request_id.as_bytes());
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = hasher.finalize();
    let mut key = String::with_capacity(64);
    for byte in digest {
        key.push(HEX[(byte >> 4) as usize] as char);
        key.push(HEX[(byte & 0x0f) as usize] as char);
    }
    key
}

#[cfg(feature = "daemon")]
fn replay_store_error(error: impl std::fmt::Display) -> ServiceError {
    ServiceError::ReplayStore(error.to_string())
}

#[cfg(feature = "daemon")]
fn contract_refusal(error: &ContractError) -> CodexRefusal {
    match error {
        ContractError::Expiry => CodexRefusal::Expired,
        ContractError::Identity => CodexRefusal::IdentitySubstitution,
        ContractError::ProviderDigest => CodexRefusal::ProviderDigestSubstitution,
        _ => CodexRefusal::Malformed,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ServiceError {
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error("invalid caller admission")]
    InvalidAdmission,
    #[error("caller runtime was admitted twice")]
    DuplicateCaller,
    #[error("callers must not share transport keys")]
    SharedCallerKey,
    #[error("connector replay store failed: {0}")]
    ReplayStore(String),
    #[error("connector replay record is malformed")]
    InvalidReplayRecord,
    #[error("caller key changed while durable replay records still exist")]
    ReplayCallerKeyMismatch,
    #[error("caller runtime is not admitted")]
    CallerNotAdmitted,
    #[error("transport payload exceeds the caller bound")]
    PayloadTooLarge,
    #[error("unexpected transport envelope")]
    Envelope,
    #[error("transport envelope identity substitution")]
    OuterIdentity,
    #[error("transport encryption or authentication failed")]
    Encryption,
    #[error("transport MessagePack encoding failed")]
    Encoding,
    #[error("completion did not carry a transported provider outcome")]
    InvalidCompletion,
    #[error("completion has no active request")]
    NoActiveRequest,
    #[error("completion does not match the active request")]
    ActiveRequestMismatch,
}

fn require_id(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

fn require_content(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.is_empty() {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

fn require_json_object(value: &str, field: &'static str) -> Result<(), ContractError> {
    if !matches!(
        serde_json::from_str::<serde_json::Value>(value),
        Ok(serde_json::Value::Object(_))
    ) {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

fn require_provider_name(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

fn require_provider_call_id(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return Err(ContractError::Invalid(field));
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("unexpected schema")]
    Schema,
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("duplicate tool {0:?}")]
    DuplicateTool(String),
    #[error("request identity substitution")]
    Identity,
    #[error("provider request digest substitution")]
    ProviderDigest,
    #[error("native request digest substitution")]
    NativeDigest,
    #[error("invocation expiry is outside the admitted horizon")]
    Expiry,
    #[error("transport event sequence is not contiguous")]
    EventSequence,
    #[error("canonical MessagePack encoding failed")]
    Encoding,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "daemon")]
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[cfg(feature = "daemon")]
    static TEST_STORE_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    #[cfg(feature = "daemon")]
    struct TestStore {
        root: std::path::PathBuf,
        path: std::path::PathBuf,
    }

    #[cfg(feature = "daemon")]
    impl TestStore {
        fn new() -> Self {
            let sequence = TEST_STORE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "codex-connector-replay-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join("replay.cc");
            Self { root, path }
        }
    }

    #[cfg(feature = "daemon")]
    impl Drop for TestStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn request() -> CodexProviderRequest {
        let mut request = CodexProviderRequest::new(
            "request-1",
            "conversation-1",
            "gpt-5.4",
            "Return the typed result.",
        );
        request.input.push(CodexInputItem::UserText {
            text: "Projected state".to_string(),
        });
        request.tools.push(CodexToolDefinition {
            name: "read_source".to_string(),
            description: "Read one admitted source.".to_string(),
            parameters_json: r#"{"type":"object"}"#.to_string(),
        });
        request
    }

    fn invocation() -> CodexTransportInvocation {
        CodexTransportInvocation::new("epiphany-yggdrasil", 2_000, [7; 32], request()).unwrap()
    }

    fn receipt(invocation: &CodexTransportInvocation) -> CodexTransportReceipt {
        CodexTransportReceipt {
            schema_id: RECEIPT_SCHEMA_ID.to_string(),
            request_id: invocation.request_id().to_string(),
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            native_request_sha256: invocation.native_request_sha256,
            provider_request_sha256: invocation.provider_request_sha256,
            model: invocation.request.model.clone(),
            transport: "codex-responses-sse".to_string(),
            outcome: CodexTransportOutcome::Completed {
                provider_response_id: Some("response-1".to_string()),
                input_tokens: Some(10),
                output_tokens: Some(3),
                reasoning_output_tokens: Some(1),
                cached_input_tokens: None,
            },
        }
    }

    #[test]
    fn provider_digest_is_stable_and_content_addressed() {
        let original = request();
        let same = original.clone();
        assert_eq!(
            provider_request_sha256(&original).unwrap(),
            provider_request_sha256(&same).unwrap()
        );
        let mut changed = original.clone();
        changed.instructions.push_str(" Changed.");
        assert_ne!(
            provider_request_sha256(&original).unwrap(),
            provider_request_sha256(&changed).unwrap()
        );
    }

    #[test]
    fn canonical_responses_body_preserves_caller_owned_provider_policy() {
        let mut request = request();
        request.tool_choice = CodexToolChoice::Required;
        request.parallel_tool_calls = false;
        request.reasoning_effort = Some("high".to_string());
        request.previous_response_id = Some("response-previous".to_string());
        request.max_output_tokens = Some(512);
        request.output_format_name = Some("epiphany_role_result_v3".to_string());
        request.output_schema_json = Some(
            r#"{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"],"additionalProperties":false}"#
                .to_string(),
        );

        let body = canonical_responses_body(&request).unwrap();
        assert_eq!(body["tool_choice"], "required");
        assert_eq!(body["parallel_tool_calls"], false);
        assert_eq!(body["reasoning"], serde_json::json!({"effort": "high"}));
        assert_eq!(body["previous_response_id"], "response-previous");
        assert_eq!(body["max_output_tokens"], 512);
        assert_eq!(body["tools"][0]["name"], "read_source");
        assert_eq!(body["text"]["format"]["name"], "epiphany_role_result_v3");
        assert_eq!(
            canonical_responses_body_bytes(&request).unwrap(),
            serde_json::to_vec(&body).unwrap()
        );
    }

    #[test]
    fn provider_contract_refuses_transport_side_fixup_pressure() {
        let mut request = request();
        request.output_format_name = Some("epiphany.role.result".to_string());
        request.output_schema_json = Some(r#"{"type":"object"}"#.to_string());
        assert_eq!(
            request.validate(),
            Err(ContractError::Invalid("output_format_name"))
        );

        request.output_format_name = None;
        request.output_schema_json = None;
        request.input.push(CodexInputItem::ToolResult {
            call_id: "x".repeat(65),
            output: "evidence".to_string(),
        });
        assert_eq!(
            request.validate(),
            Err(ContractError::Invalid("input.call_id"))
        );
    }

    #[test]
    fn invocation_refuses_provider_request_substitution() {
        let mut invocation = invocation();
        invocation.request.model = "substituted".to_string();
        assert_eq!(
            invocation.validate(1_000, 2_000),
            Err(ContractError::ProviderDigest)
        );
    }

    #[test]
    fn invocation_refuses_expired_or_blank_native_provenance() {
        let mut invocation = invocation();
        assert_eq!(
            invocation.validate(2_001, 2_000),
            Err(ContractError::Expiry)
        );
        invocation.expires_at_unix_ms = 2_500;
        invocation.native_request_sha256 = [0; 32];
        assert_eq!(
            invocation.validate(2_001, 2_000),
            Err(ContractError::Invalid("native_request_sha256"))
        );
    }

    #[test]
    fn typed_tool_round_survives_messagepack() {
        let invocation = invocation();
        let bytes = rmp_serde::to_vec(&invocation).unwrap();
        let decoded: CodexTransportInvocation = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, invocation);
        assert!(matches!(
            decoded.request.tools.as_slice(),
            [CodexToolDefinition { name, .. }] if name == "read_source"
        ));
    }

    #[test]
    fn transported_result_binds_identity_digest_and_event_order() {
        let invocation = invocation();
        let result = CodexTransportResult::transported(
            &invocation,
            vec![CodexTransportEvent {
                sequence: 0,
                payload: CodexTransportEventPayload::ToolCall {
                    call_id: "call-1".to_string(),
                    name: "read_source".to_string(),
                    arguments: "{}".to_string(),
                },
            }],
            receipt(&invocation),
        );
        assert_eq!(result.validate_against(&invocation), Ok(()));

        let mut reordered = result;
        let CodexTransportDisposition::Transported { events, .. } = &mut reordered.disposition
        else {
            unreachable!()
        };
        events[0].sequence = 1;
        assert_eq!(
            reordered.validate_against(&invocation),
            Err(ContractError::EventSequence)
        );
    }

    #[test]
    fn receipt_refuses_caller_substitution() {
        let invocation = invocation();
        let mut substituted_caller = receipt(&invocation);
        substituted_caller.caller_runtime_id = "ghostlight-dungeon-yggdrasil".to_string();
        assert_eq!(
            substituted_caller.validate_against(&invocation),
            Err(ContractError::Identity)
        );

        let mut substituted_native_basis = receipt(&invocation);
        substituted_native_basis.native_request_sha256 = [8; 32];
        assert_eq!(
            substituted_native_basis.validate_against(&invocation),
            Err(ContractError::NativeDigest)
        );
    }

    #[cfg(feature = "daemon")]
    fn caller(
        caller_runtime_id: &str,
        key: &str,
        max_concurrent_requests: usize,
    ) -> CodexCallerAdmission {
        CodexCallerAdmission::new(
            caller_runtime_id,
            key,
            1,
            ["gpt-5.4".to_string()],
            max_concurrent_requests,
            64 * 1024,
            32_768,
        )
        .unwrap()
    }

    #[cfg(feature = "daemon")]
    fn open_service(store: &TestStore, max_concurrent_requests: usize) -> CodexTransportService {
        CodexTransportService::open(
            &store.path,
            [
                caller(
                    "epiphany-yggdrasil",
                    "epiphany-distinct-test-key",
                    max_concurrent_requests,
                ),
                caller(
                    "ghostlight-yggdrasil",
                    "ghostlight-distinct-test-key",
                    max_concurrent_requests,
                ),
            ],
            5_000,
        )
        .unwrap()
    }

    #[cfg(feature = "client")]
    fn security(key: &str) -> CodexTransportKey {
        CodexTransportKey::from_connection_secret(key).unwrap()
    }

    #[cfg(feature = "daemon")]
    fn invocation_for(caller_runtime_id: &str, request_id: &str) -> CodexTransportInvocation {
        let mut request = request();
        request.request_id = request_id.to_string();
        CodexTransportInvocation::new(caller_runtime_id, 2_000, [7; 32], request).unwrap()
    }

    #[cfg(feature = "client")]
    #[test]
    fn encrypted_invocation_hides_content_and_binds_outer_identity() {
        let invocation = invocation();
        let epiphany_key = security("epiphany-distinct-test-key");
        let envelope = encrypt_invocation(&invocation, &epiphany_key).unwrap();
        assert!(
            !envelope
                .ciphertext
                .windows("Projected state".len())
                .any(|window| window == b"Projected state")
        );
        assert_eq!(
            decrypt_invocation(&envelope, &epiphany_key).unwrap(),
            invocation
        );
        assert_eq!(
            decrypt_invocation(&envelope, &security("wrong-caller-key")),
            Err(ServiceError::Encryption)
        );

        let mut substituted = envelope;
        substituted.request_id = "request-2".to_string();
        assert_eq!(
            decrypt_invocation(&substituted, &epiphany_key),
            Err(ServiceError::Encryption)
        );
    }

    #[cfg(feature = "client")]
    #[test]
    fn shared_client_transports_one_exact_encrypted_request_and_result() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let invocation = invocation();
        let expected = invocation.clone();
        let security = security("epiphany-distinct-test-key");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_transport_frame(&mut stream, 64 * 1024).unwrap();
            let envelope: CodexTransportEnvelope = rmp_serde::from_slice(&request).unwrap();
            assert_eq!(decrypt_invocation(&envelope, &security).unwrap(), expected);
            let response = encrypt_result(
                &CodexTransportResult::refused(&expected, CodexRefusal::Policy),
                &security,
            )
            .unwrap();
            write_transport_frame(
                &mut stream,
                &rmp_serde::to_vec(&response).unwrap(),
                64 * 1024,
            )
            .unwrap();
        });

        let client = CodexConnectorClient::new(
            endpoint,
            "epiphany-distinct-test-key",
            64 * 1024,
            Some(Duration::from_secs(1)),
        )
        .unwrap();
        assert_eq!(
            client.execute(&invocation).unwrap().disposition,
            CodexTransportDisposition::Refused(CodexRefusal::Policy)
        );
        server.join().unwrap();
    }

    #[test]
    #[cfg(feature = "daemon")]
    fn service_refuses_shared_keys_and_isolates_caller_request_identities() {
        let store = TestStore::new();
        assert!(matches!(
            CodexTransportService::open(
                &store.path,
                [
                    caller("epiphany-yggdrasil", "shared-key", 1),
                    caller("ghostlight-yggdrasil", "shared-key", 1),
                ],
                5_000,
            ),
            Err(ServiceError::SharedCallerKey)
        ));

        let epiphany = invocation_for("epiphany-yggdrasil", "shared-request-id");
        let ghostlight = invocation_for("ghostlight-yggdrasil", "shared-request-id");
        let mut service = open_service(&store, 1);
        assert!(matches!(
            service
                .begin(
                    &encrypt_invocation(&epiphany, &security("epiphany-distinct-test-key"))
                        .unwrap(),
                    1_000,
                )
                .unwrap(),
            CodexTransportAdmission::Execute(_)
        ));
        assert!(matches!(
            service
                .begin(
                    &encrypt_invocation(&ghostlight, &security("ghostlight-distinct-test-key"))
                        .unwrap(),
                    1_000,
                )
                .unwrap(),
            CodexTransportAdmission::Execute(_)
        ));
    }

    #[test]
    #[cfg(feature = "daemon")]
    fn service_returns_exact_completed_replay_and_refuses_conflicting_replay() {
        let store = TestStore::new();
        let invocation = invocation();
        let security = security("epiphany-distinct-test-key");
        let mut service = open_service(&store, 1);
        let claim = match service
            .begin(&encrypt_invocation(&invocation, &security).unwrap(), 1_000)
            .unwrap()
        {
            CodexTransportAdmission::Execute(claim) => claim,
            CodexTransportAdmission::Reply(_) => panic!("first invocation must execute"),
        };
        let response = service
            .complete(
                *claim,
                CodexTransportResult::transported(
                    &invocation,
                    vec![CodexTransportEvent {
                        sequence: 0,
                        payload: CodexTransportEventPayload::ToolCall {
                            call_id: "call-1".to_string(),
                            name: "read_source".to_string(),
                            arguments: "{}".to_string(),
                        },
                    }],
                    receipt(&invocation),
                ),
            )
            .unwrap();
        drop(service);
        let mut service = open_service(&store, 1);

        let replay = match service
            .begin(&encrypt_invocation(&invocation, &security).unwrap(), 1_000)
            .unwrap()
        {
            CodexTransportAdmission::Reply(response) => response,
            CodexTransportAdmission::Execute(_) => panic!("completed invocation re-executed"),
        };
        assert_eq!(replay, response);
        let decoded = decrypt_result(&replay, &security, &invocation).unwrap();
        assert!(matches!(
            decoded.disposition,
            CodexTransportDisposition::Transported { .. }
        ));

        let mut changed_request = request();
        changed_request.instructions.push_str(" Different cargo.");
        let conflicting =
            CodexTransportInvocation::new("epiphany-yggdrasil", 2_000, [7; 32], changed_request)
                .unwrap();
        let refusal = match service
            .begin(&encrypt_invocation(&conflicting, &security).unwrap(), 1_000)
            .unwrap()
        {
            CodexTransportAdmission::Reply(response) => response,
            CodexTransportAdmission::Execute(_) => panic!("conflicting replay executed"),
        };
        assert!(matches!(
            decrypt_result(&refusal, &security, &conflicting)
                .unwrap()
                .disposition,
            CodexTransportDisposition::Refused(CodexRefusal::ReplayConflict)
        ));
    }

    #[test]
    #[cfg(feature = "daemon")]
    fn service_refuses_duplicate_inflight_and_per_caller_capacity() {
        let store = TestStore::new();
        let first = invocation_for("epiphany-yggdrasil", "request-1");
        let second = invocation_for("epiphany-yggdrasil", "request-2");
        let security = security("epiphany-distinct-test-key");
        let mut service = open_service(&store, 1);
        let first_envelope = encrypt_invocation(&first, &security).unwrap();
        assert!(matches!(
            service.begin(&first_envelope, 1_000).unwrap(),
            CodexTransportAdmission::Execute(_)
        ));

        for (invocation, expected) in [
            (&first, CodexRefusal::InFlight),
            (&second, CodexRefusal::Capacity),
        ] {
            let response = match service
                .begin(&encrypt_invocation(invocation, &security).unwrap(), 1_000)
                .unwrap()
            {
                CodexTransportAdmission::Reply(response) => response,
                CodexTransportAdmission::Execute(_) => panic!("refused invocation executed"),
            };
            assert_eq!(
                decrypt_result(&response, &security, invocation)
                    .unwrap()
                    .disposition,
                CodexTransportDisposition::Refused(expected)
            );
        }
    }

    #[test]
    #[cfg(feature = "daemon")]
    fn restart_refuses_ambiguous_claim_without_consuming_live_capacity() {
        let store = TestStore::new();
        let first = invocation_for("epiphany-yggdrasil", "request-1");
        let second = invocation_for("epiphany-yggdrasil", "request-2");
        let security = security("epiphany-distinct-test-key");
        let mut service = open_service(&store, 1);
        assert!(matches!(
            service
                .begin(&encrypt_invocation(&first, &security).unwrap(), 1_000)
                .unwrap(),
            CodexTransportAdmission::Execute(_)
        ));
        drop(service);

        let mut restarted = open_service(&store, 1);
        let ambiguous = match restarted
            .begin(&encrypt_invocation(&first, &security).unwrap(), 1_000)
            .unwrap()
        {
            CodexTransportAdmission::Reply(response) => response,
            CodexTransportAdmission::Execute(_) => panic!("ambiguous claim re-executed"),
        };
        assert_eq!(
            decrypt_result(&ambiguous, &security, &first)
                .unwrap()
                .disposition,
            CodexTransportDisposition::Refused(CodexRefusal::Indeterminate)
        );
        assert!(matches!(
            restarted
                .begin(&encrypt_invocation(&second, &security).unwrap(), 1_000)
                .unwrap(),
            CodexTransportAdmission::Execute(_)
        ));
        drop(restarted);
        assert!(matches!(
            CodexTransportService::open(
                &store.path,
                [CodexCallerAdmission::new(
                    "epiphany-yggdrasil",
                    "rotated-connection-key",
                    2,
                    ["gpt-5.4".to_string()],
                    1,
                    64 * 1024,
                    32_768,
                )
                .unwrap()],
                5_000,
            ),
            Err(ServiceError::ReplayCallerKeyMismatch)
        ));
    }
}
