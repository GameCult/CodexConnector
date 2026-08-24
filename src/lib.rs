use std::collections::{HashMap, HashSet};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROVIDER_REQUEST_SCHEMA_ID: &str = "gamecult.codex.provider_request.v2";
pub const INVOCATION_SCHEMA_ID: &str = "gamecult.codex.transport_invocation.v2";
pub const RESULT_SCHEMA_ID: &str = "gamecult.codex.transport_result.v2";
pub const RECEIPT_SCHEMA_ID: &str = "gamecult.codex.transport_receipt.v2";
pub const ENVELOPE_SCHEMA_ID: &str = "gamecult.codex.transport_envelope.v2";

#[derive(Clone, PartialEq, Eq)]
pub struct CodexTransportKey([u8; 32]);

impl CodexTransportKey {
    pub fn from_connection_secret(secret: &str) -> Result<Self, ServiceError> {
        if secret.trim().is_empty() || secret.trim() != secret {
            return Err(ServiceError::InvalidAdmission);
        }
        Ok(Self(Sha256::digest(secret.as_bytes()).into()))
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
    pub output_contract_id: Option<String>,
    pub previous_response_id: Option<String>,
    pub tools: Vec<CodexToolDefinition>,
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
            output_contract_id: None,
            previous_response_id: None,
            tools: Vec::new(),
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
            (self.output_contract_id.as_deref(), "output_contract_id"),
            (self.previous_response_id.as_deref(), "previous_response_id"),
        ] {
            if let Some(value) = value {
                require_id(value, field)?;
            }
        }
        if let Some(schema) = &self.output_schema_json {
            require_content(schema, "output_schema_json")?;
        }

        let mut tool_names = HashSet::new();
        for tool in &self.tools {
            require_id(&tool.name, "tool.name")?;
            require_content(&tool.description, "tool.description")?;
            require_content(&tool.parameters_json, "tool.parameters_json")?;
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
                    require_id(call_id, "input.call_id")?;
                    require_id(name, "input.tool_name")?;
                    require_content(arguments, "input.arguments")?;
                }
                CodexInputItem::ToolResult { call_id, output } => {
                    require_id(call_id, "input.call_id")?;
                    require_content(output, "input.output")?;
                }
            }
        }
        Ok(())
    }
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

pub fn canonical_invocation_bytes(
    invocation: &CodexTransportInvocation,
) -> Result<Vec<u8>, ContractError> {
    invocation.request.validate()?;
    if invocation.provider_request_sha256 != provider_request_sha256(&invocation.request)? {
        return Err(ContractError::ProviderDigest);
    }
    rmp_serde::to_vec(invocation).map_err(|_| ContractError::Encoding)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodexEnvelopeKind {
    Invocation,
    Result,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexTransportEnvelope {
    pub schema_id: String,
    pub caller_runtime_id: String,
    pub request_id: String,
    pub message_kind: CodexEnvelopeKind,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

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

fn envelope_aad(
    schema_id: &str,
    caller_runtime_id: &str,
    request_id: &str,
    message_kind: CodexEnvelopeKind,
) -> Result<Vec<u8>, ServiceError> {
    rmp_serde::to_vec(&(schema_id, caller_runtime_id, request_id, message_kind))
        .map_err(|_| ServiceError::Encoding)
}

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

pub struct CodexCallerAdmission {
    caller_runtime_id: String,
    security: CodexTransportKey,
    allowed_models: HashSet<String>,
    max_concurrent_requests: usize,
    max_payload_bytes: usize,
    max_output_tokens: u32,
}

impl CodexCallerAdmission {
    pub fn new(
        caller_runtime_id: impl Into<String>,
        connection_key: impl Into<String>,
        allowed_models: impl IntoIterator<Item = String>,
        max_concurrent_requests: usize,
        max_payload_bytes: usize,
        max_output_tokens: u32,
    ) -> Result<Self, ServiceError> {
        let caller_runtime_id = caller_runtime_id.into();
        require_id(&caller_runtime_id, "caller_runtime_id")?;
        let allowed_models = allowed_models.into_iter().collect::<HashSet<_>>();
        if allowed_models.is_empty()
            || allowed_models
                .iter()
                .any(|model| require_id(model, "allowed_model").is_err())
            || max_concurrent_requests == 0
            || max_payload_bytes == 0
            || max_output_tokens == 0
        {
            return Err(ServiceError::InvalidAdmission);
        }
        let connection_key = connection_key.into();
        let security = CodexTransportKey::from_connection_secret(&connection_key)?;
        Ok(Self {
            caller_runtime_id,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestIdentity {
    caller_runtime_id: String,
    request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveRequest {
    invocation_sha256: [u8; 32],
    expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompletedRequest {
    invocation_sha256: [u8; 32],
    expires_at_unix_ms: u64,
    response: CodexTransportEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexExecutionClaim {
    invocation: CodexTransportInvocation,
    invocation_sha256: [u8; 32],
}

impl CodexExecutionClaim {
    pub fn invocation(&self) -> &CodexTransportInvocation {
        &self.invocation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexTransportAdmission {
    Execute(Box<CodexExecutionClaim>),
    Reply(CodexTransportEnvelope),
}

pub struct CodexTransportService {
    callers: HashMap<String, CodexCallerAdmission>,
    active: HashMap<RequestIdentity, ActiveRequest>,
    completed: HashMap<RequestIdentity, CompletedRequest>,
    max_expiry_skew_ms: u64,
}

impl CodexTransportService {
    pub fn new(
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
        Ok(Self {
            callers,
            active: HashMap::new(),
            completed: HashMap::new(),
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

        self.active
            .retain(|_, request| request.expires_at_unix_ms >= now_unix_ms);
        self.completed
            .retain(|_, request| request.expires_at_unix_ms >= now_unix_ms);

        let identity = RequestIdentity {
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            request_id: invocation.request_id().to_string(),
        };
        let invocation_sha256: [u8; 32] =
            Sha256::digest(canonical_invocation_bytes(&invocation)?).into();
        if let Some(completed) = self.completed.get(&identity) {
            return if completed.invocation_sha256 == invocation_sha256 {
                Ok(CodexTransportAdmission::Reply(completed.response.clone()))
            } else {
                self.reply_refusal(&invocation, CodexRefusal::ReplayConflict, &security)
            };
        }
        if let Some(active) = self.active.get(&identity) {
            let refusal = if active.invocation_sha256 == invocation_sha256 {
                CodexRefusal::InFlight
            } else {
                CodexRefusal::ReplayConflict
            };
            return self.reply_refusal(&invocation, refusal, &security);
        }
        let active_for_caller = self
            .active
            .keys()
            .filter(|key| key.caller_runtime_id == invocation.caller_runtime_id)
            .count();
        if active_for_caller >= max_concurrent_requests {
            return self.reply_refusal(&invocation, CodexRefusal::Capacity, &security);
        }

        self.active.insert(
            identity,
            ActiveRequest {
                invocation_sha256,
                expires_at_unix_ms: invocation.expires_at_unix_ms,
            },
        );
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
        let active = self
            .active
            .get(&identity)
            .ok_or(ServiceError::NoActiveRequest)?;
        if active.invocation_sha256 != claim.invocation_sha256 {
            return Err(ServiceError::ActiveRequestMismatch);
        }
        let caller = self
            .callers
            .get(&identity.caller_runtime_id)
            .ok_or(ServiceError::CallerNotAdmitted)?;
        let response = encrypt_result(&result, &caller.security)?;
        self.active.remove(&identity);
        self.completed.insert(
            identity,
            CompletedRequest {
                invocation_sha256: claim.invocation_sha256,
                expires_at_unix_ms: claim.invocation.expires_at_unix_ms,
                response: response.clone(),
            },
        );
        Ok(response)
    }

    pub fn cancel(&mut self, claim: &CodexExecutionClaim) -> bool {
        let identity = RequestIdentity {
            caller_runtime_id: claim.invocation.caller_runtime_id.clone(),
            request_id: claim.invocation.request_id().to_string(),
        };
        self.active
            .get(&identity)
            .is_some_and(|active| active.invocation_sha256 == claim.invocation_sha256)
            && self.active.remove(&identity).is_some()
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

    fn caller(
        caller_runtime_id: &str,
        key: &str,
        max_concurrent_requests: usize,
    ) -> CodexCallerAdmission {
        CodexCallerAdmission::new(
            caller_runtime_id,
            key,
            ["gpt-5.4".to_string()],
            max_concurrent_requests,
            64 * 1024,
            32_768,
        )
        .unwrap()
    }

    fn service(max_concurrent_requests: usize) -> CodexTransportService {
        CodexTransportService::new(
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

    fn security(key: &str) -> CodexTransportKey {
        CodexTransportKey::from_connection_secret(key).unwrap()
    }

    fn invocation_for(caller_runtime_id: &str, request_id: &str) -> CodexTransportInvocation {
        let mut request = request();
        request.request_id = request_id.to_string();
        CodexTransportInvocation::new(caller_runtime_id, 2_000, [7; 32], request).unwrap()
    }

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

    #[test]
    fn service_refuses_shared_keys_and_isolates_caller_request_identities() {
        assert!(matches!(
            CodexTransportService::new(
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
        let mut service = service(1);
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
    fn service_returns_exact_completed_replay_and_refuses_conflicting_replay() {
        let invocation = invocation();
        let security = security("epiphany-distinct-test-key");
        let mut service = service(1);
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
    fn service_refuses_duplicate_inflight_and_per_caller_capacity() {
        let first = invocation_for("epiphany-yggdrasil", "request-1");
        let second = invocation_for("epiphany-yggdrasil", "request-2");
        let security = security("epiphany-distinct-test-key");
        let mut service = service(1);
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
}
