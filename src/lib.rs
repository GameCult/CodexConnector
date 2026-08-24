use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROVIDER_REQUEST_SCHEMA_ID: &str = "gamecult.codex.provider_request.v2";
pub const INVOCATION_SCHEMA_ID: &str = "gamecult.codex.transport_invocation.v2";
pub const RESULT_SCHEMA_ID: &str = "gamecult.codex.transport_result.v2";
pub const RECEIPT_SCHEMA_ID: &str = "gamecult.codex.transport_receipt.v2";

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
pub enum CodexTransportResult {
    Refused {
        schema_id: String,
        request_id: String,
        caller_runtime_id: String,
        reason: CodexRefusal,
    },
    Transported {
        schema_id: String,
        request_id: String,
        caller_runtime_id: String,
        provider_request_sha256: [u8; 32],
        events: Vec<CodexTransportEvent>,
        receipt: CodexTransportReceipt,
    },
}

impl CodexTransportResult {
    pub fn validate_against(
        &self,
        invocation: &CodexTransportInvocation,
    ) -> Result<(), ContractError> {
        let (schema_id, request_id, caller_runtime_id) = match self {
            Self::Refused {
                schema_id,
                request_id,
                caller_runtime_id,
                ..
            }
            | Self::Transported {
                schema_id,
                request_id,
                caller_runtime_id,
                ..
            } => (schema_id, request_id, caller_runtime_id),
        };
        if schema_id != RESULT_SCHEMA_ID {
            return Err(ContractError::Schema);
        }
        if request_id != invocation.request_id()
            || caller_runtime_id != &invocation.caller_runtime_id
        {
            return Err(ContractError::Identity);
        }

        if let Self::Transported {
            provider_request_sha256,
            events,
            receipt,
            ..
        } = self
        {
            if provider_request_sha256 != &invocation.provider_request_sha256 {
                return Err(ContractError::ProviderDigest);
            }
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
    CallerNotAdmitted,
    Expired,
    IdentitySubstitution,
    ProviderDigestSubstitution,
    Policy,
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
        let result = CodexTransportResult::Transported {
            schema_id: RESULT_SCHEMA_ID.to_string(),
            request_id: invocation.request_id().to_string(),
            caller_runtime_id: invocation.caller_runtime_id.clone(),
            provider_request_sha256: invocation.provider_request_sha256,
            events: vec![CodexTransportEvent {
                sequence: 0,
                payload: CodexTransportEventPayload::ToolCall {
                    call_id: "call-1".to_string(),
                    name: "read_source".to_string(),
                    arguments: "{}".to_string(),
                },
            }],
            receipt: receipt(&invocation),
        };
        assert_eq!(result.validate_against(&invocation), Ok(()));

        let mut reordered = result;
        let CodexTransportResult::Transported { events, .. } = &mut reordered else {
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
}
