# CodexConnector

CodexConnector is a credential-isolated transport daemon for Codex-compatible
subscription inference. Epiphany and Ghostlight remain separate minds. They
derive their own exact provider requests, execute their own tools, interpret
their own results, and admit their own state.

The service owns authenticated caller admission, bounded transport physiology,
exact provider-request receipts, and redacted CultMesh health. A private pinned
official `codex app-server` child is the sole writer and refresh authority for
one credential store. The public connector reads the credential only after the
child's private auth RPC completes, then performs the exact Responses request.
It owns no prompt policy or decision authority.

The default library is the shared consumer ABI: v2 typed contracts, exact
provider lowering, encryption, bounded direct-pipe framing, one-request socket
transport, and exact result validation. It does not compile CultCache, HTTP,
TLS, provider auth, replay, or daemon code. Epiphany and Ghostlight consume this
surface instead of copying wire law.

Connection establishment is bounded independently. Response read/write timeout
is optional so a consumer's typed outer pass may remain the sole deadline owner.

The explicit `daemon` feature adds the transport service core, private
Codex-auth/provider backend, and the sole public daemon entrypoint. The daemon
reads one typed CultCache configuration document, binds
only loopback, uses CultNet's four-byte big-endian direct-pipe framing around
the encrypted MessagePack envelope, bounds connection threads and frame sizes,
and keeps provider execution outside the service-state lock. One keyed
CultCache replay record is sealed active before provider I/O and replaced by
the exact encrypted response before socket reply. Completed retries survive
restart byte-for-byte; a restart-era active claim refuses as indeterminate
rather than executing twice. Replay identity is never expired implicitly.
Connection-key rotation is detected through an explicit non-secret epoch and
refuses startup until the caller identity or replay authority is deliberately
retired. The core
admits distinct caller keys and policies and refuses conflicting or concurrent
reuse of one caller/request identity. The backend verifies the exact child binary and
reported Codex home, limits child RPC to authentication, reads API-key or
ChatGPT credentials without publishing their identity, retries one ChatGPT 401
only after the official writer advances the credential store, and lowers raw
SSE into typed text, tool-call, usage, and failure receipts.

No upstream Codex crate is linked into the package. The official binary is a
pinned deployment input, keeping Codex's application build graph outside both
consumers and this small daemon.

Focused verification uses the two real build surfaces:

```text
cargo test --lib
cargo test --lib --features daemon
cargo check --bin codex-connector --features daemon
```

This is not yet a deployable replacement for the live connector. Redacted
CultMesh/Odin publication, shared consumer client cuts, and the independent
Idunn target remain open. The old daemon remains the sole live credential
writer until those proofs land.

## Contract invariant

Each consumer internally derives an exact typed Codex provider request. The
connector verifies and transports those exact bytes and returns a terminal
receipt binding their SHA-256. A consumer-native request digest is carried for
audit correlation; the connector does not interpret or rederive consumer-native
cognition.

Tool choice, parallel-tool policy, provider-safe call IDs, strict tool schemas,
structured-output naming, and the output-token bound are therefore caller-owned
fields. The shared contract renders one deterministic Responses body and
refuses inputs that would require the daemon to rename, project, or repair them.

Tool calls are typed output. The connector never executes them.

The encrypted envelope contains only MessagePack contracts and an AES-256-GCM
payload. Prompt text and results are not visible to the framing layer. The
caller runtime identity remains visible so the daemon can select that caller's
distinct key; the authenticated inner contract repeats the identity and must
match it exactly.
