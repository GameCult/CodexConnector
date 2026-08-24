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

The current source establishes the v2 typed contract, its transport-neutral
service core, the private Codex-auth/provider backend, and one public daemon
entrypoint. The daemon reads one typed CultCache configuration document, binds
only loopback, uses CultNet's four-byte big-endian direct-pipe framing around
the encrypted MessagePack envelope, bounds connection threads and frame sizes,
and keeps provider execution outside the service-state lock. The core admits
distinct caller keys and policies,
returns an exact cached response for byte-identical retries, refuses conflicting
or concurrent reuse of one caller/request identity, and leaves provider
execution outside its lock. The backend verifies the exact child binary and
reported Codex home, limits child RPC to authentication, reads API-key or
ChatGPT credentials without publishing their identity, retries one ChatGPT 401
only after the official writer advances the credential store, and lowers raw
SSE into typed text, tool-call, usage, and failure receipts.

No upstream Codex crate is linked into the package. The official binary is a
pinned deployment input, keeping Codex's application build graph outside both
consumers and this small daemon.

This is not yet a deployable replacement for the live connector. Persistent
replay recovery, redacted CultMesh/Odin publication, shared consumer client
cuts, and the independent Idunn target remain open. The old daemon remains the
sole live credential writer until those proofs land.

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
