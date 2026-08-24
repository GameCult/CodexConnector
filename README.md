# CodexConnector

CodexConnector is a credential-isolated transport daemon for Codex-compatible
subscription inference. Epiphany and Ghostlight remain separate minds. They
derive their own exact provider requests, execute their own tools, interpret
their own results, and admit their own state.

The connector owns one writable credential/refresh store, authenticated caller
admission, bounded transport physiology, exact provider-request receipts, and
redacted CultMesh health. It owns no prompt policy or decision authority.

The current source establishes the v2 typed contract and its transport-neutral
service core before adding the daemon shell. The core admits distinct caller
keys and policies, returns an exact cached response for byte-identical retries,
refuses conflicting or concurrent reuse of one caller/request identity, and
leaves provider execution outside its lock. The existing Yggdrasil connector
already proves the process seam, but its single-caller, fixed-model, stateless,
no-tools wire law cannot become the shared contract by inertia.

## Contract invariant

Each consumer internally derives an exact typed Codex provider request. The
connector verifies and transports those exact bytes and returns a terminal
receipt binding their SHA-256. A consumer-native request digest is carried for
audit correlation; the connector does not interpret or rederive consumer-native
cognition.

Tool calls are typed output. The connector never executes them.

The encrypted envelope contains only MessagePack contracts and an AES-256-GCM
payload. Prompt text and results are not visible to the framing layer. The
caller runtime identity remains visible so the daemon can select that caller's
distinct key; the authenticated inner contract repeats the identity and must
match it exactly.
