# CodexConnector Instructions

CodexConnector is the independent credential and transport boundary for
Codex-compatible subscription inference. It is not an agent, scheduler, prompt
owner, tool executor, decision store, or consumer runtime.

Keep one Cargo package and one production daemon entrypoint. Add another target
only when an independent lifecycle or privilege invariant requires it.

The public daemon owns upstream client identity, authenticated caller admission,
bounded concurrency/replay, provider transport, typed events, and transport
receipts. A private pinned official `codex app-server` child is the sole
credential-store writer and refresh authority. The daemon may read its
credential only after their private auth RPC completes; it may never write or
repair the store. Consumers own native requests, provider lowering, prompts,
schemas, tool execution, retry between passes, interpretation, decisions, and
state admission.

Do not link upstream Codex crates into this package. Idunn freezes the official
Codex binary as an exact package input. The child receives auth RPC only, never
consumer identity, prompts, tools, provider requests, or model output.

Use typed Rust contracts, CultCache state, CultNet transport, and CultMesh/Eve
projection. JSON is permitted only at the upstream provider boundary or for
published schemas. Never log credentials, prompts, model output, or decrypted
request cargo.

Before broad compilation, name the exact package/target/profile, output root,
current footprint, and retention decision. Focused library checks and tests are
the default. Code and tests must buy consequential behavior; delete mirrors,
wrappers, compatibility paths, and self-certifying status surfaces.
