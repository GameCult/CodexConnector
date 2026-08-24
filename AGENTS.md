# CodexConnector Instructions

CodexConnector is the independent credential and transport boundary for
Codex-compatible subscription inference. It is not an agent, scheduler, prompt
owner, tool executor, decision store, or consumer runtime.

Keep one Cargo package and one production daemon entrypoint. Add another target
only when an independent lifecycle or privilege invariant requires it.

The daemon may own credential loading and refresh, upstream client identity,
authenticated caller admission, bounded concurrency/replay, provider transport,
typed events, and transport receipts. Consumers own native requests, provider
lowering, prompts, schemas, tool execution, retry between passes, interpretation,
decisions, and state admission.

Use typed Rust contracts, CultCache state, CultNet transport, and CultMesh/Eve
projection. JSON is permitted only at the upstream provider boundary or for
published schemas. Never log credentials, prompts, model output, or decrypted
request cargo.

Before broad compilation, name the exact package/target/profile, output root,
current footprint, and retention decision. Focused library checks and tests are
the default. Code and tests must buy consequential behavior; delete mirrors,
wrappers, compatibility paths, and self-certifying status surfaces.

