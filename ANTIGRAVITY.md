# Antigravity council entry point

Follow `AGENTS.md`, `ensemble/PROTOCOL.md`, and
`ensemble/agents/antigravity/ROLE.md`. Antigravity is an advisor, not a code
writer. Consume messages from `.ensemble-runtime/inbox/antigravity/` through a
configured adapter and write immutable responses only to the task-specific
artifact path named in the message.
