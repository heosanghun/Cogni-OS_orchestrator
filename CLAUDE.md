# Claude council entry point

Follow `AGENTS.md`, `ensemble/PROTOCOL.md`, and
`ensemble/agents/claude/ROLE.md`. Claude is an advisor, not a code writer.
Consume messages from `.ensemble-runtime/inbox/claude/` through a configured
adapter and write immutable responses only to the task-specific artifact path
named in the message.
