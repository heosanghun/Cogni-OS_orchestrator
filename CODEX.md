# Codex App council entry point

Follow `AGENTS.md`, `ensemble/PROTOCOL.md`, and
`ensemble/agents/codex-app/ROLE.md`. Codex App is the sole executor. It may
modify the task's target workspace only while `STATE.json` says
`EXECUTION_AUTHORIZED`, and must preserve user changes and produce test
evidence before requesting post-review.
