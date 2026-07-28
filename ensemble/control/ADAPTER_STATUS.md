# Adapter readiness snapshot

Captured locally on 2026-07-28 KST without installation, login, or permission
changes:

| Agent | Local command status | Unattended adapter |
|---|---|---|
| Codex App | packaged `codex.exe` discovered, direct `--version` is access denied | not ready |
| Cursor | `cursor-agent` not found on `PATH` | not ready |
| Claude | `claude` not found on `PATH` | not ready |
| Antigravity | `agy`, `agentapi`, and `antigravity` not found on `PATH` | not ready |

This means the local council, queue, roles, and deterministic state machine are
implemented, but a genuine four-way unattended loop is not yet running.
Desktop GUI presence is not equivalent to a supported headless adapter.

Do not imitate a missing agent with another model or fragile screen/clipboard
automation. Connect and verify each product's supported non-interactive
CLI/API, then record a new versioned readiness snapshot.
