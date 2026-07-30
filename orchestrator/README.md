# Coordinator

`ensemble.ps1` is a deterministic PowerShell 5.1 coordinator. It owns task
state, immutable artifact promotion, queueing, vote tallies, and bounded state
transitions. It does not call an LLM or perform GitHub writes.

## Commands

```powershell
.\orchestrator\ensemble.ps1 init
.\orchestrator\ensemble.ps1 probe
.\orchestrator\ensemble.ps1 new-task -Title "..." -Goal "..." `
  -TargetWorkspace "C:\clean-worktree"
.\orchestrator\ensemble.ps1 status
.\orchestrator\ensemble.ps1 queue -Agent claude
.\orchestrator\ensemble.ps1 submit -TaskId TASK-... -Agent claude `
  -Phase r1 -MessageId <message-id-from-envelope> `
  -MessageStateVersion 1 `
  -InputFile C:\comunity\.ensemble-runtime\outbox\claude\<message-id>.md
.\orchestrator\ensemble.ps1 advance -TaskId TASK-...
```

The watcher is a polling accelerator:

```powershell
.\orchestrator\watch.ps1 -PollSeconds 5
```

Do not start it as an unattended service until all four adapters pass
`ADAPTER_CONTRACT.md`. The included self-test exercises the state machine with
synthetic files and does not call external models.

For a desktop UI smoke loop, `room.ps1` safely selects only messages that
still have a coordinator-owned pending envelope:

```powershell
.\orchestrator\room.ps1 next -Agent cursor
.\orchestrator\room.ps1 wait -Agent cursor -TimeoutSeconds 600
.\orchestrator\room.ps1 submit -Agent cursor `
  -MessagePath <ROOM_MESSAGE_PATH>
```

This helper does not invoke or wake a model. See `START_HERE_KO.md` for the
four copy-paste UI prompts and the distinction between manual and unattended
operation.

## Antigravity + Codex pair workbench

`pair.ps1` and `pair-sidecar.ps1` provide a separate, reduced-assurance,
read-only planning loop. It is not a shortcut around the four-agent quorum.

```powershell
$taskId = (
  .\orchestrator\pair.ps1 new-task `
    -Title "Read-only evidence review" `
    -Goal "Verify evidence and propose bounded next tests." `
    -TargetWorkspace C:\Project\System1.5
).Trim()

.\orchestrator\pair.ps1 status -TaskId $taskId
.\orchestrator\pair.ps1 stop -TaskId $taskId -Reason "Operator stop"
```

The local sidecar allowlist contains both active product workspaces:
`C:\Project\System1.5` and `C:\Project\CTS`.  A task must still name exactly
one target and all adapter calls remain read-only.

The Antigravity sidecar manifest explicitly pins the real
`language_server.exe`, Codex, Git, and `pair-process-runner.ps1` by absolute
path and SHA-256. Every local adapter invocation runs below a gated Windows Job
Object with a wall-clock timeout and write-once, hash-sidecar invocation
evidence. This contains the Codex process tree and local adapter runner/CLI
processes. Antigravity
`agentapi` dispatches server-side generation asynchronously and exposes no
public cancel command, so stop/timeout revokes result acceptance instead of
claiming to cancel that server-side generation. The Codex subprocess uses
`approval_policy="never"` and the `read-only` sandbox.
Because the public API also lacks a completion signal, production requires the
broker-observed response/DONE hashes and sizes to match across at least two
reconciliations and 30 seconds before quarantining a round. Producer-controlled
filesystem timestamps are not trusted.

Antigravity runs in a dedicated project whose only write scope is
`.ensemble-runtime\pair-agent-outbox`. Completed R1/R2 directories are moved
atomically into the broker-only task import area, revalidated, and copied to
canonical task artifacts. Antigravity cannot write the product workspace,
STATE, locks, prompts, attempts, broker evidence, orchestrator, or tests.
Each accepted round is bound by a tamper-evident broker-owned seal. Every later
reconciliation, including a terminal candidate check, rejects and quarantines
any writable R1/R2 path that reappears after acceptance.
The final candidate, its DONE sentinel, and the Codex R1 inputs are bound by a
separate candidate seal and revalidated on terminal reconciliation. Raw import
files and SAFE_STOP evidence are likewise rehashed instead of being trusted by
path existence alone.

New tasks use schema v6 durable `RUNNING_*` phases. If a broker crashes across
an external-call boundary, the Job closes, its process tree is terminated, and
the same namespace is not replayed. The next reconciliation records
`PAIR_SAFE_STOP`; a recovery requires a new task ID. See
`PAIR_FAST_START_KO.md` for the operator guide and assurance limits.

For a real adapter, `InputFile` must be the exact `output_path` assigned in the
message envelope. The coordinator binds message ID, agent, phase, state
version, base commit, outbox path, and durable artifact path before promotion.

Implementation reports additionally require:

```text
tests: PASS
test_log_path: C:\absolute\path\inside\task-or-target.log
test_log_sha256: <64 lowercase hex characters>
```

The log must contain `result: PASS` and `exit_code: 0`. The coordinator hashes
the log and Git working-tree entries independently into
`implementation/EVIDENCE_vNNN.json` plus a SHA256 sidecar.
