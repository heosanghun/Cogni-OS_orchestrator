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
