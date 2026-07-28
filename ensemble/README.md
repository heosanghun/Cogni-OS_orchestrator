# Local-first four-agent development council

This directory is the Git-tracked, human-readable record for a council made of
three advisors and one executor:

| Agent | Function | Product-code write access |
|---|---|---:|
| Antigravity | architecture and alternatives | no |
| Cursor | implementation structure and regression risk | no |
| Claude | adversarial review, safety, and reproducibility | no |
| Codex App | plan synthesis, implementation, and tests | yes, after gate |

The recommended topology is hybrid:

- local files under `C:\comunity` carry active messages and state quickly;
- GitHub stores reviewed checkpoints, minority reports, and optional draft PRs;
- only the coordinator/executor Git identity writes remote checkpoints;
- the four models do not independently push and pull every conversational turn.

`monitoring_project` is a control plane, not the product source tree. Every task
must identify a separate `target_workspace` when the code lives elsewhere
(for example `C:\Project\System1.5`).

## Start here

```powershell
# Initialize ignored runtime folders.
powershell -ExecutionPolicy Bypass -File .\orchestrator\ensemble.ps1 init

# Create a task. This queues blind advice for the three advisors.
powershell -ExecutionPolicy Bypass -File .\orchestrator\ensemble.ps1 new-task `
  -Title "Short task title" `
  -Goal "Machine-checkable goal and completion tests" `
  -TargetWorkspace "C:\Project\System1.5"

# Inspect tasks and inboxes.
powershell -ExecutionPolicy Bypass -File .\orchestrator\ensemble.ps1 status
powershell -ExecutionPolicy Bypass -File .\orchestrator\ensemble.ps1 queue `
  -Agent antigravity
```

The coordinator does not invent unsupported automation. An installed,
non-interactive CLI/API adapter is required to wake each desktop agent. Until
an adapter passes the contract in `orchestrator/ADAPTER_CONTRACT.md`, that
agent remains manual and a fully unattended four-agent loop is not claimed.
