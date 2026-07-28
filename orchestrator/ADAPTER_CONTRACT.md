# Agent adapter contract

Markdown queues do not wake desktop applications by themselves. The
coordinator may start unattended operation only after each agent has a
supported non-interactive CLI/API adapter that passes this contract.

## Required lifecycle

```text
probe -> submit -> poll -> collect
                  \-> cancel
```

`probe` returns `ready`, `missing`, `auth_required`, or `unusable`, plus the
actual executable, version, and capabilities. It must not install software,
open a login browser, or request permissions. `FOUND_UNVERIFIED` is not ready.

`submit` accepts a task envelope and returns a native handle. `poll` returns
`queued`, `running`, `completed`, `failed`, or `timed_out`. `collect`
normalizes native output and validates task ID, state version, base commit,
input hashes, result schema, and output hash. `cancel` may stop only a process
created by that adapter.

## Invocation model

- Use one-shot, non-interactive workers. The coordinator is the only daemon.
- Advisors receive read-only tools and frozen snapshots.
- The executor receives write access only to its isolated task worktree after
  `EXECUTION_AUTHORIZED`.
- Never use unrestricted/yolo flags.
- Never parse private GUI transcript formats as a stable API.
- Antigravity or any asynchronous bridge must write a result plus a `DONE`
  sentinel; process creation alone is not completion.
- Retry the same idempotency key once, then record `ABSTAIN` or
  `ADAPTER_UNAVAILABLE`. Do not repeatedly open approval dialogs.

## Envelope fields

Every invocation must bind:

```json
{
  "schema_version": 1,
  "task_id": "TASK-...",
  "message_id": "...",
  "idempotency_key": "task/phase/agent/version",
  "state_version": 4,
  "agent_id": "cursor",
  "role": "advisor",
  "phase": "PLAN_REVIEW",
  "base_commit": "...",
  "workspace": "C:\\isolated-worktree",
  "inputs": [
    {"path": "...", "sha256": "..."}
  ],
  "policy": {
    "read_only": true,
    "git_push": false,
    "network": false,
    "deadline_utc": "..."
  },
  "output_path": "..."
}
```

The normalized result must include status, summary, recommendation/vote,
confidence, evidence-linked claims, risks, blocking reasons, files read and
changed, tests, model/adapter identity, timestamps, and narrative Markdown.

## Windows durability rules

- Poll the full queue every 2–5 seconds. A file-system watcher may accelerate
  delivery but is not the source of truth because events can be lost.
- Write `*.partial`, flush, and rename on the same NTFS volume.
- Use UTF-8 without BOM; Windows PowerShell 5.1 `Out-File` defaults are unsafe
  for this contract.
- Claim work with an atomic lease and an idempotency key.
- Bind collection to the coordinator-issued message ID, exact agent, state
  version, base commit, outbox path, and durable artifact path.
- Never modify an existing message. A correction is a new file with
  `supersedes`.
- Move invalid, stale, or exhausted messages to `dead-letter`; do not merge
  them into current state.

## Bootstrap truth

`orchestrator\ensemble.ps1 probe` intentionally reports only discovery. A
separate non-interactive authentication and schema-output test is required for
each installed tool. If even one required advisor lacks a supported adapter,
the system remains a prepared local council, not a fully autonomous council.

When every process runs as the same Windows user, file ownership and message
binding prevent accidents but are not a hostile security boundary. Strong
identity isolation requires separate OS accounts, containers, or another
adapter-level authentication boundary.
