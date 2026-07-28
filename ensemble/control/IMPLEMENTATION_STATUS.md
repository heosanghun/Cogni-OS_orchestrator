# Four-agent council implementation status

Updated: 2026-07-28 KST

| Component | Status | Evidence |
|---|---|---|
| Local repository | ready | `C:\comunity`, branch `codex/four-agent-local-bus` |
| Roles | ready | three advisors, one Codex App executor |
| Blind advice + cross-critique | ready | `R1_BLIND -> R2_CRITIQUE` |
| Plan vote | ready | two-of-three approval, valid hard stop overrides |
| Single-writer execution gate | ready | only `codex-app` after authorization |
| Post-execution vote | ready | frozen report and two-of-three approval |
| Immutable Markdown ledger | ready | `ensemble/ledger/<task-id>/` |
| Local runtime queues | ready | ignored `.ensemble-runtime/` |
| Stale response rejection | tested | message state version must match |
| Message envelope binding | tested | message/agent/phase/base/outbox are bound |
| Receipt/SHA gate | tested | direct ledger artifacts cannot advance state |
| Junk receipt rejection | tested | exact advisor filenames only |
| Crash-left lock recovery | tested | exclusive-handle stale-lock proof |
| Live lock contention | tested | watcher skips contention and resumes next cycle |
| Timeout behavior | tested | one idempotent retry, then one approval packet |
| Completion/timeout ordering | tested | valid completion is evaluated first |
| Policy invariants | tested | zero quorum/threshold rejected |
| Clean Git execution gate | ready | non-Git/dirty/diverged targets stop once |
| Git/test evidence | tested | changed-file and test-log SHA manifest |
| Integrated approval packet | ready | one `APPROVAL_PACKET.md`, no repeated prompt |
| Normal state-machine test | pass | reaches `READY_TO_COMMIT` |
| Hard-stop test | pass | valid veto reaches `WAITING_HUMAN` |
| Unknown hard-stop test | pass | invalid code becomes `REVISE` |
| External agent adapters | not ready | see `ADAPTER_STATUS.md` |
| Fully unattended 4-agent loop | not running | adapters must pass contract first |
| GitHub branch | published | `origin/codex/four-agent-local-bus` |
| Draft pull request | not created | GitHub integration returned HTTP 403 |

The state machine is functional without touching a product repository. No
System1.5 training, deployment, external message, or GitHub remote mutation was
started as part of these self-tests.
