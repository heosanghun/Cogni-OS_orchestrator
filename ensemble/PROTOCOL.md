# Council protocol

## Why local-first

GitHub-only conversation adds polling delay, commit noise, public-data risk,
and push/pull conflicts. A shared local control plane provides low-latency
coordination, while GitHub remains the durable audit and review boundary.

## State flow

```text
R1_BLIND
  -> R2_CRITIQUE
  -> EXECUTOR_PLAN_OPEN
  -> PLAN_REVIEW_OPEN
  -> EXECUTION_AUTHORIZED
  -> POST_REVIEW_OPEN
  -> READY_TO_COMMIT
```

Exceptional terminal states are `WAITING_HUMAN` and `SAFE_STOP`.

1. **R1_BLIND**: the three advisors independently assess the frozen brief.
2. **R2_CRITIQUE**: each advisor reads all first-round voices and challenges
   assumptions, evidence, and risks.
3. **EXECUTOR_PLAN_OPEN**: the executor synthesizes one bounded plan.
4. **PLAN_REVIEW_OPEN**: advisors vote independently. Two approvals and no hard
   stop authorize execution.
5. **EXECUTION_AUTHORIZED**: only the executor edits the declared target and
   records a diff/test report.
6. **POST_REVIEW_OPEN**: advisors inspect the frozen diff and test evidence.
7. **READY_TO_COMMIT**: two approvals, zero hard stops, and passing required
   tests allow a local checkpoint. Push/PR/merge are separate policy gates.

## File ownership

Each voice owns one immutable file:

```text
ensemble/ledger/<task-id>/
  BRIEF.md
  STATE.json
  ADVICE_R1/<agent>.md
  CRITIQUE_R2/<agent>.md
  plans/EXECUTOR_PLAN_v001.md
  plan-reviews/<agent>_v001.md
  implementation/REPORT_v001.md
  post-reviews/<agent>_v001.md
  DECISION.md
  MINORITY_REPORT.md
  events.jsonl
```

The coordinator is the only writer for `STATE.json`, `events.jsonl`, queue
files, and locks. Advisors write only their named voice files. The executor
writes only plan/implementation artifacts and allowed target files.

## Decision and retry rules

- Advisor threshold: two of three `APPROVE` votes.
- A valid hard stop always blocks a majority.
- Blind advice and critique happen once per task.
- Plan revisions and implementation repairs share a maximum of three cycles.
- The same failure signature twice, an A-to-B-to-A decision loop, a repeated
  diff hash, or budget exhaustion moves the task to `SAFE_STOP`.
- A timed-out advisor may be retried once with the same idempotency key, then
  recorded as `ABSTAIN`; silent infinite waiting is forbidden.
- An executor is never silently replaced by an advisor.

## GitHub checkpoint policy

- Do not commit every message.
- Do not push directly to `main` and never force-push.
- Freeze one candidate commit and have advisors review that exact SHA.
- Push only reviewed milestones to a task branch, then create a draft PR.
- If the remote base changed, preserve local evidence and enter
  `WAITING_HUMAN`; do not auto-rebase or overwrite.
