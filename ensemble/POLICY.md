# Automation policy

## Allowed without another prompt

The council may autonomously perform local, reversible, scoped actions:

- read repositories and existing evidence;
- create task-owned Markdown and runtime messages;
- edit files only in the declared target workspace after advisor approval;
- run predeclared tests and read-only diagnostics;
- create an isolated local task branch or worktree;
- create a local commit after post-review.

Executable product work requires a clean Git target with a frozen base commit.
Non-Git targets may be analyzed read-only but are not automatically executed
because rollback and diff provenance cannot be guaranteed.

## Always stop once for human review

The coordinator must aggregate scope, diff, risk, tests, and rollback into one
approval packet and enter `WAITING_HUMAN` for:

- credentials, secrets, authentication, permissions, billing, or paid APIs;
- external messages, deployment, release, publication, scientific headline
  claims, main merge, or public PR readiness;
- destructive deletion, database migration, history rewrite, force push, or
  irreversible state;
- private/regulated data, unresolved license questions, or supply-chain
  dependency changes;
- a dirty/diverged target whose changes cannot be isolated safely;
- changed goals, ambiguous completion criteria, exhausted repair budgets, or
  missing advisor quorum;
- missing supported unattended adapter for an agent required by the task.

The council must not repeatedly open permission dialogs. It either acts inside
this policy or emits one consolidated packet and waits.

## Hard-stop codes

```text
NONE
SECRET_OR_PII
POLICY_VIOLATION
FORBIDDEN_GPU
DESTRUCTIVE
EXTERNAL_SIDE_EFFECT
STATE_CORRUPT
DIRTY_BASE_CONFLICT
LICENSE_RISK
INTEGRITY_FAILURE
ADAPTER_UNAVAILABLE
```

A non-`NONE` hard stop must cite evidence. Invalid or unsupported hard-stop
text is treated as `REVISE`, not as a way to seize control.

## System1.5 GPU policy

For `C:\Project\System1.5` on Quadro-Ampere-05:

- query physical GPUs 0 through 3 only;
- compute only on GPU 0 or 1 after preflight;
- GPU 2 is query-only and GPU 3 is externally occupied;
- never allocate, query, signal, or change GPUs 4 through 7;
- never signal a process not created by the current coordinator task;
- long training requires a versioned run ID, output namespace, and explicit
  runtime/disk/GPU budget in the frozen brief.

Any forbidden GPU in a command or configuration is an immediate hard stop, not
a matter for voting.
