# Council run modes

## PREPARED_MANUAL

Roles, queues, coordinator, ledger, and copy-paste prompts exist. One or more
agents require a person to start a GUI turn or relay a message.

This is the current mode as of 2026-07-29. There is no active task.

## LIVE_GUI_LOOP

All four active UI sessions can directly read `C:\comunity`, write only their
assigned outbox, run `room.ps1 submit`, and remain active while waiting for the
next phase. This can demonstrate the council but is not a durable unattended
service. A stopped chat, sleeping machine, context timeout, or product update
can break the loop.

## FULLY_UNATTENDED

Every required agent has a supported CLI/API/Sidecar/Scheduled adapter that
passes `orchestrator\ADAPTER_CONTRACT.md`, including authentication,
idempotency, stale-message rejection, output schema, cancellation, and
atomic result collection.

The coordinator must not report this mode while any required adapter is
missing or unusable.
