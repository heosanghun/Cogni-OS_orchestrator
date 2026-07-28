# Durable task ledger

The coordinator creates one immutable-evidence directory per task here.
Runtime inboxes, heartbeats, leases, and transient logs belong in the ignored
`.ensemble-runtime` directory and must never be pushed.
