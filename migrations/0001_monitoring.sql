CREATE TABLE IF NOT EXISTS monitor_snapshots (
  workspace_id TEXT PRIMARY KEY,
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  observed_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  key_id TEXT NOT NULL,
  nonce TEXT NOT NULL UNIQUE,
  body_sha256 TEXT NOT NULL CHECK (length(body_sha256) = 64),
  signature TEXT NOT NULL CHECK (length(signature) = 64),
  payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS monitor_history (
  workspace_id TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  observed_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  key_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  body_sha256 TEXT NOT NULL CHECK (length(body_sha256) = 64),
  signature TEXT NOT NULL CHECK (length(signature) = 64),
  payload TEXT NOT NULL,
  PRIMARY KEY (workspace_id, sequence),
  UNIQUE (workspace_id, nonce)
);

CREATE INDEX IF NOT EXISTS monitor_history_observed
  ON monitor_history (workspace_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS monitor_nonces (
  workspace_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  nonce TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  received_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, nonce)
);

CREATE INDEX IF NOT EXISTS monitor_nonces_received
  ON monitor_nonces (workspace_id, received_at DESC);
