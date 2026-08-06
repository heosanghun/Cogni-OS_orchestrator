CREATE TABLE IF NOT EXISTS monitor_schema_floors (
  workspace_id TEXT PRIMARY KEY,
  minimum_schema_rank INTEGER NOT NULL
    CHECK (minimum_schema_rank BETWEEN 100 AND 199),
  minimum_schema_version TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
