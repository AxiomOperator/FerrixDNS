CREATE TABLE telemetry_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- client_key is the client ID, or its address when unknown, or empty when anonymized.
CREATE TABLE query_rollups_1m (
  bucket_start_ms INTEGER NOT NULL,
  client_key TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL,
  qtype TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  latency_sum_us INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket_start_ms, client_key, outcome, qtype)
);
