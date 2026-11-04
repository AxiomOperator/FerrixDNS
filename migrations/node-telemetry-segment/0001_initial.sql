CREATE TABLE query_events (
  seq INTEGER PRIMARY KEY,
  occurred_at_ms INTEGER NOT NULL,
  client_id TEXT,
  client_ip TEXT,
  qname TEXT,
  matched_name TEXT,
  qtype TEXT NOT NULL,
  outcome TEXT NOT NULL,
  rcode TEXT NOT NULL,
  rule_id TEXT,
  source_list_id TEXT,
  upstream TEXT,
  duration_us INTEGER NOT NULL,
  revision_id TEXT
);
CREATE INDEX idx_query_client ON query_events(client_id, seq DESC);
CREATE INDEX idx_query_name ON query_events(qname, seq DESC);
CREATE INDEX idx_query_time ON query_events(occurred_at_ms DESC);
