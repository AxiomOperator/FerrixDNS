CREATE TABLE users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);

-- Only a hash of the session token is stored, so reading this table doesn't reveal live sessions.
CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL
);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at_ms);

-- Fetch state for downloaded lists. The enforced content is pinned by the policy revision.
CREATE TABLE list_status (
  list_id TEXT PRIMARY KEY,
  etag TEXT,
  last_modified TEXT,
  last_checked_at_ms INTEGER,
  last_success_at_ms INTEGER,
  last_error TEXT,
  entry_count INTEGER NOT NULL DEFAULT 0,
  invalid_line_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE local_audit_events (
  id TEXT PRIMARY KEY,
  occurred_at_ms INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  details_json TEXT NOT NULL
);
CREATE INDEX idx_audit_time ON local_audit_events(occurred_at_ms DESC);
