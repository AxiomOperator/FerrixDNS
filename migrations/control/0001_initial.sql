CREATE TABLE sites (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at_ms INTEGER NOT NULL,
  -- Deploys changed list downloads by itself, without waiting for someone to press Deploy.
  auto_deploy_lists INTEGER NOT NULL DEFAULT 1,
  next_generation INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE nodes (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id),
  name TEXT NOT NULL,
  public_key TEXT NOT NULL UNIQUE,
  enrolled_at_ms INTEGER NOT NULL,
  last_seen_ms INTEGER,
  version TEXT NOT NULL DEFAULT '',
  applied_generation INTEGER NOT NULL DEFAULT 0,
  policy_revision TEXT NOT NULL DEFAULT '',
  report_json TEXT NOT NULL DEFAULT '{}',
  rollups_stored_through_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX nodes_site ON nodes(site_id);

CREATE TABLE enrollment_tokens (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  secret_hash TEXT NOT NULL UNIQUE,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  used_at_ms INTEGER,
  used_by_node TEXT
);

CREATE TABLE bundles (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  manifest TEXT NOT NULL,
  signature TEXT NOT NULL,
  policy_sha256 TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  UNIQUE (site_id, generation)
);

-- Which stored files each bundle may hand out, so a node can only fetch what its site was given.
CREATE TABLE bundle_files (
  bundle_id TEXT NOT NULL REFERENCES bundles(id) ON DELETE CASCADE,
  sha256 TEXT NOT NULL,
  PRIMARY KEY (bundle_id, sha256)
);
CREATE INDEX bundle_files_sha256 ON bundle_files(sha256);

CREATE TABLE deployments (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  bundle_id TEXT NOT NULL REFERENCES bundles(id) ON DELETE CASCADE,
  generation INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('policy', 'list_refresh', 'rollback')),
  strategy TEXT NOT NULL CHECK (strategy IN ('all', 'canary')),
  canary_node_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('canary', 'rolling_out', 'succeeded', 'partially_failed', 'failed', 'superseded')),
  reason TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  rollback_of TEXT
);
CREATE INDEX deployments_site ON deployments(site_id, generation);

CREATE TABLE deployment_nodes (
  deployment_id TEXT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
  node_id TEXT NOT NULL,
  state TEXT NOT NULL,
  detail TEXT,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (deployment_id, node_id)
);

-- Counts only. Query names and client addresses stay on each node.
CREATE TABLE node_rollups (
  node_id TEXT NOT NULL,
  bucket_start_ms INTEGER NOT NULL,
  outcome TEXT NOT NULL,
  count INTEGER NOT NULL,
  latency_sum_us INTEGER NOT NULL,
  PRIMARY KEY (node_id, bucket_start_ms, outcome)
);
CREATE INDEX node_rollups_bucket ON node_rollups(bucket_start_ms);
