//! The controller's database: sites, nodes, tokens, bundles, deployments and fleet counts.

use std::path::Path;
use std::time::Duration;

use fleet_contract::RollupRow;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
};
use sqlx::{Row, SqlitePool};

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations/control");

/// A node that hasn't reported for this long is shown as offline.
pub const OFFLINE_AFTER_MS: i64 = 60_000;
/// How long fleet counts are kept.
const ROLLUP_RETENTION_MS: i64 = 90 * 24 * 60 * 60 * 1000;

#[derive(Clone, Debug)]
pub struct Site {
    pub id: String,
    pub name: String,
    pub created_at_ms: i64,
    pub auto_deploy_lists: bool,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub id: String,
    pub site_id: String,
    pub name: String,
    pub public_key: String,
    pub enrolled_at_ms: i64,
    pub last_seen_ms: Option<i64>,
    pub version: String,
    pub applied_generation: u64,
    pub policy_revision: String,
    pub report_json: String,
    pub rollups_stored_through_ms: i64,
}

#[derive(Clone, Debug)]
pub struct Bundle {
    pub site_id: String,
    pub manifest: String,
    pub signature: String,
    pub policy_sha256: String,
}

#[derive(Clone, Debug)]
pub struct Deployment {
    pub id: String,
    pub site_id: String,
    pub bundle_id: String,
    pub generation: u64,
    pub kind: String,
    pub strategy: String,
    pub canary_node_id: Option<String>,
    pub status: String,
    pub reason: String,
    pub created_by: String,
    pub created_at_ms: i64,
    pub rollback_of: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NodeProgress {
    pub node_id: String,
    pub state: String,
    pub detail: Option<String>,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug)]
pub struct PendingToken {
    pub id: String,
    pub site_id: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub created_by: String,
}

/// What the next deployment needs, stored as one step.
pub struct NewDeployment<'a> {
    pub site_id: &'a str,
    pub bundle_id: &'a str,
    pub manifest: &'a str,
    pub signature: &'a str,
    pub policy_sha256: &'a str,
    pub files: &'a [String],
    pub generation: u64,
    pub created_at_ms: i64,
    pub deployment_id: &'a str,
    pub kind: &'a str,
    pub strategy: &'a str,
    pub canary_node_id: Option<&'a str>,
    pub reason: &'a str,
    pub created_by: &'a str,
    pub rollback_of: Option<&'a str>,
}

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

fn generation_of(row: &SqliteRow, column: &str) -> Result<u64, sqlx::Error> {
    Ok(u64::try_from(row.try_get::<i64, _>(column)?).unwrap_or(0))
}

fn site(row: &SqliteRow) -> Result<Site, sqlx::Error> {
    Ok(Site {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        created_at_ms: row.try_get("created_at_ms")?,
        auto_deploy_lists: row.try_get("auto_deploy_lists")?,
    })
}

fn node(row: &SqliteRow) -> Result<Node, sqlx::Error> {
    Ok(Node {
        id: row.try_get("id")?,
        site_id: row.try_get("site_id")?,
        name: row.try_get("name")?,
        public_key: row.try_get("public_key")?,
        enrolled_at_ms: row.try_get("enrolled_at_ms")?,
        last_seen_ms: row.try_get("last_seen_ms")?,
        version: row.try_get("version")?,
        applied_generation: generation_of(row, "applied_generation")?,
        policy_revision: row.try_get("policy_revision")?,
        report_json: row.try_get("report_json")?,
        rollups_stored_through_ms: row.try_get("rollups_stored_through_ms")?,
    })
}

fn bundle(row: &SqliteRow) -> Result<Bundle, sqlx::Error> {
    Ok(Bundle {
        site_id: row.try_get("site_id")?,
        manifest: row.try_get("manifest")?,
        signature: row.try_get("signature")?,
        policy_sha256: row.try_get("policy_sha256")?,
    })
}

fn deployment(row: &SqliteRow) -> Result<Deployment, sqlx::Error> {
    Ok(Deployment {
        id: row.try_get("id")?,
        site_id: row.try_get("site_id")?,
        bundle_id: row.try_get("bundle_id")?,
        generation: generation_of(row, "generation")?,
        kind: row.try_get("kind")?,
        strategy: row.try_get("strategy")?,
        canary_node_id: row.try_get("canary_node_id")?,
        status: row.try_get("status")?,
        reason: row.try_get("reason")?,
        created_by: row.try_get("created_by")?,
        created_at_ms: row.try_get("created_at_ms")?,
        rollback_of: row.try_get("rollback_of")?,
    })
}

impl Store {
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    // --- Sites ---

    pub async fn create_site(&self, site: &Site) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO sites (id, name, created_at_ms, auto_deploy_lists) VALUES (?, ?, ?, ?)",
        )
        .bind(&site.id)
        .bind(&site.name)
        .bind(site.created_at_ms)
        .bind(site.auto_deploy_lists)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn sites(&self) -> Result<Vec<Site>, sqlx::Error> {
        sqlx::query("SELECT * FROM sites ORDER BY name")
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(site)
            .collect()
    }

    pub async fn site(&self, id: &str) -> Result<Option<Site>, sqlx::Error> {
        sqlx::query("SELECT * FROM sites WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(site)
            .transpose()
    }

    pub async fn update_site(
        &self,
        id: &str,
        name: &str,
        auto_deploy_lists: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE sites SET name = ?, auto_deploy_lists = ? WHERE id = ?")
            .bind(name)
            .bind(auto_deploy_lists)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Removes a site and everything that only it uses. The caller checks it has no nodes.
    pub async fn delete_site(&self, id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM sites WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // --- Enrollment ---

    pub async fn create_token(
        &self,
        token: &PendingToken,
        secret_hash: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO enrollment_tokens \
             (id, site_id, secret_hash, created_at_ms, expires_at_ms, created_by) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&token.id)
        .bind(&token.site_id)
        .bind(secret_hash)
        .bind(token.created_at_ms)
        .bind(token.expires_at_ms)
        .bind(&token.created_by)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn pending_tokens(&self, now_ms: i64) -> Result<Vec<PendingToken>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT id, site_id, created_at_ms, expires_at_ms, created_by FROM enrollment_tokens \
             WHERE used_at_ms IS NULL AND expires_at_ms > ? ORDER BY created_at_ms DESC",
        )
        .bind(now_ms)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(PendingToken {
                    id: row.try_get("id")?,
                    site_id: row.try_get("site_id")?,
                    created_at_ms: row.try_get("created_at_ms")?,
                    expires_at_ms: row.try_get("expires_at_ms")?,
                    created_by: row.try_get("created_by")?,
                })
            })
            .collect()
    }

    pub async fn delete_token(&self, id: &str) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("DELETE FROM enrollment_tokens WHERE id = ? AND used_at_ms IS NULL")
                .bind(id)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Spends a token and adds its node in one step, so a token can never work twice, even when
    /// two nodes present it at the same moment. Returns the site, if the token was good.
    pub async fn enroll(
        &self,
        secret_hash: &str,
        now_ms: i64,
        node: &Node,
    ) -> Result<Option<String>, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let site_id: Option<String> = sqlx::query(
            "UPDATE enrollment_tokens SET used_at_ms = ?, used_by_node = ? \
             WHERE secret_hash = ? AND used_at_ms IS NULL AND expires_at_ms > ? RETURNING site_id",
        )
        .bind(now_ms)
        .bind(&node.id)
        .bind(secret_hash)
        .bind(now_ms)
        .fetch_optional(&mut *transaction)
        .await?
        .map(|row| row.try_get("site_id"))
        .transpose()?;
        let Some(site_id) = site_id else {
            return Ok(None);
        };
        sqlx::query(
            "INSERT INTO nodes (id, site_id, name, public_key, enrolled_at_ms, version) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&node.id)
        .bind(&site_id)
        .bind(&node.name)
        .bind(&node.public_key)
        .bind(now_ms)
        .bind(&node.version)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(Some(site_id))
    }

    // --- Nodes ---

    pub async fn node(&self, id: &str) -> Result<Option<Node>, sqlx::Error> {
        sqlx::query("SELECT * FROM nodes WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(node)
            .transpose()
    }

    pub async fn nodes(&self) -> Result<Vec<Node>, sqlx::Error> {
        sqlx::query("SELECT * FROM nodes ORDER BY name, id")
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(node)
            .collect()
    }

    pub async fn site_nodes(&self, site_id: &str) -> Result<Vec<Node>, sqlx::Error> {
        sqlx::query("SELECT * FROM nodes WHERE site_id = ? ORDER BY enrolled_at_ms, id")
            .bind(site_id)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(node)
            .collect()
    }

    pub async fn rename_node(&self, id: &str, name: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE nodes SET name = ? WHERE id = ?")
            .bind(name)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Notes what a node has just applied, without waiting for its next report.
    pub async fn note_applied_generation(
        &self,
        id: &str,
        generation: u64,
        policy_revision: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE nodes SET applied_generation = MAX(applied_generation, ?), \
             policy_revision = COALESCE(?, policy_revision) WHERE id = ?",
        )
        .bind(i64::try_from(generation).unwrap_or(i64::MAX))
        .bind(policy_revision)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_node(&self, id: &str) -> Result<bool, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM deployment_nodes WHERE node_id = ?")
            .bind(id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM node_rollups WHERE node_id = ?")
            .bind(id)
            .execute(&mut *transaction)
            .await?;
        let deleted = sqlx::query("DELETE FROM nodes WHERE id = ?")
            .bind(id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(deleted.rows_affected() > 0)
    }

    /// Records a node's report and its query counts. The newest copy of a minute wins, so sending
    /// one twice changes nothing. Returns how far the counts are now stored.
    pub async fn record_heartbeat(
        &self,
        node: &Node,
        update: &HeartbeatUpdate<'_>,
    ) -> Result<i64, sqlx::Error> {
        let stored_through = update
            .rollups
            .iter()
            .map(|row| row.bucket_start_ms)
            .max()
            .unwrap_or(0)
            .max(node.rollups_stored_through_ms);
        let mut transaction = self.pool.begin().await?;
        for row in update.rollups {
            sqlx::query(
                "INSERT INTO node_rollups (node_id, bucket_start_ms, outcome, count, latency_sum_us) \
                 VALUES (?, ?, ?, ?, ?) ON CONFLICT (node_id, bucket_start_ms, outcome) \
                 DO UPDATE SET count = excluded.count, latency_sum_us = excluded.latency_sum_us",
            )
            .bind(&node.id)
            .bind(row.bucket_start_ms)
            .bind(&row.outcome)
            .bind(row.count)
            .bind(row.latency_sum_us)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "UPDATE nodes SET last_seen_ms = ?, version = ?, applied_generation = ?, \
             policy_revision = ?, report_json = ?, rollups_stored_through_ms = ? WHERE id = ?",
        )
        .bind(update.now_ms)
        .bind(update.version)
        .bind(i64::try_from(update.applied_generation).unwrap_or(i64::MAX))
        .bind(update.policy_revision)
        .bind(update.report_json)
        .bind(stored_through)
        .bind(&node.id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(stored_through)
    }

    pub async fn forget_old_rollups(&self, now_ms: i64) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM node_rollups WHERE bucket_start_ms < ?")
            .bind(now_ms - ROLLUP_RETENTION_MS)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn rollups(&self, from_ms: i64, to_ms: i64) -> Result<Vec<FleetRollup>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT node_id, bucket_start_ms, outcome, count, latency_sum_us FROM node_rollups \
             WHERE bucket_start_ms >= ? AND bucket_start_ms <= ?",
        )
        .bind(from_ms)
        .bind(to_ms)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(FleetRollup {
                    node_id: row.try_get("node_id")?,
                    bucket_start_ms: row.try_get("bucket_start_ms")?,
                    outcome: row.try_get("outcome")?,
                    count: row.try_get("count")?,
                    latency_sum_us: row.try_get("latency_sum_us")?,
                })
            })
            .collect()
    }

    // --- Bundles and deployments ---

    /// Takes the next generation for a site. A number is never used twice, even if the bundle it
    /// was for is never finished.
    pub async fn next_generation(&self, site_id: &str) -> Result<u64, sqlx::Error> {
        let row = sqlx::query(
            "UPDATE sites SET next_generation = next_generation + 1 WHERE id = ? \
             RETURNING next_generation - 1 AS generation",
        )
        .bind(site_id)
        .fetch_one(&self.pool)
        .await?;
        generation_of(&row, "generation")
    }

    pub async fn create_deployment(&self, new: &NewDeployment<'_>) -> Result<(), sqlx::Error> {
        let generation = i64::try_from(new.generation).unwrap_or(i64::MAX);
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO bundles (id, site_id, generation, manifest, signature, policy_sha256, created_at_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(new.bundle_id)
        .bind(new.site_id)
        .bind(generation)
        .bind(new.manifest)
        .bind(new.signature)
        .bind(new.policy_sha256)
        .bind(new.created_at_ms)
        .execute(&mut *transaction)
        .await?;
        for file in new.files {
            sqlx::query("INSERT OR IGNORE INTO bundle_files (bundle_id, sha256) VALUES (?, ?)")
                .bind(new.bundle_id)
                .bind(file)
                .execute(&mut *transaction)
                .await?;
        }
        // Whatever was rolling out is replaced by this.
        sqlx::query(
            "UPDATE deployments SET status = 'superseded' \
             WHERE site_id = ? AND status IN ('canary', 'rolling_out')",
        )
        .bind(new.site_id)
        .execute(&mut *transaction)
        .await?;
        let status = if new.canary_node_id.is_some() {
            "canary"
        } else {
            "rolling_out"
        };
        sqlx::query(
            "INSERT INTO deployments (id, site_id, bundle_id, generation, kind, strategy, \
             canary_node_id, status, reason, created_by, created_at_ms, rollback_of) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(new.deployment_id)
        .bind(new.site_id)
        .bind(new.bundle_id)
        .bind(generation)
        .bind(new.kind)
        .bind(new.strategy)
        .bind(new.canary_node_id)
        .bind(status)
        .bind(new.reason)
        .bind(new.created_by)
        .bind(new.created_at_ms)
        .bind(new.rollback_of)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await
    }

    pub async fn bundle(&self, id: &str) -> Result<Option<Bundle>, sqlx::Error> {
        sqlx::query("SELECT * FROM bundles WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(bundle)
            .transpose()
    }

    /// Whether a site has been given a file.
    pub async fn site_may_read(&self, site_id: &str, sha256: &str) -> Result<bool, sqlx::Error> {
        let row = sqlx::query(
            "SELECT 1 FROM bundle_files JOIN bundles ON bundles.id = bundle_files.bundle_id \
             WHERE bundles.site_id = ? AND bundle_files.sha256 = ? LIMIT 1",
        )
        .bind(site_id)
        .bind(sha256)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    pub async fn deployment(&self, id: &str) -> Result<Option<Deployment>, sqlx::Error> {
        sqlx::query("SELECT * FROM deployments WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(deployment)
            .transpose()
    }

    pub async fn deployments(
        &self,
        site_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<Deployment>, sqlx::Error> {
        sqlx::query(
            "SELECT * FROM deployments WHERE (?1 IS NULL OR site_id = ?1) \
             ORDER BY created_at_ms DESC, generation DESC LIMIT ?2",
        )
        .bind(site_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(deployment)
        .collect()
    }

    /// The newest deployment for a site.
    pub async fn latest_deployment(
        &self,
        site_id: &str,
    ) -> Result<Option<Deployment>, sqlx::Error> {
        sqlx::query("SELECT * FROM deployments WHERE site_id = ? ORDER BY generation DESC LIMIT 1")
            .bind(site_id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(deployment)
            .transpose()
    }

    /// The bundle a node should be running.
    ///
    /// While a canary is being tried, or if it failed, every other node stays on what came before.
    pub async fn desired_bundle(&self, node: &Node) -> Result<Option<Deployment>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT * FROM deployments WHERE site_id = ?1 \
             AND NOT (strategy = 'canary' AND status IN ('canary', 'failed') \
                      AND canary_node_id IS NOT ?2) \
             ORDER BY generation DESC LIMIT 1",
        )
        .bind(&node.site_id)
        .bind(&node.id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(deployment).transpose()
    }

    pub async fn set_deployment_status(&self, id: &str, status: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE deployments SET status = ? WHERE id = ?")
            .bind(status)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn record_progress(
        &self,
        deployment_id: &str,
        node_id: &str,
        state: &str,
        detail: Option<&str>,
        now_ms: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO deployment_nodes (deployment_id, node_id, state, detail, updated_at_ms) \
             VALUES (?, ?, ?, ?, ?) ON CONFLICT (deployment_id, node_id) DO UPDATE SET \
             state = excluded.state, detail = excluded.detail, updated_at_ms = excluded.updated_at_ms",
        )
        .bind(deployment_id)
        .bind(node_id)
        .bind(state)
        .bind(detail)
        .bind(now_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn progress(&self, deployment_id: &str) -> Result<Vec<NodeProgress>, sqlx::Error> {
        let rows = sqlx::query("SELECT * FROM deployment_nodes WHERE deployment_id = ?")
            .bind(deployment_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(NodeProgress {
                    node_id: row.try_get("node_id")?,
                    state: row.try_get("state")?,
                    detail: row.try_get("detail")?,
                    updated_at_ms: row.try_get("updated_at_ms")?,
                })
            })
            .collect()
    }

    /// The deployment that made a generation.
    pub async fn deployment_for_bundle(
        &self,
        bundle_id: &str,
    ) -> Result<Option<Deployment>, sqlx::Error> {
        sqlx::query("SELECT * FROM deployments WHERE bundle_id = ?")
            .bind(bundle_id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(deployment)
            .transpose()
    }
}

/// What a heartbeat changes about a node.
pub struct HeartbeatUpdate<'a> {
    pub now_ms: i64,
    pub version: &'a str,
    pub applied_generation: u64,
    pub policy_revision: &'a str,
    pub report_json: &'a str,
    pub rollups: &'a [RollupRow],
}

/// One node's count for one minute and outcome.
#[derive(Clone, Debug)]
pub struct FleetRollup {
    pub node_id: String,
    pub bucket_start_ms: i64,
    pub outcome: String,
    pub count: i64,
    pub latency_sum_us: i64,
}

/// Why the controller's database couldn't be opened.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("controller database failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("controller database migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
}
