use std::path::Path;
use std::time::Duration;

use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};
use thiserror::Error;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations/node-config");

/// Why a config database operation failed.
#[derive(Debug, Error)]
pub enum ConfigDbError {
    #[error("config database failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("config database migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

/// A local administrator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
}

/// A login session and its user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub user_id: String,
    pub username: String,
    pub csrf_token: String,
    pub expires_at_ms: i64,
}

/// Fetch state for a downloaded list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListStatus {
    pub list_id: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub last_checked_at_ms: Option<i64>,
    pub last_success_at_ms: Option<i64>,
    pub last_error: Option<String>,
    pub entry_count: i64,
    pub invalid_line_count: i64,
}

/// A recorded administrative action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: String,
    pub occurred_at_ms: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub details_json: String,
}

/// The node's `config.db`: accounts, sessions, list fetch state and the audit log.
///
/// Policy itself lives in revision files (ADR-012), so a database failure here can't affect the
/// policy the DNS path enforces.
#[derive(Clone, Debug)]
pub struct ConfigDb {
    pool: SqlitePool,
}

fn status_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<ListStatus, sqlx::Error> {
    Ok(ListStatus {
        list_id: row.try_get("list_id")?,
        etag: row.try_get("etag")?,
        last_modified: row.try_get("last_modified")?,
        last_checked_at_ms: row.try_get("last_checked_at_ms")?,
        last_success_at_ms: row.try_get("last_success_at_ms")?,
        last_error: row.try_get("last_error")?,
        entry_count: row.try_get("entry_count")?,
        invalid_line_count: row.try_get("invalid_line_count")?,
    })
}

impl ConfigDb {
    /// Opens the database, creating and migrating it if needed.
    pub async fn open(path: &Path) -> Result<Self, ConfigDbError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(sqlx::Error::Io)?;
        }
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn user_count(&self) -> Result<i64, ConfigDbError> {
        let row = sqlx::query("SELECT COUNT(*) AS total FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("total")?)
    }

    /// Creates the first administrator, only if there are no users yet.
    ///
    /// Returns whether it was created, so concurrent setup attempts can't both succeed.
    pub async fn create_first_user(
        &self,
        id: &str,
        username: &str,
        password_hash: &str,
        now_ms: i64,
    ) -> Result<bool, ConfigDbError> {
        let result = sqlx::query(
            "INSERT INTO users (id, username, password_hash, created_at_ms) \
             SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)",
        )
        .bind(id)
        .bind(username)
        .bind(password_hash)
        .bind(now_ms)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn find_user(&self, username: &str) -> Result<Option<User>, ConfigDbError> {
        let row = sqlx::query("SELECT id, username, password_hash FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(User {
                id: row.try_get("id")?,
                username: row.try_get("username")?,
                password_hash: row.try_get("password_hash")?,
            })
        })
        .transpose()
    }

    /// Changes a password and ends all of that user's sessions.
    ///
    /// Returns whether the user exists.
    pub async fn set_password(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<bool, ConfigDbError> {
        let mut transaction = self.pool.begin().await?;
        let updated = sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?")
            .bind(password_hash)
            .bind(username)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username = ?)",
        )
        .bind(username)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(updated.rows_affected() == 1)
    }

    /// Every account, for encrypted backups.
    pub async fn users(&self) -> Result<Vec<User>, ConfigDbError> {
        let rows = sqlx::query("SELECT id, username, password_hash FROM users")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(User {
                    id: row.try_get("id")?,
                    username: row.try_get("username")?,
                    password_hash: row.try_get("password_hash")?,
                })
            })
            .collect()
    }

    /// Replaces every account from a backup, ending all sessions.
    pub async fn replace_users(&self, users: &[User], now_ms: i64) -> Result<(), ConfigDbError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM sessions")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM users")
            .execute(&mut *transaction)
            .await?;
        for user in users {
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, created_at_ms) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(user.id.clone())
            .bind(user.username.clone())
            .bind(user.password_hash.clone())
            .bind(now_ms)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Replaces all list fetch state from a backup.
    pub async fn replace_list_statuses(
        &self,
        statuses: &[ListStatus],
    ) -> Result<(), ConfigDbError> {
        sqlx::query("DELETE FROM list_status")
            .execute(&self.pool)
            .await?;
        for status in statuses {
            self.save_list_status(status).await?;
        }
        Ok(())
    }

    /// Adds audit events from a backup, keeping any already present.
    pub async fn import_audit_events(&self, events: &[AuditEvent]) -> Result<(), ConfigDbError> {
        for event in events {
            sqlx::query(
                "INSERT OR IGNORE INTO local_audit_events (id, occurred_at_ms, actor, action, \
                 target, details_json) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(&event.id)
            .bind(event.occurred_at_ms)
            .bind(&event.actor)
            .bind(&event.action)
            .bind(&event.target)
            .bind(&event.details_json)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn create_session(
        &self,
        token_hash: &str,
        user_id: &str,
        csrf_token: &str,
        now_ms: i64,
        expires_at_ms: i64,
    ) -> Result<(), ConfigDbError> {
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at_ms, expires_at_ms) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(token_hash)
        .bind(user_id)
        .bind(csrf_token)
        .bind(now_ms)
        .bind(expires_at_ms)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Finds a session that hasn't expired.
    pub async fn find_session(
        &self,
        token_hash: &str,
        now_ms: i64,
    ) -> Result<Option<Session>, ConfigDbError> {
        let row = sqlx::query(
            "SELECT sessions.user_id, users.username, sessions.csrf_token, sessions.expires_at_ms \
             FROM sessions JOIN users ON users.id = sessions.user_id \
             WHERE sessions.token_hash = ? AND sessions.expires_at_ms > ?",
        )
        .bind(token_hash)
        .bind(now_ms)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(Session {
                user_id: row.try_get("user_id")?,
                username: row.try_get("username")?,
                csrf_token: row.try_get("csrf_token")?,
                expires_at_ms: row.try_get("expires_at_ms")?,
            })
        })
        .transpose()
    }

    pub async fn delete_session(&self, token_hash: &str) -> Result<(), ConfigDbError> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_expired_sessions(&self, now_ms: i64) -> Result<(), ConfigDbError> {
        sqlx::query("DELETE FROM sessions WHERE expires_at_ms <= ?")
            .bind(now_ms)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_statuses(&self) -> Result<Vec<ListStatus>, ConfigDbError> {
        let rows = sqlx::query("SELECT * FROM list_status")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .iter()
            .map(status_from_row)
            .collect::<Result<_, sqlx::Error>>()?)
    }

    pub async fn list_status(&self, list_id: &str) -> Result<Option<ListStatus>, ConfigDbError> {
        let row = sqlx::query("SELECT * FROM list_status WHERE list_id = ?")
            .bind(list_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(status_from_row).transpose()?)
    }

    pub async fn save_list_status(&self, status: &ListStatus) -> Result<(), ConfigDbError> {
        sqlx::query(
            "INSERT INTO list_status (list_id, etag, last_modified, last_checked_at_ms, \
             last_success_at_ms, last_error, entry_count, invalid_line_count) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (list_id) DO UPDATE SET etag = excluded.etag, \
             last_modified = excluded.last_modified, \
             last_checked_at_ms = excluded.last_checked_at_ms, \
             last_success_at_ms = excluded.last_success_at_ms, \
             last_error = excluded.last_error, entry_count = excluded.entry_count, \
             invalid_line_count = excluded.invalid_line_count",
        )
        .bind(&status.list_id)
        .bind(&status.etag)
        .bind(&status.last_modified)
        .bind(status.last_checked_at_ms)
        .bind(status.last_success_at_ms)
        .bind(&status.last_error)
        .bind(status.entry_count)
        .bind(status.invalid_line_count)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_list_status(&self, list_id: &str) -> Result<(), ConfigDbError> {
        sqlx::query("DELETE FROM list_status WHERE list_id = ?")
            .bind(list_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn add_audit_event(&self, event: &AuditEvent) -> Result<(), ConfigDbError> {
        sqlx::query(
            "INSERT INTO local_audit_events (id, occurred_at_ms, actor, action, target, \
             details_json) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&event.id)
        .bind(event.occurred_at_ms)
        .bind(&event.actor)
        .bind(&event.action)
        .bind(&event.target)
        .bind(&event.details_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn recent_audit_events(&self, limit: i64) -> Result<Vec<AuditEvent>, ConfigDbError> {
        let rows = sqlx::query(
            "SELECT * FROM local_audit_events ORDER BY occurred_at_ms DESC, id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(AuditEvent {
                    id: row.try_get("id")?,
                    occurred_at_ms: row.try_get("occurred_at_ms")?,
                    actor: row.try_get("actor")?,
                    action: row.try_get("action")?,
                    target: row.try_get("target")?,
                    details_json: row.try_get("details_json")?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open() -> (tempfile::TempDir, ConfigDb) {
        let directory = tempfile::tempdir().unwrap();
        let db = ConfigDb::open(&directory.path().join("nested/config.db"))
            .await
            .unwrap();
        (directory, db)
    }

    #[tokio::test]
    async fn only_the_first_user_can_be_created_by_setup() {
        let (_directory, db) = open().await;
        assert_eq!(db.user_count().await.unwrap(), 0);
        assert!(
            db.create_first_user("u1", "admin", "hash", 1)
                .await
                .unwrap()
        );
        assert!(
            !db.create_first_user("u2", "second", "hash", 2)
                .await
                .unwrap()
        );
        assert_eq!(db.user_count().await.unwrap(), 1);
        assert_eq!(db.find_user("admin").await.unwrap().unwrap().id, "u1");
        assert!(db.find_user("second").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn sessions_expire_and_end_when_the_password_changes() {
        let (_directory, db) = open().await;
        db.create_first_user("u1", "admin", "hash", 1)
            .await
            .unwrap();
        db.create_session("token", "u1", "csrf", 1, 100)
            .await
            .unwrap();

        let session = db.find_session("token", 50).await.unwrap().unwrap();
        assert_eq!(session.username, "admin");
        assert_eq!(session.csrf_token, "csrf");
        assert!(
            db.find_session("token", 100).await.unwrap().is_none(),
            "expired"
        );
        assert!(db.find_session("other", 50).await.unwrap().is_none());

        assert!(db.set_password("admin", "new-hash").await.unwrap());
        assert!(db.find_session("token", 50).await.unwrap().is_none());
        assert_eq!(
            db.find_user("admin").await.unwrap().unwrap().password_hash,
            "new-hash"
        );
        assert!(!db.set_password("nobody", "hash").await.unwrap());
    }

    #[tokio::test]
    async fn logout_and_cleanup_remove_sessions() {
        let (_directory, db) = open().await;
        db.create_first_user("u1", "admin", "hash", 1)
            .await
            .unwrap();
        db.create_session("a", "u1", "csrf", 1, 100).await.unwrap();
        db.create_session("b", "u1", "csrf", 1, 200).await.unwrap();
        db.delete_session("a").await.unwrap();
        assert!(db.find_session("a", 50).await.unwrap().is_none());
        db.delete_expired_sessions(200).await.unwrap();
        assert!(db.find_session("b", 50).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_status_round_trips_and_updates() {
        let (_directory, db) = open().await;
        let mut status = ListStatus {
            list_id: "l1".into(),
            etag: Some("v1".into()),
            entry_count: 5,
            ..ListStatus::default()
        };
        db.save_list_status(&status).await.unwrap();
        status.last_error = Some("boom".into());
        db.save_list_status(&status).await.unwrap();
        assert_eq!(db.list_status("l1").await.unwrap().unwrap(), status);
        assert_eq!(db.list_statuses().await.unwrap().len(), 1);
        db.delete_list_status("l1").await.unwrap();
        assert!(db.list_status("l1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn audit_events_come_back_newest_first() {
        let (_directory, db) = open().await;
        for (id, at) in [("a", 1), ("b", 3), ("c", 2)] {
            db.add_audit_event(&AuditEvent {
                id: id.into(),
                occurred_at_ms: at,
                actor: "admin".into(),
                action: "rule.create".into(),
                target: "r1".into(),
                details_json: "{}".into(),
            })
            .await
            .unwrap();
        }
        let events = db.recent_audit_events(2).await.unwrap();
        assert_eq!(events[0].id, "b");
        assert_eq!(events[1].id, "c");
    }
}
