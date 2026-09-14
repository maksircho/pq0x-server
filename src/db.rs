use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::time::Duration;
use crate::models::{KeyBundleResponse, PendingMessage};

#[derive(Clone)]
pub struct Database {
    pub pool: Pool<Sqlite>,
}

impl Database {
    pub async fn init(db_url: &str) -> Result<Self, sqlx::Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(3))
            .connect(db_url)
            .await?;

        // Initialize SQLite Tables automatically
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS key_bundles (
                address TEXT PRIMARY KEY,
                ik_pub_hex TEXT NOT NULL,
                spk_pub_hex TEXT NOT NULL,
                spk_sig_hex TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS message_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_token TEXT NOT NULL,
                payload_hex TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS auth_challenges (
                address TEXT PRIMARY KEY,
                nonce_hex TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_msg_target ON message_queue(target_token);
            "#,
        )
        .execute(&pool)
        .await?;

        Ok(Self { pool })
    }

    // Key Bundle Operations
    pub async fn upsert_key_bundle(
        &self,
        address: &str,
        ik_pub: &str,
        spk_pub: &str,
        spk_sig: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO key_bundles (address, ik_pub_hex, spk_pub_hex, spk_sig_hex)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(address) DO UPDATE SET
                ik_pub_hex=excluded.ik_pub_hex,
                spk_pub_hex=excluded.spk_pub_hex,
                spk_sig_hex=excluded.spk_sig_hex
            "#,
        )
        .bind(address)
        .bind(ik_pub)
        .bind(spk_pub)
        .bind(spk_sig)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_key_bundle(&self, address: &str) -> Result<Option<KeyBundleResponse>, sqlx::Error> {
        sqlx::query_as::<_, KeyBundleResponse>(
            "SELECT address, ik_pub_hex, spk_pub_hex, spk_sig_hex FROM key_bundles WHERE address = ?1"
        )
        .bind(address)
        .fetch_optional(&self.pool)
        .await
    }

    // Message Queue Operations
    pub async fn deposit_message(&self, target_token: &str, payload_hex: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO message_queue (target_token, payload_hex) VALUES (?1, ?2)"
        )
        .bind(target_token)
        .bind(payload_hex)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn fetch_and_purge_messages(&self, target_token: &str) -> Result<Vec<PendingMessage>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        let messages = sqlx::query_as::<_, PendingMessage>(
            "SELECT id, target_token, payload_hex, created_at FROM message_queue WHERE target_token = ?1"
        )
        .bind(target_token)
        .fetch_all(&mut *tx)
        .await?;

        if !messages.is_empty() {
            sqlx::query("DELETE FROM message_queue WHERE target_token = ?1")
                .bind(target_token)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(messages)
    }

    // Auth Challenge Operations
    pub async fn set_challenge(&self, address: &str, nonce_hex: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO auth_challenges (address, nonce_hex)
            VALUES (?1, ?2)
            ON CONFLICT(address) DO UPDATE SET nonce_hex=excluded.nonce_hex
            "#
        )
        .bind(address)
        .bind(nonce_hex)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn consume_challenge(&self, address: &str) -> Result<Option<String>, sqlx::Error> {
        let res = sqlx::query_scalar::<_, String>(
            "SELECT nonce_hex FROM auth_challenges WHERE address = ?1"
        )
        .bind(address)
        .fetch_optional(&self.pool)
        .await?;

        if res.is_some() {
            sqlx::query("DELETE FROM auth_challenges WHERE address = ?1")
                .bind(address)
                .execute(&self.pool)
                .await?;
        }

        Ok(res)
    }

    // TTL Cleanup Task
    pub async fn purge_expired_messages(&self, ttl_days: i64) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            "DELETE FROM message_queue WHERE created_at < datetime('now', ?1)"
        )
        .bind(format!("-{} days", ttl_days))
        .execute(&self.pool)
        .await?;

        Ok(res.rows_affected())
    }
}
