use std::env;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use sqlx::Row;

use crate::kiro::model::credentials::{CredentialsConfig, KiroCredentials};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageMode {
    Local,
    Pgsql,
}

impl StorageMode {
    pub fn from_env() -> anyhow::Result<Self> {
        let raw = env::var("KIRO_STORAGE_MODE")
            .or_else(|_| env::var("KIRO_STORAGE"))
            .unwrap_or_else(|_| "local".to_string());

        match raw.to_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "pgsql" | "pg" | "postgres" | "postgresql" => Ok(Self::Pgsql),
            other => bail!("Unsupported storage mode: {}. Use local or pgsql.", other),
        }
    }
}

impl std::fmt::Display for StorageMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageMode::Local => write!(f, "local"),
            StorageMode::Pgsql => write!(f, "pgsql"),
        }
    }
}

pub trait CredentialStore: Send + Sync {
    fn mode(&self) -> StorageMode;
    fn load(&self) -> anyhow::Result<Vec<KiroCredentials>>;
    fn persist(&self, credentials: &[KiroCredentials]) -> anyhow::Result<()>;
}

pub fn build_credential_store(
    credentials_path: impl Into<PathBuf>,
) -> anyhow::Result<Arc<dyn CredentialStore>> {
    let mode = StorageMode::from_env()?;
    match mode {
        StorageMode::Local => Ok(Arc::new(LocalCredentialStore::new(credentials_path))),
        StorageMode::Pgsql => {
            let url = env::var("KIRO_PG_URL")
                .or_else(|_| env::var("DATABASE_URL"))
                .context("Missing PostgreSQL connection URL. Set KIRO_PG_URL or DATABASE_URL.")?;
            Ok(Arc::new(PgCredentialStore::new(url)?))
        }
    }
}

pub struct LocalCredentialStore {
    path: PathBuf,
    is_multiple_format: Mutex<bool>,
}

impl LocalCredentialStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            is_multiple_format: Mutex::new(false),
        }
    }
}

impl CredentialStore for LocalCredentialStore {
    fn mode(&self) -> StorageMode {
        StorageMode::Local
    }

    fn load(&self) -> anyhow::Result<Vec<KiroCredentials>> {
        let config = CredentialsConfig::load(&self.path)?;
        let is_multiple = config.is_multiple();
        *self
            .is_multiple_format
            .lock()
            .expect("credentials format lock poisoned") = is_multiple;
        Ok(config.into_sorted_credentials())
    }

    fn persist(&self, credentials: &[KiroCredentials]) -> anyhow::Result<()> {
        let is_multiple = *self
            .is_multiple_format
            .lock()
            .expect("credentials format lock poisoned");
        if !is_multiple {
            return Ok(());
        }

        let json = serde_json::to_string_pretty(credentials).context("Failed to serialize credentials")?;

        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| std::fs::write(&self.path, &json))
                .with_context(|| format!("Failed to persist credentials file: {:?}", self.path))?;
        } else {
            std::fs::write(&self.path, &json)
                .with_context(|| format!("Failed to persist credentials file: {:?}", self.path))?;
        }

        Ok(())
    }
}

struct PgCredentialStore {
    pool: sqlx::Pool<sqlx::Postgres>,
    schema_ready: AtomicBool,
}

impl PgCredentialStore {
    fn new(database_url: String) -> anyhow::Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect_lazy(&database_url)
            .context("Failed to create PostgreSQL pool")?;

        Ok(Self {
            pool,
            schema_ready: AtomicBool::new(false),
        })
    }

    fn ensure_schema(&self) -> anyhow::Result<()> {
        if self.schema_ready.load(Ordering::Acquire) {
            return Ok(());
        }

        self.block_on(async {
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS kiro_credentials (\
                 id BIGINT PRIMARY KEY,\
                 access_token TEXT,\
                 refresh_token TEXT,\
                 profile_arn TEXT,\
                 expires_at TEXT,\
                 auth_method TEXT,\
                 client_id TEXT,\
                 client_secret TEXT,\
                 priority INTEGER NOT NULL DEFAULT 0\
                 )",
            )
            .execute(&self.pool)
            .await
            .map(|_| ())
        })?;

        self.schema_ready.store(true, Ordering::Release);
        Ok(())
    }

    fn block_on<F, T>(&self, future: F) -> anyhow::Result<T>
    where
        F: Future<Output = Result<T, sqlx::Error>>,
    {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            tokio::task::block_in_place(|| handle.block_on(future))
                .context("PostgreSQL operation failed")
        } else {
            let runtime = tokio::runtime::Runtime::new()
                .context("Failed to create Tokio runtime for PostgreSQL")?;
            runtime
                .block_on(future)
                .context("PostgreSQL operation failed")
        }
    }
}

impl CredentialStore for PgCredentialStore {
    fn mode(&self) -> StorageMode {
        StorageMode::Pgsql
    }

    fn load(&self) -> anyhow::Result<Vec<KiroCredentials>> {
        self.ensure_schema()?;

        let rows = self.block_on(async {
            sqlx::query(
                "SELECT id, access_token, refresh_token, profile_arn, expires_at, auth_method, \
                 client_id, client_secret, priority\
                 FROM kiro_credentials\
                 ORDER BY priority ASC, id ASC",
            )
            .fetch_all(&self.pool)
            .await
        })?;

        let mut credentials = Vec::with_capacity(rows.len());
        for row in rows {
            let id: i64 = row.try_get("id")?;
            let priority: i32 = row.try_get("priority")?;
            let id = u64::try_from(id).context("Invalid credential id in PostgreSQL")?;

            credentials.push(KiroCredentials {
                id: Some(id),
                access_token: row.try_get("access_token")?,
                refresh_token: row.try_get("refresh_token")?,
                profile_arn: row.try_get("profile_arn")?,
                expires_at: row.try_get("expires_at")?,
                auth_method: row.try_get("auth_method")?,
                client_id: row.try_get("client_id")?,
                client_secret: row.try_get("client_secret")?,
                priority: priority.max(0) as u32,
            });
        }

        Ok(credentials)
    }

    fn persist(&self, credentials: &[KiroCredentials]) -> anyhow::Result<()> {
        self.ensure_schema()?;

        let mut prepared = Vec::with_capacity(credentials.len());
        for cred in credentials {
            let id = cred
                .id
                .context("Credential id is required for PostgreSQL persistence")?;
            let id = i64::try_from(id)
                .context("Credential id out of range for PostgreSQL persistence")?;
            let priority = i32::try_from(cred.priority).unwrap_or(i32::MAX);
            prepared.push((cred, id, priority));
        }

        self.block_on(async {
            let mut tx = self.pool.begin().await?;

            for (cred, id, priority) in prepared {
                sqlx::query(
                    "INSERT INTO kiro_credentials (\
                     id, access_token, refresh_token, profile_arn, expires_at, auth_method, \
                     client_id, client_secret, priority\
                     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)\
                     ON CONFLICT (id) DO UPDATE SET\
                     access_token = EXCLUDED.access_token,\
                     refresh_token = EXCLUDED.refresh_token,\
                     profile_arn = EXCLUDED.profile_arn,\
                     expires_at = EXCLUDED.expires_at,\
                     auth_method = EXCLUDED.auth_method,\
                     client_id = EXCLUDED.client_id,\
                     client_secret = EXCLUDED.client_secret,\
                     priority = EXCLUDED.priority",
                )
                .bind(id)
                .bind(&cred.access_token)
                .bind(&cred.refresh_token)
                .bind(&cred.profile_arn)
                .bind(&cred.expires_at)
                .bind(&cred.auth_method)
                .bind(&cred.client_id)
                .bind(&cred.client_secret)
                .bind(priority)
                .execute(&mut *tx)
                .await?;
            }

            tx.commit().await?;
            Ok(())
        })?;

        Ok(())
    }
}

#[cfg(test)]
pub struct MemoryCredentialStore {
    credentials: Mutex<Vec<KiroCredentials>>,
}

#[cfg(test)]
impl MemoryCredentialStore {
    pub fn new(credentials: Vec<KiroCredentials>) -> Self {
        Self {
            credentials: Mutex::new(credentials),
        }
    }
}

#[cfg(test)]
impl CredentialStore for MemoryCredentialStore {
    fn mode(&self) -> StorageMode {
        StorageMode::Local
    }

    fn load(&self) -> anyhow::Result<Vec<KiroCredentials>> {
        Ok(self
            .credentials
            .lock()
            .expect("memory credentials lock poisoned")
            .clone())
    }

    fn persist(&self, credentials: &[KiroCredentials]) -> anyhow::Result<()> {
        *self
            .credentials
            .lock()
            .expect("memory credentials lock poisoned") = credentials.to_vec();
        Ok(())
    }
}
