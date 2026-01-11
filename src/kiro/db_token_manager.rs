//! PostgreSQL-backed Token 管理器
//!
//! 用于多实例场景：所有状态以数据库为准，不使用本地缓存。

use anyhow::Context;
use chrono::{DateTime, Utc};
use tokio_postgres::{Client, NoTls, Row};

use crate::http_client::ProxyConfig;
use crate::kiro::model::credentials::KiroCredentials;
use crate::kiro::model::usage_limits::UsageLimitsResponse;
use crate::kiro::token_manager::{
    CallContext, CredentialEntrySnapshot, ManagerSnapshot, is_token_expired,
    is_token_expiring_soon, refresh_token, validate_refresh_token,
};
use crate::model::config::Config;
use crate::kiro::token_manager::TokenManagerOps;
use async_trait::async_trait;

const MAX_FAILURES_PER_CREDENTIAL: i32 = 3;

const DISABLED_REASON_MANUAL: &str = "Manual";
const DISABLED_REASON_TOO_MANY_FAILURES: &str = "TooManyFailures";
const DISABLED_REASON_QUOTA_EXCEEDED: &str = "QuotaExceeded";

pub struct DbTokenManager {
    config: Config,
    proxy: Option<ProxyConfig>,
    client: Client,
}

impl DbTokenManager {
    pub async fn connect(
        config: Config,
        proxy: Option<ProxyConfig>,
        db_url: String,
    ) -> anyhow::Result<Self> {
        let (client, connection) = tokio_postgres::connect(&db_url, NoTls)
            .await
            .context("连接 PostgreSQL 失败")?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!("PostgreSQL 连接异常: {}", e);
            }
        });

        let manager = Self {
            config,
            proxy,
            client,
        };
        manager.ensure_schema().await?;
        Ok(manager)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    async fn ensure_schema(&self) -> anyhow::Result<()> {
        let ddl = r#"
        CREATE TABLE IF NOT EXISTS credentials (
            id BIGSERIAL PRIMARY KEY,
            access_token TEXT,
            refresh_token TEXT NOT NULL,
            profile_arn TEXT,
            expires_at TIMESTAMPTZ,
            auth_method TEXT,
            client_id TEXT,
            client_secret TEXT,
            priority INT NOT NULL DEFAULT 0,
            failure_count INT NOT NULL DEFAULT 0,
            disabled BOOLEAN NOT NULL DEFAULT false,
            disabled_reason TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_credentials_available
            ON credentials(disabled, priority, id);
        "#;
        self.client.batch_execute(ddl).await?;
        Ok(())
    }

    pub async fn total_count(&self) -> anyhow::Result<usize> {
        let row = self
            .client
            .query_one("SELECT COUNT(*) FROM credentials", &[])
            .await?;
        let count: i64 = row.get(0);
        Ok(count.max(0) as usize)
    }

    pub async fn available_count(&self) -> anyhow::Result<usize> {
        let row = self
            .client
            .query_one("SELECT COUNT(*) FROM credentials WHERE disabled = false", &[])
            .await?;
        let count: i64 = row.get(0);
        Ok(count.max(0) as usize)
    }

    pub async fn get_profile_arn(&self) -> anyhow::Result<Option<String>> {
        let row = self
            .client
            .query_opt(
                "SELECT profile_arn FROM credentials WHERE disabled = false ORDER BY priority, id LIMIT 1",
                &[],
            )
            .await?;
        Ok(row.and_then(|r| r.get::<_, Option<String>>(0)))
    }

    pub async fn acquire_context(&self) -> anyhow::Result<CallContext> {
        let total = self.total_count().await?;
        if total == 0 {
            anyhow::bail!("没有可用凭据（0/0）");
        }

        let mut tried_ids: Vec<i64> = Vec::new();

        loop {
            let candidates = self.fetch_available_credentials().await?;
            let mut selected = None;

            for candidate in candidates {
                if tried_ids.contains(&candidate.id) {
                    continue;
                }
                selected = Some(candidate);
                break;
            }

            let Some(candidate) = selected else {
                let available = self.available_count().await?;
                if available == 0 && self.has_auto_disabled().await? {
                    self.auto_recover_disabled().await?;
                    tried_ids.clear();
                    continue;
                }
                if available > 0 {
                    anyhow::bail!(
                        "所有凭据均无法获取有效 Token（可用: {}/{}）",
                        available,
                        total
                    );
                }
                anyhow::bail!("所有凭据均已禁用（{}/{})", available, total);
            };

            match self.try_ensure_token(&candidate).await {
                Ok(ctx) => return Ok(ctx),
                Err(e) => {
                    tracing::warn!(
                        "凭据 #{} Token 刷新失败，尝试下一个凭据: {}",
                        candidate.id,
                        e
                    );
                    tried_ids.push(candidate.id);
                }
            }
        }
    }

    async fn fetch_available_credentials(&self) -> anyhow::Result<Vec<DbCredentialRow>> {
        let rows = self
            .client
            .query(
                "SELECT id, access_token, refresh_token, profile_arn, expires_at, auth_method, \
                 client_id, client_secret, priority, failure_count, disabled, disabled_reason \
                 FROM credentials WHERE disabled = false ORDER BY priority, id",
                &[],
            )
            .await?;
        rows.into_iter().map(row_to_db_credential).collect()
    }

    async fn fetch_credential_by_id(&self, id: u64) -> anyhow::Result<DbCredentialRow> {
        let id = id as i64;
        let row = self
            .client
            .query_opt(
                "SELECT id, access_token, refresh_token, profile_arn, expires_at, auth_method, \
                 client_id, client_secret, priority, failure_count, disabled, disabled_reason \
                 FROM credentials WHERE id = $1",
                &[&id],
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
        row_to_db_credential(row)
    }

    async fn fetch_credential_by_id_tx(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        id: i64,
    ) -> anyhow::Result<DbCredentialRow> {
        let row = tx
            .query_opt(
                "SELECT id, access_token, refresh_token, profile_arn, expires_at, auth_method, \
                 client_id, client_secret, priority, failure_count, disabled, disabled_reason \
                 FROM credentials WHERE id = $1",
                &[&id],
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;
        row_to_db_credential(row)
    }

    async fn has_auto_disabled(&self) -> anyhow::Result<bool> {
        let row = self
            .client
            .query_one(
                "SELECT COUNT(*) FROM credentials WHERE disabled = true AND disabled_reason = $1",
                &[&DISABLED_REASON_TOO_MANY_FAILURES],
            )
            .await?;
        let count: i64 = row.get(0);
        Ok(count > 0)
    }

    async fn auto_recover_disabled(&self) -> anyhow::Result<()> {
        tracing::warn!(
            "所有凭据均已被自动禁用，执行自愈：重置失败计数并重新启用（等价于重启）"
        );
        self.client
            .execute(
                "UPDATE credentials SET disabled = false, failure_count = 0, disabled_reason = NULL, \
                 updated_at = NOW() WHERE disabled_reason = $1",
                &[&DISABLED_REASON_TOO_MANY_FAILURES],
            )
            .await?;
        Ok(())
    }

    async fn try_ensure_token(&self, row: &DbCredentialRow) -> anyhow::Result<CallContext> {
        let mut creds = row.credentials.clone();
        let needs_refresh = is_token_expired(&creds) || is_token_expiring_soon(&creds);

        if needs_refresh {
            let tx = self.client.build_transaction().start().await?;
            tx.execute("SELECT pg_advisory_xact_lock($1)", &[&row.id])
                .await?;

            let refreshed = {
                let current = self.fetch_credential_by_id_tx(&tx, row.id).await?;
                let current_creds = current.credentials;
                if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                    let new_creds =
                        refresh_token(&current_creds, &self.config, self.proxy.as_ref()).await?;
                    if is_token_expired(&new_creds) {
                        anyhow::bail!("刷新后的 Token 仍然无效或已过期");
                    }
                    self.update_tokens(&tx, row.id, &new_creds).await?;
                    new_creds
                } else {
                    current_creds
                }
            };

            tx.commit().await?;
            creds = refreshed;
        }

        let token = creds
            .access_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("没有可用的 accessToken"))?;

        Ok(CallContext {
            id: row.id as u64,
            credentials: creds,
            token,
        })
    }

    async fn update_tokens(
        &self,
        tx: &tokio_postgres::Transaction<'_>,
        id: i64,
        creds: &KiroCredentials,
    ) -> anyhow::Result<()> {
        let expires_at = parse_rfc3339_opt(&creds.expires_at)?;
        tx.execute(
            "UPDATE credentials SET access_token = $1, refresh_token = $2, profile_arn = $3, \
             expires_at = $4, updated_at = NOW() WHERE id = $5",
            &[
                &creds.access_token,
                &creds.refresh_token,
                &creds.profile_arn,
                &expires_at,
                &id,
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn report_success(&self, id: u64) -> anyhow::Result<()> {
        let id = id as i64;
        self.client
            .execute(
                "UPDATE credentials SET failure_count = 0, updated_at = NOW() WHERE id = $1",
                &[&id],
            )
            .await?;
        Ok(())
    }

    pub async fn report_failure(&self, id: u64) -> anyhow::Result<bool> {
        let id = id as i64;
        let updated = self
            .client
            .execute(
                "UPDATE credentials SET failure_count = failure_count + 1, \
                 disabled = CASE WHEN failure_count + 1 >= $1 THEN true ELSE disabled END, \
                 disabled_reason = CASE WHEN failure_count + 1 >= $1 THEN $2 ELSE disabled_reason END, \
                 updated_at = NOW() WHERE id = $3",
                &[&MAX_FAILURES_PER_CREDENTIAL, &DISABLED_REASON_TOO_MANY_FAILURES, &id],
            )
            .await?;

        if updated == 0 {
            return Ok(self.available_count().await? > 0);
        }

        Ok(self.available_count().await? > 0)
    }

    pub async fn report_quota_exhausted(&self, id: u64) -> anyhow::Result<bool> {
        let id = id as i64;
        let updated = self
            .client
            .execute(
                "UPDATE credentials SET disabled = true, disabled_reason = $1, \
                 failure_count = $2, updated_at = NOW() WHERE id = $3",
                &[&DISABLED_REASON_QUOTA_EXCEEDED, &MAX_FAILURES_PER_CREDENTIAL, &id],
            )
            .await?;

        if updated == 0 {
            return Ok(self.available_count().await? > 0);
        }

        Ok(self.available_count().await? > 0)
    }

    pub async fn snapshot(&self) -> anyhow::Result<ManagerSnapshot> {
        let rows = self
            .client
            .query(
                "SELECT id, priority, disabled, failure_count, auth_method, profile_arn, expires_at \
                 FROM credentials ORDER BY priority, id",
                &[],
            )
            .await?;

        let mut credentials = Vec::with_capacity(rows.len());
        for row in rows {
            credentials.push(CredentialEntrySnapshot {
                id: row.get::<_, i64>(0) as u64,
                priority: row.get::<_, i32>(1) as u32,
                disabled: row.get::<_, bool>(2),
                failure_count: row.get::<_, i32>(3) as u32,
                auth_method: row.get::<_, Option<String>>(4),
                has_profile_arn: row.get::<_, Option<String>>(5).is_some(),
                expires_at: to_rfc3339_opt(row.get::<_, Option<DateTime<Utc>>>(6)),
            });
        }

        let total = credentials.len();
        let available = credentials.iter().filter(|c| !c.disabled).count();
        let current_id = self
            .client
            .query_opt(
                "SELECT id FROM credentials WHERE disabled = false ORDER BY priority, id LIMIT 1",
                &[],
            )
            .await?
            .map(|row| row.get::<_, i64>(0) as u64)
            .unwrap_or(0);

        Ok(ManagerSnapshot {
            entries: credentials,
            current_id,
            total,
            available,
        })
    }

    pub async fn set_disabled(&self, id: u64, disabled: bool) -> anyhow::Result<()> {
        let id = id as i64;
        let reason = if disabled {
            Some(DISABLED_REASON_MANUAL)
        } else {
            None
        };
        let updated = self
            .client
            .execute(
                "UPDATE credentials SET disabled = $1, failure_count = CASE WHEN $1 THEN failure_count ELSE 0 END, \
                 disabled_reason = $2, updated_at = NOW() WHERE id = $3",
                &[&disabled, &reason, &id],
            )
            .await?;

        if updated == 0 {
            anyhow::bail!("凭据不存在: {}", id);
        }
        Ok(())
    }

    pub async fn set_priority(&self, id: u64, priority: u32) -> anyhow::Result<()> {
        let id = id as i64;
        let priority = priority as i32;
        let updated = self
            .client
            .execute(
                "UPDATE credentials SET priority = $1, updated_at = NOW() WHERE id = $2",
                &[&priority, &id],
            )
            .await?;
        if updated == 0 {
            anyhow::bail!("凭据不存在: {}", id);
        }
        Ok(())
    }

    pub async fn reset_and_enable(&self, id: u64) -> anyhow::Result<()> {
        let id = id as i64;
        let updated = self
            .client
            .execute(
                "UPDATE credentials SET disabled = false, failure_count = 0, disabled_reason = NULL, \
                 updated_at = NOW() WHERE id = $1",
                &[&id],
            )
            .await?;
        if updated == 0 {
            anyhow::bail!("凭据不存在: {}", id);
        }
        Ok(())
    }

    pub async fn get_usage_limits_for(&self, id: u64) -> anyhow::Result<UsageLimitsResponse> {
        let row = self.fetch_credential_by_id(id).await?;
        let mut creds = row.credentials;
        let needs_refresh = is_token_expired(&creds) || is_token_expiring_soon(&creds);

        let token = if needs_refresh {
            let tx = self.client.build_transaction().start().await?;
            tx.execute("SELECT pg_advisory_xact_lock($1)", &[&row.id])
                .await?;

            let current = self.fetch_credential_by_id_tx(&tx, row.id).await?;
            let current_creds = current.credentials;
            let refreshed = if is_token_expired(&current_creds) || is_token_expiring_soon(&current_creds) {
                let new_creds =
                    refresh_token(&current_creds, &self.config, self.proxy.as_ref()).await?;
                self.update_tokens(&tx, row.id, &new_creds).await?;
                new_creds
            } else {
                current_creds
            };

            tx.commit().await?;
            creds = refreshed;

            creds
                .access_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("刷新后无 access_token"))?
        } else {
            creds
                .access_token
                .clone()
                .ok_or_else(|| anyhow::anyhow!("凭据无 access_token"))?
        };

        crate::kiro::token_manager::get_usage_limits(
            &creds,
            &self.config,
            &token,
            self.proxy.as_ref(),
        )
        .await
    }

    pub async fn add_credential(&self, mut new_cred: KiroCredentials) -> anyhow::Result<u64> {
        validate_refresh_token(&new_cred)?;

        let mut validated =
            refresh_token(&new_cred, &self.config, self.proxy.as_ref()).await?;

        validated.priority = new_cred.priority;
        validated.auth_method = new_cred.auth_method.take();
        validated.client_id = new_cred.client_id.take();
        validated.client_secret = new_cred.client_secret.take();

        let expires_at = parse_rfc3339_opt(&validated.expires_at)?;
        let row = self
            .client
            .query_one(
                "INSERT INTO credentials (access_token, refresh_token, profile_arn, expires_at, \
                 auth_method, client_id, client_secret, priority, failure_count, disabled, disabled_reason) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, false, NULL) RETURNING id",
                &[
                    &validated.access_token,
                    &validated.refresh_token,
                    &validated.profile_arn,
                    &expires_at,
                    &validated.auth_method,
                    &validated.client_id,
                    &validated.client_secret,
                    &(validated.priority as i32),
                ],
            )
            .await?;

        let id: i64 = row.get(0);
        Ok(id as u64)
    }

    pub async fn delete_credential(&self, id: u64) -> anyhow::Result<()> {
        let id = id as i64;
        let row = self
            .client
            .query_opt("SELECT disabled FROM credentials WHERE id = $1", &[&id])
            .await?
            .ok_or_else(|| anyhow::anyhow!("凭据不存在: {}", id))?;

        let disabled: bool = row.get(0);
        if !disabled {
            anyhow::bail!("只能删除已禁用的凭据（请先禁用凭据 #{}）", id);
        }

        self.client
            .execute("DELETE FROM credentials WHERE id = $1", &[&id])
            .await?;
        Ok(())
    }
}

struct DbCredentialRow {
    id: i64,
    credentials: KiroCredentials,
}

fn row_to_db_credential(row: Row) -> anyhow::Result<DbCredentialRow> {
    let id: i64 = row.get(0);
    let expires_at = to_rfc3339_opt(row.get::<_, Option<DateTime<Utc>>>(4));
    Ok(DbCredentialRow {
        id,
        credentials: KiroCredentials {
            id: Some(id as u64),
            access_token: row.get::<_, Option<String>>(1),
            refresh_token: row.get::<_, Option<String>>(2),
            profile_arn: row.get::<_, Option<String>>(3),
            expires_at,
            auth_method: row.get::<_, Option<String>>(5),
            client_id: row.get::<_, Option<String>>(6),
            client_secret: row.get::<_, Option<String>>(7),
            priority: row.get::<_, i32>(8) as u32,
        },
    })
}

fn to_rfc3339_opt(value: Option<DateTime<Utc>>) -> Option<String> {
    value.map(|dt| dt.to_rfc3339())
}

fn parse_rfc3339_opt(value: &Option<String>) -> anyhow::Result<Option<DateTime<Utc>>> {
    match value {
        Some(text) => {
            let dt = DateTime::parse_from_rfc3339(text)
                .with_context(|| format!("解析 expires_at 失败: {}", text))?
                .with_timezone(&Utc);
            Ok(Some(dt))
        }
        None => Ok(None),
    }
}

#[async_trait]
impl TokenManagerOps for DbTokenManager {
    fn config(&self) -> &Config {
        self.config()
    }

    async fn total_count(&self) -> anyhow::Result<usize> {
        self.total_count().await
    }

    async fn available_count(&self) -> anyhow::Result<usize> {
        self.available_count().await
    }

    async fn acquire_context(&self) -> anyhow::Result<CallContext> {
        self.acquire_context().await
    }

    async fn report_success(&self, id: u64) -> anyhow::Result<()> {
        self.report_success(id).await
    }

    async fn report_failure(&self, id: u64) -> anyhow::Result<bool> {
        self.report_failure(id).await
    }

    async fn report_quota_exhausted(&self, id: u64) -> anyhow::Result<bool> {
        self.report_quota_exhausted(id).await
    }

    async fn snapshot(&self) -> anyhow::Result<ManagerSnapshot> {
        self.snapshot().await
    }

    async fn set_disabled(&self, id: u64, disabled: bool) -> anyhow::Result<()> {
        self.set_disabled(id, disabled).await
    }

    async fn set_priority(&self, id: u64, priority: u32) -> anyhow::Result<()> {
        self.set_priority(id, priority).await
    }

    async fn reset_and_enable(&self, id: u64) -> anyhow::Result<()> {
        self.reset_and_enable(id).await
    }

    async fn get_usage_limits_for(&self, id: u64) -> anyhow::Result<UsageLimitsResponse> {
        self.get_usage_limits_for(id).await
    }

    async fn add_credential(&self, new_cred: KiroCredentials) -> anyhow::Result<u64> {
        self.add_credential(new_cred).await
    }

    async fn delete_credential(&self, id: u64) -> anyhow::Result<()> {
        self.delete_credential(id).await
    }

    async fn get_profile_arn(&self) -> anyhow::Result<Option<String>> {
        self.get_profile_arn().await
    }
}
