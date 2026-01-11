use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialsBackend {
    File,
    Postgres,
}

/// KNA 应用配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port", deserialize_with = "deserialize_port")]
    pub port: u16,

    #[serde(default = "default_region")]
    pub region: String,

    #[serde(default = "default_kiro_version")]
    pub kiro_version: String,

    #[serde(default)]
    pub machine_id: Option<String>,

    #[serde(default)]
    pub api_key: Option<String>,

    #[serde(default = "default_system_version")]
    pub system_version: String,

    #[serde(default = "default_node_version")]
    pub node_version: String,

    /// 外部 count_tokens API 地址（可选）
    #[serde(default)]
    pub count_tokens_api_url: Option<String>,

    /// count_tokens API 密钥（可选）
    #[serde(default)]
    pub count_tokens_api_key: Option<String>,

    /// count_tokens API 认证类型（可选，"x-api-key" 或 "bearer"，默认 "x-api-key"）
    #[serde(default = "default_count_tokens_auth_type")]
    pub count_tokens_auth_type: String,

    /// HTTP 代理地址（可选）
    /// 支持格式: http://host:port, https://host:port, socks5://host:port
    #[serde(default)]
    pub proxy_url: Option<String>,

    /// 代理认证用户名（可选）
    #[serde(default)]
    pub proxy_username: Option<String>,

    /// 代理认证密码（可选）
    #[serde(default)]
    pub proxy_password: Option<String>,

    /// Admin API 密钥（可选，启用 Admin API 功能）
    #[serde(default)]
    pub admin_api_key: Option<String>,

    /// 凭据存储后端（file / postgres）
    #[serde(default = "default_credentials_backend")]
    pub credentials_backend: CredentialsBackend,

    /// PostgreSQL 连接地址（credentials_backend=postgres 时必填）
    #[serde(default)]
    pub db_url: Option<String>,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_kiro_version() -> String {
    "0.8.0".to_string()
}

fn default_system_version() -> String {
    const SYSTEM_VERSIONS: &[&str] = &["darwin#24.6.0", "win32#10.0.22631"];
    SYSTEM_VERSIONS[fastrand::usize(..SYSTEM_VERSIONS.len())].to_string()
}

fn default_node_version() -> String {
    "22.21.1".to_string()
}

fn default_count_tokens_auth_type() -> String {
    "x-api-key".to_string()
}

fn default_credentials_backend() -> CredentialsBackend {
    CredentialsBackend::File
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            region: default_region(),
            kiro_version: default_kiro_version(),
            machine_id: None,
            api_key: None,
            system_version: default_system_version(),
            node_version: default_node_version(),
            count_tokens_api_url: None,
            count_tokens_api_key: None,
            count_tokens_auth_type: default_count_tokens_auth_type(),
            proxy_url: None,
            proxy_username: None,
            proxy_password: None,
            admin_api_key: None,
            credentials_backend: default_credentials_backend(),
            db_url: None,
        }
    }
}

impl Config {
    /// 获取默认配置文件路径
    pub fn default_config_path() -> &'static str {
        "config.json"
    }

    /// 从文件加载配置
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            // 配置文件不存在，返回默认配置
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)?;
        let mut raw: Value = serde_json::from_str(&content)?;
        expand_env_vars_in_value(&mut raw)?;
        let config: Config = serde_json::from_value(raw)?;
        Ok(config)
    }

    pub fn resolve_db_url(&self) -> anyhow::Result<String> {
        let raw = self
            .db_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("credentials_backend=postgres 时必须配置 dbUrl"))?;
        expand_env_vars(raw)
    }
}

fn expand_env_vars_in_value(value: &mut Value) -> anyhow::Result<()> {
    match value {
        Value::String(raw) => {
            let expanded = expand_env_vars(raw)?;
            *raw = expanded;
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                expand_env_vars_in_value(item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for value in map.values_mut() {
                expand_env_vars_in_value(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn deserialize_port<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct PortVisitor;

    impl<'de> serde::de::Visitor<'de> for PortVisitor {
        type Value = u16;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a u16 or a string containing a u16")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u16::try_from(value).map_err(|_| E::custom("port out of range"))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value < 0 {
                return Err(E::custom("port must be non-negative"));
            }
            u16::try_from(value).map_err(|_| E::custom("port out of range"))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            value.parse::<u16>().map_err(|_| E::custom("invalid port"))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            self.visit_str(&value)
        }
    }

    deserializer.deserialize_any(PortVisitor)
}

fn expand_env_vars(input: &str) -> anyhow::Result<String> {
    let mut result = String::new();
    let mut rest = input;

    while let Some(start) = rest.find("${") {
        result.push_str(&rest[..start]);
        rest = &rest[start + 2..];

        let end = rest
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("环境变量占位符未闭合"))?;
        let key = &rest[..end];
        if key.is_empty() {
            anyhow::bail!("环境变量名不能为空");
        }
        let value = env::var(key)
            .map_err(|_| anyhow::anyhow!("环境变量未设置: {}", key))?;
        result.push_str(&value);
        rest = &rest[end + 1..];
    }

    result.push_str(rest);
    Ok(result)
}
