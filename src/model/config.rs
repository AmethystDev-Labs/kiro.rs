use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use regex::Regex;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CredentialsBackend {
    File,
    Postgres,
}

impl Default for CredentialsBackend {
    fn default() -> Self {
        Self::File
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsBackend {
    Rustls,
    NativeTls,
}

impl Default for TlsBackend {
    fn default() -> Self {
        Self::Rustls
    }
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

    #[serde(default = "default_tls_backend", deserialize_with = "deserialize_tls_backend")]
    pub tls_backend: TlsBackend,

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

    /// 凭据后端类型
    #[serde(default, deserialize_with = "deserialize_credentials_backend")]
    pub credentials_backend: CredentialsBackend,

    /// PostgreSQL 连接地址
    #[serde(default)]
    pub db_url: Option<String>,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

fn deserialize_port<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct PortVisitor;

    impl<'de> Visitor<'de> for PortVisitor {
        type Value = u16;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a port number or a string containing a port number or environment variable")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value <= u16::MAX as u64 {
                Ok(value as u16)
            } else {
                Err(E::custom(format!("port out of range: {}", value)))
            }
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value >= 0 && value <= u16::MAX as i64 {
                Ok(value as u16)
            } else {
                Err(E::custom(format!("port out of range: {}", value)))
            }
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let resolved = Config::resolve_env(value);
            resolved.parse::<u16>().map_err(|e| E::custom(format!("invalid port: {}. Error: {}", resolved, e)))
        }
    }

    deserializer.deserialize_any(PortVisitor)
}

fn deserialize_tls_backend<'de, D>(deserializer: D) -> Result<TlsBackend, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct TlsBackendVisitor;

    impl<'de> Visitor<'de> for TlsBackendVisitor {
        type Value = TlsBackend;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string representing TlsBackend or environment variable")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let resolved = Config::resolve_env(value);
            match resolved.to_lowercase().as_str() {
                "rustls" => Ok(TlsBackend::Rustls),
                "native-tls" | "nativetls" => Ok(TlsBackend::NativeTls),
                _ => Err(E::custom(format!("invalid tlsBackend: {}", resolved))),
            }
        }
    }

    deserializer.deserialize_str(TlsBackendVisitor)
}

fn deserialize_credentials_backend<'de, D>(deserializer: D) -> Result<CredentialsBackend, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct CredentialsBackendVisitor;

    impl<'de> Visitor<'de> for CredentialsBackendVisitor {
        type Value = CredentialsBackend;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string representing CredentialsBackend or environment variable")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let resolved = Config::resolve_env(value);
            match resolved.to_lowercase().as_str() {
                "file" => Ok(CredentialsBackend::File),
                "postgres" | "postgresql" => Ok(CredentialsBackend::Postgres),
                _ => Err(E::custom(format!("invalid credentialsBackend: {}", resolved))),
            }
        }
    }

    deserializer.deserialize_str(CredentialsBackendVisitor)
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

fn default_tls_backend() -> TlsBackend {
    TlsBackend::Rustls
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
            tls_backend: default_tls_backend(),
            count_tokens_api_url: None,
            count_tokens_api_key: None,
            count_tokens_auth_type: default_count_tokens_auth_type(),
            proxy_url: None,
            proxy_username: None,
            proxy_password: None,
            admin_api_key: None,
            credentials_backend: CredentialsBackend::default(),
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
        let mut config: Config = serde_json::from_str(&content)?;
        config.resolve_all_env();
        Ok(config)
    }

    /// 解析字符串中的环境变量 ${ENV}
    pub fn resolve_env(value: &str) -> String {
        let re = Regex::new(r"\$\{([^}]+)\}").unwrap();
        re.replace_all(value, |caps: &regex::Captures| {
            let key = &caps[1];
            env::var(key).unwrap_or_else(|_| caps[0].to_string())
        })
        .to_string()
    }

    /// 解析 Option<String> 中的环境变量
    pub fn resolve_env_opt(value: Option<String>) -> Option<String> {
        value.map(|s| Self::resolve_env(&s))
    }

    /// 对所有字段应用环境变量解析
    pub fn resolve_all_env(&mut self) {
        if let Some(val) = self.machine_id.as_ref() {
            self.machine_id = Some(Self::resolve_env(val));
        }
        if let Some(val) = self.api_key.as_ref() {
            self.api_key = Some(Self::resolve_env(val));
        }
        if let Some(val) = self.count_tokens_api_url.as_ref() {
            self.count_tokens_api_url = Some(Self::resolve_env(val));
        }
        if let Some(val) = self.count_tokens_api_key.as_ref() {
            self.count_tokens_api_key = Some(Self::resolve_env(val));
        }
        if let Some(val) = self.proxy_url.as_ref() {
            self.proxy_url = Some(Self::resolve_env(val));
        }
        if let Some(val) = self.proxy_username.as_ref() {
            self.proxy_username = Some(Self::resolve_env(val));
        }
        if let Some(val) = self.proxy_password.as_ref() {
            self.proxy_password = Some(Self::resolve_env(val));
        }
        if let Some(val) = self.admin_api_key.as_ref() {
            self.admin_api_key = Some(Self::resolve_env(val));
        }
        if let Some(val) = self.db_url.as_ref() {
            self.db_url = Some(Self::resolve_env(val));
        }
        
        self.host = Self::resolve_env(&self.host);
        self.region = Self::resolve_env(&self.region);
        self.kiro_version = Self::resolve_env(&self.kiro_version);
        self.system_version = Self::resolve_env(&self.system_version);
        self.node_version = Self::resolve_env(&self.node_version);
        self.count_tokens_auth_type = Self::resolve_env(&self.count_tokens_auth_type);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_resolve_env() {
        unsafe {
            env::set_var("TEST_HOST", "1.2.3.4");
            env::set_var("TEST_PORT", "9999");
        }
        
        assert_eq!(Config::resolve_env("${TEST_HOST}"), "1.2.3.4");
        assert_eq!(Config::resolve_env("http://${TEST_HOST}:${TEST_PORT}"), "http://1.2.3.4:9999");
        assert_eq!(Config::resolve_env("${NON_EXISTENT}"), "${NON_EXISTENT}");
    }

    #[test]
    fn test_config_resolve_all_env() {
        unsafe {
            env::set_var("KIRO_REGION", "us-west-2");
            env::set_var("KIRO_API_KEY", "secret-key");
        }

        let mut config = Config::default();
        config.region = "${KIRO_REGION}".to_string();
        config.api_key = Some("${KIRO_API_KEY}".to_string());
        
        config.resolve_all_env();

        assert_eq!(config.region, "us-west-2");
        assert_eq!(config.api_key, Some("secret-key".to_string()));
    }

    #[test]
    fn test_deserialize_port() {
        unsafe {
            env::set_var("KIRO_PORT", "9090");
        }
        
        let json = r#"{"port": "${KIRO_PORT}"}"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.port, 9090);

        let json_num = r#"{"port": 8888}"#;
        let config_num: Config = serde_json::from_str(json_num).unwrap();
        assert_eq!(config_num.port, 8888);
    }

    #[test]
    fn test_deserialize_enums() {
        unsafe {
            env::set_var("KIRO_TLS", "native-tls");
            env::set_var("KIRO_BACKEND", "postgres");
        }

        let json = r#"{
            "tlsBackend": "${KIRO_TLS}",
            "credentialsBackend": "${KIRO_BACKEND}"
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.tls_backend, TlsBackend::NativeTls);
        assert_eq!(config.credentials_backend, CredentialsBackend::Postgres);
    }
}
