use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on for clients, e.g. "0.0.0.0:7777".
    pub listen: String,
    /// Where session definitions and spilled backlog live.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Argon2 PHC string; generate with `mbnc hash-password`.
    pub password_hash: String,
    /// TLS for client connections. Required unless `allow_plaintext = true`.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Accept unencrypted client connections when no [tls] section is given.
    /// Only sensible behind a VPN / SSH tunnel / stunnel, or for testing.
    #[serde(default)]
    pub allow_plaintext: bool,
    #[serde(default)]
    pub backlog: BacklogConfig,
    #[serde(default)]
    pub reconnect: ReconnectConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain.
    pub cert: PathBuf,
    /// PEM private key (PKCS#8, PKCS#1 or SEC1).
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BacklogConfig {
    /// Buffered output kept in memory per session before spilling to disk.
    pub memory_bytes: usize,
    /// Size at which the on-disk backlog file is rotated. At most two files
    /// are kept, so up to ~2x this much is retained; older output is dropped.
    pub disk_bytes: u64,
}

impl Default for BacklogConfig {
    fn default() -> Self {
        BacklogConfig { memory_bytes: 1024 * 1024, disk_bytes: 32 * 1024 * 1024 }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ReconnectConfig {
    /// Automatically reconnect (and re-run the login script) when the M*
    /// drops the connection while no client is attached.
    pub enabled: bool,
    pub initial_delay_secs: u64,
    pub max_delay_secs: u64,
    /// Abandon the login script if it hasn't completed after this long.
    pub login_timeout_secs: u64,
    /// Give up on a TCP/TLS connection attempt after this long.
    pub connect_timeout_secs: u64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        ReconnectConfig {
            enabled: true,
            initial_delay_secs: 10,
            max_delay_secs: 300,
            login_timeout_secs: 60,
            connect_timeout_secs: 30,
        }
    }
}

impl ReconnectConfig {
    pub fn initial_delay(&self) -> Duration {
        Duration::from_secs(self.initial_delay_secs.max(1))
    }
    pub fn max_delay(&self) -> Duration {
        Duration::from_secs(self.max_delay_secs.max(self.initial_delay_secs).max(1))
    }
    pub fn login_timeout(&self) -> Duration {
        Duration::from_secs(self.login_timeout_secs.max(1))
    }
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs.max(1))
    }
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("data")
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        // Resolve relative paths against the config file's directory.
        let base = path.parent().unwrap_or(Path::new("."));
        cfg.data_dir = base.join(&cfg.data_dir);
        if let Some(tls) = cfg.tls.as_mut() {
            tls.cert = base.join(&tls.cert);
            tls.key = base.join(&tls.key);
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.tls.is_none() && !self.allow_plaintext {
            bail!("no [tls] section configured; set allow_plaintext = true to run without TLS");
        }
        argon2::PasswordHash::new(&self.password_hash)
            .map_err(|e| anyhow::anyhow!("password_hash is not a valid PHC string: {e}"))?;
        Ok(())
    }
}
