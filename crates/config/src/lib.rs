//! Global scanner configuration, loaded from YAML.
//!
//! Kept small in M1 (scan-level knobs). Later milestones extend this with
//! `fingerprint`, `ai`, and `fleet` sections — add nested structs with
//! `#[serde(default)]` so old config files keep working.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml parse error: {0}")]
    Parse(#[from] serde_yaml_ng::Error),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub scan: ScanConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Max concurrent in-flight requests.
    pub concurrency: usize,
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
    /// Whether HTTP runners follow redirects.
    pub follow_redirects: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 100,
            timeout_secs: 10,
            follow_redirects: true,
        }
    }
}

impl Config {
    /// Load config from a YAML file path.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)?;
        Ok(serde_yaml_ng::from_str(&text)?)
    }
}
