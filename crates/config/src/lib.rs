//! Global scanner configuration, loaded from YAML.
//!
//! Kept small in M1 (scan-level knobs). Later milestones extend this with
//! `fingerprint`, `ai`, and `fleet` sections — add nested structs with
//! `#[serde(default)]` so old config files keep working.

use alive_core::Severity;
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
    pub ai: AiConfig,
}

/// Which provider tier to use. Mirrored by `alive-ai::ProviderKind`; kept as a
/// plain enum here so the config crate doesn't depend on the AI/http crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderChoice {
    /// On-prem model — data never leaves the network (the safe default).
    #[default]
    Local,
    /// Cloud model (e.g. Claude).
    Cloud,
}

/// AI triage settings. Disabled by default; a finding is only sent to an LLM
/// when `enabled` (or the `--ai` flag) is set and it meets `min_severity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    pub enabled: bool,
    /// Only triage findings at or above this severity.
    pub min_severity: Severity,
    /// Provider used when nothing forces a choice.
    pub default_provider: ProviderChoice,
    pub providers: ProvidersConfig,
    pub routing: RoutingConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProvidersConfig {
    pub local: LocalProviderConfig,
    pub claude: ClaudeProviderConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalProviderConfig {
    /// OpenAI-compatible base URL (Ollama default shown).
    pub base_url: String,
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClaudeProviderConfig {
    /// `claude-opus-4-8` (default), `claude-sonnet-4-6`, or `claude-haiku-4-5`.
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    /// Where sensitive (internal) findings must go. Hard security boundary.
    pub sensitive_data: ProviderChoice,
    /// Mask internal IPs/hostnames before sending to the cloud.
    pub redact_before_cloud: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_severity: Severity::Medium,
            default_provider: ProviderChoice::Local,
            providers: ProvidersConfig::default(),
            routing: RoutingConfig::default(),
        }
    }
}

impl Default for LocalProviderConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:11434/v1".to_string(),
            model: "qwen2.5:14b".to_string(),
        }
    }
}

impl Default for ClaudeProviderConfig {
    fn default() -> Self {
        Self {
            model: "claude-opus-4-8".to_string(),
        }
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            sensitive_data: ProviderChoice::Local,
            redact_before_cloud: true,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_defaults_are_safe() {
        let c = Config::default();
        assert!(!c.ai.enabled);
        assert_eq!(c.ai.min_severity, Severity::Medium);
        assert_eq!(c.ai.default_provider, ProviderChoice::Local);
        assert_eq!(c.ai.routing.sensitive_data, ProviderChoice::Local);
        assert!(c.ai.routing.redact_before_cloud);
    }

    #[test]
    fn partial_yaml_keeps_defaults() {
        // Only the scan section present → ai fills in from defaults.
        let c: Config = serde_yaml_ng::from_str("scan:\n  concurrency: 20\n").unwrap();
        assert_eq!(c.scan.concurrency, 20);
        assert!(!c.ai.enabled);
        assert_eq!(c.ai.providers.claude.model, "claude-opus-4-8");
    }

    #[test]
    fn ai_section_round_trips() {
        let yaml = "ai:\n  enabled: true\n  default_provider: cloud\n  routing:\n    sensitive_data: local\n";
        let c: Config = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(c.ai.enabled);
        assert_eq!(c.ai.default_provider, ProviderChoice::Cloud);
        let round = serde_yaml_ng::to_string(&c).unwrap();
        let c2: Config = serde_yaml_ng::from_str(&round).unwrap();
        assert_eq!(c2.ai.default_provider, ProviderChoice::Cloud);
    }
}
