use serde::{Deserialize, Serialize};

/// Severity of a finding, ordered from least to most serious.
///
/// The ordering is meaningful: `Info < Low < Medium < High < Critical`, so
/// severity thresholds (e.g. "only AI-triage Medium and above") are just
/// comparisons. Matches the nuclei `info.severity` vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Lowercase label as used in nuclei templates and reports.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_ascending_by_seriousness() {
        assert!(Severity::Info < Severity::Critical);
        assert!(Severity::Medium >= Severity::Medium);
    }
}
