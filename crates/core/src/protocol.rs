use serde::{Deserialize, Serialize};

/// Network protocol a request/probe speaks.
///
/// Mirrors the nuclei template protocol blocks we intend to support. `Http`
/// lands first (M1); the rest come online in M3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Tcp,
    Dns,
    Tls,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Tcp => "tcp",
            Protocol::Dns => "dns",
            Protocol::Tls => "tls",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
