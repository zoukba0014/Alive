use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// A single scan target: a host (IP or name) with an optional port.
///
/// This is the atomic unit produced by target expansion (CIDR/range parsing
/// lives in a later crate) and consumed by protocol runners. Deliberately
/// does not resolve DNS or validate reachability — it is just addressing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target {
    pub host: String,
    pub port: Option<u16>,
}

impl Target {
    pub fn new(host: impl Into<String>, port: Option<u16>) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

impl FromStr for Target {
    type Err = Error;

    /// Parse `host` or `host:port`. IPv6 literals must be bracketed
    /// (`[::1]:80`) when a port is present.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(Error::InvalidTarget(s.to_string()));
        }

        // Bracketed IPv6 with optional port: [addr] or [addr]:port
        if let Some(rest) = s.strip_prefix('[') {
            let (addr, tail) = rest
                .split_once(']')
                .ok_or_else(|| Error::InvalidTarget(s.to_string()))?;
            let port = match tail {
                "" => None,
                p => Some(
                    p.strip_prefix(':')
                        .and_then(|n| n.parse().ok())
                        .ok_or_else(|| Error::InvalidTarget(s.to_string()))?,
                ),
            };
            return Ok(Target::new(addr, port));
        }

        // host:port only when there is exactly one colon (avoids splitting
        // bare IPv6 literals like `::1`).
        if s.matches(':').count() == 1 {
            if let Some((host, port)) = s.split_once(':') {
                let port: u16 = port
                    .parse()
                    .map_err(|_| Error::InvalidTarget(s.to_string()))?;
                return Ok(Target::new(host, Some(port)));
            }
        }

        Ok(Target::new(s, None))
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(p) => write!(f, "{}:{}", self.host, p),
            None => f.write_str(&self.host),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_only() {
        let t: Target = "10.0.0.1".parse().unwrap();
        assert_eq!(t, Target::new("10.0.0.1", None));
    }

    #[test]
    fn parses_host_port() {
        let t: Target = "10.0.0.1:6379".parse().unwrap();
        assert_eq!(t, Target::new("10.0.0.1", Some(6379)));
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        let t: Target = "[::1]:80".parse().unwrap();
        assert_eq!(t, Target::new("::1", Some(80)));
    }

    #[test]
    fn bare_ipv6_has_no_port() {
        let t: Target = "::1".parse().unwrap();
        assert_eq!(t, Target::new("::1", None));
    }

    #[test]
    fn rejects_empty() {
        assert!("".parse::<Target>().is_err());
    }
}
