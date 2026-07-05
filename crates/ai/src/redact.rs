//! Redaction of internal identifiers before findings leave the network.
//!
//! Used two ways by the router: [`contains_sensitive`] decides whether a
//! finding must stay on the local provider, and [`redact`] masks internal
//! IPs/hostnames when a finding is sent to the cloud with redaction enabled.

use std::net::Ipv4Addr;
use std::sync::OnceLock;

use regex::Regex;

const MASK: &str = "[REDACTED]";

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap())
}

fn internal_host_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // hostnames ending in `.internal` or `.local` (case-insensitive).
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:internal|local)\b").unwrap()
    })
}

/// True when the address is an internal / non-routable IPv4 (RFC1918 or loopback).
fn is_internal_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback()
}

/// Mask internal IPv4 addresses (RFC1918/loopback) and `.internal`/`.local`
/// hostnames in `text`. Public IPs are left intact.
pub fn redact(text: &str) -> String {
    let masked_ips = ipv4_re().replace_all(text, |caps: &regex::Captures| {
        match caps[0].parse::<Ipv4Addr>() {
            Ok(ip) if is_internal_ipv4(ip) => MASK.to_string(),
            _ => caps[0].to_string(),
        }
    });
    internal_host_re()
        .replace_all(&masked_ips, MASK)
        .into_owned()
}

/// True when `text` contains an internal IPv4 or an internal hostname.
pub fn contains_sensitive(text: &str) -> bool {
    if internal_host_re().is_match(text) {
        return true;
    }
    ipv4_re()
        .find_iter(text)
        .filter_map(|m| m.as_str().parse::<Ipv4Addr>().ok())
        .any(is_internal_ipv4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_rfc1918_and_internal_hosts() {
        let out = redact("host db01.internal at 10.0.0.5 and 172.16.3.4 and 192.168.1.9");
        assert!(!out.contains("10.0.0.5"));
        assert!(!out.contains("172.16.3.4"));
        assert!(!out.contains("192.168.1.9"));
        assert!(!out.contains("db01.internal"));
        assert_eq!(out.matches(MASK).count(), 4);
    }

    #[test]
    fn leaves_public_ips_intact() {
        let out = redact("cdn at 8.8.8.8 and 1.1.1.1");
        assert!(out.contains("8.8.8.8"));
        assert!(out.contains("1.1.1.1"));
        assert!(!out.contains(MASK));
    }

    #[test]
    fn contains_sensitive_detects_internal() {
        assert!(contains_sensitive("connect to 10.1.2.3"));
        assert!(contains_sensitive("gw.corp.local"));
        assert!(!contains_sensitive("example.com at 93.184.216.34"));
    }
}
