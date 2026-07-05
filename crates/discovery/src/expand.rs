use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExpandError {
    #[error("`{0}` is not an IP, CIDR, or range spec")]
    NotAnIpSpec(String),
    #[error("invalid range `{0}`")]
    InvalidRange(String),
}

/// Expand an IP-based target spec into concrete addresses.
///
/// Supported forms:
/// - single IP: `10.0.0.5`, `::1`
/// - CIDR: `10.0.0.0/24` (IPv4 CIDR yields host addresses, excluding network
///   and broadcast; IPv6 yields all addresses in the prefix)
/// - full-range: `10.0.0.1-10.0.0.50` (inclusive, iterated as u32)
/// - per-octet range: `192.168.0-2.0`, `10.0.0.1-50` (any octet may be `a-b`)
///
/// Hostnames are *not* expanded here (they need DNS); callers resolve those
/// separately. Returns [`ExpandError::NotAnIpSpec`] for non-IP input so the
/// caller can fall back to hostname resolution.
pub fn expand(spec: &str) -> Result<Vec<IpAddr>, ExpandError> {
    let spec = spec.trim();

    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    if spec.contains('/') {
        let net: IpNet = spec
            .parse()
            .map_err(|_| ExpandError::NotAnIpSpec(spec.to_string()))?;
        return match net {
            // `hosts()` excludes network/broadcast for IPv4 prefixes < /31.
            IpNet::V4(_) => Ok(net.hosts().collect()),
            IpNet::V6(_) => Ok(net.hosts().collect()),
        };
    }

    if spec.contains('-') {
        return expand_range(spec);
    }

    Err(ExpandError::NotAnIpSpec(spec.to_string()))
}

fn expand_range(spec: &str) -> Result<Vec<IpAddr>, ExpandError> {
    // Form 1: full start-end IPv4 range, e.g. `10.0.0.1-10.0.0.50`.
    if let Some((a, b)) = spec.split_once('-') {
        if let (Ok(start), Ok(end)) = (a.parse::<Ipv4Addr>(), b.parse::<Ipv4Addr>()) {
            let (s, e) = (u32::from(start), u32::from(end));
            if s > e {
                return Err(ExpandError::InvalidRange(spec.to_string()));
            }
            return Ok((s..=e).map(|n| IpAddr::V4(Ipv4Addr::from(n))).collect());
        }
    }

    // Form 2: per-octet ranges, e.g. `192.168.0-2.0` or `10.0.0.1-50`.
    let octets: Vec<&str> = spec.split('.').collect();
    if octets.len() != 4 {
        return Err(ExpandError::InvalidRange(spec.to_string()));
    }
    let mut ranges: Vec<(u8, u8)> = Vec::with_capacity(4);
    for oct in octets {
        let (lo, hi) = match oct.split_once('-') {
            Some((lo, hi)) => (
                lo.parse::<u8>()
                    .map_err(|_| ExpandError::InvalidRange(spec.to_string()))?,
                hi.parse::<u8>()
                    .map_err(|_| ExpandError::InvalidRange(spec.to_string()))?,
            ),
            None => {
                let v = oct
                    .parse::<u8>()
                    .map_err(|_| ExpandError::InvalidRange(spec.to_string()))?;
                (v, v)
            }
        };
        if lo > hi {
            return Err(ExpandError::InvalidRange(spec.to_string()));
        }
        ranges.push((lo, hi));
    }

    let mut out = Vec::new();
    for a in ranges[0].0..=ranges[0].1 {
        for b in ranges[1].0..=ranges[1].1 {
            for c in ranges[2].0..=ranges[2].1 {
                for d in ranges[3].0..=ranges[3].1 {
                    out.push(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_ip() {
        assert_eq!(expand("10.0.0.5").unwrap().len(), 1);
    }

    #[test]
    fn cidr_24_yields_254_hosts() {
        assert_eq!(expand("192.168.1.0/24").unwrap().len(), 254);
    }

    #[test]
    fn cidr_30_yields_2_hosts() {
        assert_eq!(expand("10.0.0.0/30").unwrap().len(), 2);
    }

    #[test]
    fn full_range_inclusive() {
        assert_eq!(expand("10.0.0.1-10.0.0.50").unwrap().len(), 50);
    }

    #[test]
    fn last_octet_range() {
        assert_eq!(expand("10.0.0.1-50").unwrap().len(), 50);
    }

    #[test]
    fn third_octet_range() {
        // 192.168.{0,1,2}.0 => 3 addresses
        assert_eq!(expand("192.168.0-2.0").unwrap().len(), 3);
    }

    #[test]
    fn hostname_is_rejected() {
        assert!(matches!(
            expand("example.com"),
            Err(ExpandError::NotAnIpSpec(_))
        ));
    }
}
