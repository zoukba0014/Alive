use std::net::IpAddr;

use ipnet::IpNet;

/// True if `target` is authorized by at least one entry in `scope`.
///
/// A scope entry matches when: it equals the target string exactly (hostname
/// or literal IP), or it is a CIDR that contains the target's IP, or it is a
/// bare IP equal to the target's IP. An empty scope authorizes nothing.
pub fn target_in_scope(target: &str, scope: &[String]) -> bool {
    let target = target.trim();
    let target_ip: Option<IpAddr> = target.parse().ok();

    scope.iter().any(|entry| {
        let entry = entry.trim();
        if entry == target {
            return true;
        }
        if let (Ok(net), Some(ip)) = (entry.parse::<IpNet>(), target_ip) {
            return net.contains(&ip);
        }
        if let (Ok(entry_ip), Some(ip)) = (entry.parse::<IpAddr>(), target_ip) {
            return entry_ip == ip;
        }
        false
    })
}

/// True only if every target is in scope. Empty target list is vacuously true;
/// an empty scope with any target is false.
pub fn targets_in_scope(targets: &[String], scope: &[String]) -> bool {
    targets.iter().all(|t| target_in_scope(t, scope))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_membership() {
        let scope = vec!["10.0.0.0/8".to_string()];
        assert!(target_in_scope("10.1.2.3", &scope));
        assert!(!target_in_scope("192.168.1.1", &scope));
    }

    #[test]
    fn exact_host_match() {
        let scope = vec!["intranet.local".to_string()];
        assert!(target_in_scope("intranet.local", &scope));
        assert!(!target_in_scope("evil.example.com", &scope));
    }

    #[test]
    fn empty_scope_denies() {
        assert!(!target_in_scope("127.0.0.1", &[]));
    }

    #[test]
    fn all_targets_must_be_in_scope() {
        let scope = vec!["127.0.0.1/32".to_string()];
        assert!(targets_in_scope(&["127.0.0.1".into()], &scope));
        assert!(!targets_in_scope(
            &["127.0.0.1".into(), "8.8.8.8".into()],
            &scope
        ));
    }
}
