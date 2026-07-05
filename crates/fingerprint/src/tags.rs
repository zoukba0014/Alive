/// Map a detected service (and optional banner) to nuclei `info.tags`.
///
/// The result is used to route POC execution: a template runs against an asset
/// only if its tags intersect these. Banner keywords add finer tags (e.g.
/// `nginx`, `openssh`) on top of the coarse service tag.
pub fn tags_for(service: &str, banner: Option<&str>) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();

    // Coarse service → base tag(s).
    match service {
        "http" | "https" => tags.push("http".into()),
        "postgres" => {
            tags.push("postgresql".into());
            tags.push("postgres".into());
        }
        "msrpc" => tags.push("rpc".into()),
        other if !other.is_empty() && other != "unknown" => tags.push(other.into()),
        _ => {}
    }

    // Banner keywords → product/software tags.
    if let Some(b) = banner {
        let lower = b.to_ascii_lowercase();
        for (needle, tag) in [
            ("nginx", "nginx"),
            ("apache", "apache"),
            ("openssh", "openssh"),
            ("microsoft-iis", "iis"),
            ("tomcat", "tomcat"),
            ("jetty", "jetty"),
            ("mysql", "mysql"),
            ("redis", "redis"),
        ] {
            if lower.contains(needle) {
                tags.push(tag.into());
            }
        }
    }

    tags.sort();
    tags.dedup();
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_maps_to_http_tag() {
        assert_eq!(tags_for("https", None), vec!["http".to_string()]);
    }

    #[test]
    fn redis_service_tag() {
        assert_eq!(tags_for("redis", None), vec!["redis".to_string()]);
    }

    #[test]
    fn banner_adds_software_tag() {
        let tags = tags_for("http", Some("Server: nginx/1.25.0"));
        assert!(tags.contains(&"http".to_string()));
        assert!(tags.contains(&"nginx".to_string()));
    }

    #[test]
    fn unknown_service_yields_no_tags() {
        assert!(tags_for("unknown", None).is_empty());
    }
}
