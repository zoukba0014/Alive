use crate::model::{Extractor, Matcher, Template};

/// Result of checking whether the engine can execute a template today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compatibility {
    /// True if the template has at least one runnable protocol block and no
    /// unsupported matchers/extractors blocking evaluation.
    pub runnable: bool,
    /// Human-readable reasons a template is not (fully) runnable yet.
    pub reasons: Vec<String>,
}

/// Assess a template against the engine's current capabilities:
/// http/tcp/ssl protocol blocks; status/word/regex/size/dsl matchers;
/// regex/dsl extractors. (dns parses but does not execute yet.)
pub fn check_template(t: &Template) -> Compatibility {
    let mut reasons = Vec::new();

    // Unsupported top-level sections. Non-protocol metadata keys are ignored.
    for key in t.extra.keys() {
        if matches!(
            key.as_str(),
            "variables" | "self-contained" | "stop-at-first-match" | "workflows"
        ) {
            continue;
        }
        reasons.push(format!("unsupported protocol/section: `{key}`"));
    }

    let executable = !t.http.is_empty() || !t.tcp.is_empty() || !t.ssl.is_empty();
    if !executable {
        if !t.dns.is_empty() {
            reasons.push("dns block parses but does not execute yet".to_string());
        } else {
            reasons.push("no executable protocol block (http/tcp/ssl)".to_string());
        }
    }

    for (i, req) in t.http.iter().enumerate() {
        if !req.raw.is_empty() {
            reasons.push(format!("http[{i}]: `raw` requests not yet supported"));
        }
        check_matchers("http", i, &req.matchers, &req.extractors, &mut reasons);
    }
    for (i, req) in t.tcp.iter().enumerate() {
        check_matchers("tcp", i, &req.matchers, &req.extractors, &mut reasons);
    }
    for (i, req) in t.ssl.iter().enumerate() {
        check_matchers("ssl", i, &req.matchers, &req.extractors, &mut reasons);
    }

    Compatibility {
        runnable: reasons.is_empty(),
        reasons,
    }
}

fn check_matchers(
    proto: &str,
    i: usize,
    matchers: &[Matcher],
    extractors: &[Extractor],
    reasons: &mut Vec<String>,
) {
    for m in matchers {
        if !m.is_supported() {
            reasons.push(format!("{proto}[{i}]: unsupported matcher type"));
        }
    }
    for e in extractors {
        if !e.is_supported() {
            reasons.push(format!("{proto}[{i}]: unsupported extractor type"));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::load_file;
    use std::io::Write;

    fn write_tmp(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("alive-template-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn parses_and_marks_http_template_runnable() {
        let yaml = r#"
id: demo
info:
  name: Demo
  severity: high
  tags: redis,unauth
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["hello"]
        part: body
"#;
        let p = write_tmp("demo.yaml", yaml);
        let t = load_file(&p).unwrap();
        assert_eq!(t.id, "demo");
        assert_eq!(t.info.tags, vec!["redis", "unauth"]);
        let c = super::check_template(&t);
        assert!(c.runnable, "reasons: {:?}", c.reasons);
    }

    #[test]
    fn dsl_matcher_is_now_runnable() {
        let yaml = r#"
id: dsl-demo
info:
  name: DSL
  severity: info
http:
  - path: ["{{BaseURL}}/"]
    matchers:
      - type: dsl
        dsl: ["len(body) > 0"]
"#;
        let p = write_tmp("dsl.yaml", yaml);
        let t = load_file(&p).unwrap();
        assert!(super::check_template(&t).runnable);
    }

    #[test]
    fn parses_tcp_block_runnable() {
        let yaml = r#"
id: redis-info
info:
  name: Redis INFO
  severity: high
  tags: redis
tcp:
  - inputs:
      - data: "INFO\r\n"
    read-size: 2048
    matchers:
      - type: word
        part: data
        words: ["redis_version"]
"#;
        let p = write_tmp("redis-tcp.yaml", yaml);
        let t = load_file(&p).unwrap();
        assert_eq!(t.tcp.len(), 1);
        assert_eq!(t.tcp[0].inputs[0].data.as_deref(), Some("INFO\r\n"));
        assert!(
            super::check_template(&t).runnable,
            "{:?}",
            super::check_template(&t).reasons
        );
    }

    #[test]
    fn parses_ssl_block_runnable() {
        let yaml = r#"
id: ssl-demo
info:
  name: SSL
  severity: info
ssl:
  - matchers:
      - type: word
        words: ["CN="]
"#;
        let p = write_tmp("ssl.yaml", yaml);
        let t = load_file(&p).unwrap();
        assert_eq!(t.ssl.len(), 1);
        assert!(super::check_template(&t).runnable);
    }
}
