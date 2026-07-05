use crate::model::{Matcher, Template};

/// Result of checking whether the engine can execute a template today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compatibility {
    /// True if the template has at least one runnable http request and no
    /// unsupported matchers/extractors blocking evaluation.
    pub runnable: bool,
    /// Human-readable reasons a template is not (fully) runnable yet.
    pub reasons: Vec<String>,
}

/// Assess a template against the engine's current capabilities (M1: http only,
/// status/word/regex/size matchers, regex extractor).
pub fn check_template(t: &Template) -> Compatibility {
    let mut reasons = Vec::new();

    // Unsupported top-level protocol blocks (tcp/dns/ssl/... arrive in M3).
    for key in t.extra.keys() {
        // Common non-protocol metadata keys we simply ignore.
        if matches!(
            key.as_str(),
            "variables" | "self-contained" | "stop-at-first-match"
        ) {
            continue;
        }
        reasons.push(format!("unsupported protocol/section: `{key}`"));
    }

    if t.http.is_empty() {
        reasons.push("no http block (only http is executable in M1)".to_string());
    }

    for (i, req) in t.http.iter().enumerate() {
        if !req.raw.is_empty() {
            reasons.push(format!("http[{i}]: `raw` requests not yet supported"));
        }
        for m in &req.matchers {
            if !m.is_supported() {
                reasons.push(format!("http[{i}]: unsupported matcher type"));
            }
            if let Matcher::Unsupported = m {
                // already covered above
            }
        }
        for e in &req.extractors {
            if !e.is_supported() {
                reasons.push(format!("http[{i}]: unsupported extractor type"));
            }
        }
    }

    Compatibility {
        runnable: reasons.is_empty(),
        reasons,
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
    fn flags_dsl_matcher_as_unsupported() {
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
        let c = super::check_template(&t);
        assert!(!c.runnable);
    }
}
