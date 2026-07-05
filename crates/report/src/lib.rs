//! Report emitters for [`Finding`]s: JSON, CSV, and a self-contained HTML page.
//!
//! Kept dependency-light: HTML is rendered by string building (no template
//! engine) so there is no build-time template compilation and the output is a
//! single file that opens anywhere. Consumers call [`render`] for a string or
//! [`write_report`] to drop it straight to a path.

use std::path::Path;

use alive_core::{Finding, Severity};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("csv error: {0}")]
    Csv(#[from] csv::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Output format for a findings report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Csv,
    Html,
}

/// Render findings to a string in the given format.
pub fn render(findings: &[Finding], format: ReportFormat) -> Result<String, ReportError> {
    match format {
        ReportFormat::Json => Ok(render_json(findings)?),
        ReportFormat::Csv => render_csv(findings),
        ReportFormat::Html => Ok(render_html(findings)),
    }
}

/// Render findings and write them to `path`.
pub fn write_report(
    findings: &[Finding],
    format: ReportFormat,
    path: impl AsRef<Path>,
) -> Result<(), ReportError> {
    let body = render(findings, format)?;
    std::fs::write(path, body)?;
    Ok(())
}

pub fn render_json(findings: &[Finding]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(findings)
}

/// One row per finding, plus a header. `evidence` is a count; `extracted` is
/// joined with `|` to keep the row on a single CSV field.
pub fn render_csv(findings: &[Finding]) -> Result<String, ReportError> {
    let mut wtr = csv::Writer::from_writer(Vec::new());
    wtr.write_record([
        "template_id",
        "name",
        "severity",
        "target",
        "extracted",
        "evidence",
    ])?;
    for f in findings {
        wtr.write_record([
            f.template_id.as_str(),
            f.name.as_str(),
            f.severity.as_str(),
            &f.target.to_string(),
            &f.extracted.join("|"),
            &f.evidence.len().to_string(),
        ])?;
    }
    let bytes = wtr.into_inner().map_err(|e| e.into_error())?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// A self-contained HTML page: severity summary + findings table.
pub fn render_html(findings: &[Finding]) -> String {
    let mut counts = [0usize; 5]; // info, low, medium, high, critical
    for f in findings {
        counts[sev_index(f.severity)] += 1;
    }
    let summary = format!(
        "critical: {} · high: {} · medium: {} · low: {} · info: {} · total: {}",
        counts[4],
        counts[3],
        counts[2],
        counts[1],
        counts[0],
        findings.len()
    );

    let mut rows = String::new();
    for f in findings {
        rows.push_str(&format!(
            "<tr class=\"sev-{sev}\"><td>{sev}</td><td>{tid}</td><td>{name}</td><td>{target}</td><td>{extracted}</td></tr>\n",
            sev = f.severity.as_str(),
            tid = esc(&f.template_id),
            name = esc(&f.name),
            target = esc(&f.target.to_string()),
            extracted = esc(&f.extracted.join(", ")),
        ));
    }

    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Alive scan report</title><style>\
body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#222}}\
h1{{font-size:1.3rem}}.summary{{margin:.5rem 0 1rem;color:#555}}\
table{{border-collapse:collapse;width:100%}}\
th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #eee;vertical-align:top}}\
th{{background:#fafafa}}\
.sev-critical td:first-child{{color:#b00020;font-weight:600}}\
.sev-high td:first-child{{color:#d35400;font-weight:600}}\
.sev-medium td:first-child{{color:#b8860b}}\
</style></head><body>\
<h1>Alive scan report</h1><div class=\"summary\">{summary}</div>\
<table><thead><tr><th>severity</th><th>template</th><th>name</th><th>target</th><th>extracted</th></tr></thead>\
<tbody>\n{rows}</tbody></table></body></html>"
    )
}

fn sev_index(s: Severity) -> usize {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Minimal HTML-escaping for text placed inside table cells.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alive_core::Target;

    fn sample() -> Vec<Finding> {
        let mut f = Finding::new(
            "redis-unauth",
            "Redis unauthorized",
            Severity::High,
            Target::new("10.0.0.1", Some(6379)),
        );
        f.extracted = vec!["7.0.0".into()];
        vec![
            f,
            Finding::new(
                "http-title",
                "Title <script>",
                Severity::Info,
                Target::new("example.com", None),
            ),
        ]
    }

    #[test]
    fn csv_has_header_plus_one_row_each() {
        let csv = render_csv(&sample()).unwrap();
        // header + 2 findings = 3 non-empty lines
        assert_eq!(csv.lines().filter(|l| !l.is_empty()).count(), 3);
        assert!(csv.contains("redis-unauth"));
    }

    #[test]
    fn html_contains_fields_and_escapes() {
        let html = render_html(&sample());
        assert!(html.contains("redis-unauth"));
        assert!(html.contains("10.0.0.1:6379"));
        assert!(html.contains("total: 2"));
        // the "<script>" in a name must be escaped, not raw
        assert!(html.contains("Title &lt;script&gt;"));
        assert!(!html.contains("Title <script>"));
    }
}
