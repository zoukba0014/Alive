use std::collections::BTreeMap;

use alive_core::Severity;
use serde::{Deserialize, Deserializer};

/// A parsed nuclei-compatible template.
///
/// Executable protocol blocks (`http`, `tcp`, `dns`, `ssl`) are modeled as
/// typed fields; anything else (e.g. `variables`, `workflows`) is captured in
/// `extra` so the compatibility checker can report it without failing the parse.
#[derive(Debug, Clone, Deserialize)]
pub struct Template {
    pub id: String,
    pub info: Info,
    /// nuclei v3 uses `http:`; older templates use `requests:`.
    #[serde(default, alias = "requests")]
    pub http: Vec<HttpRequest>,
    /// nuclei v3 uses `tcp:`; older templates use `network:`.
    #[serde(default, alias = "network")]
    pub tcp: Vec<TcpRequest>,
    #[serde(default)]
    pub dns: Vec<DnsRequest>,
    #[serde(default, alias = "tls")]
    pub ssl: Vec<SslRequest>,
    /// Any other top-level keys (e.g. `variables`, `workflows`).
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_yaml_ng::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Info {
    pub name: String,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default = "default_severity", deserialize_with = "de_severity")]
    pub severity: Severity,
    /// nuclei stores tags as a comma-separated string; we normalize to a list.
    #[serde(default, deserialize_with = "de_tags")]
    pub tags: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpRequest {
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub raw: Vec<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Condition,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

/// A TCP/network request block: send `inputs`, read the reply, match on `data`.
#[derive(Debug, Clone, Deserialize)]
pub struct TcpRequest {
    #[serde(default)]
    pub inputs: Vec<TcpInput>,
    /// nuclei `host` templating (e.g. `{{Hostname}}`); informational for us.
    #[serde(default)]
    pub host: Vec<String>,
    #[serde(default, rename = "read-size")]
    pub read_size: Option<usize>,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Condition,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcpInput {
    /// Bytes to send. Double-quoted YAML escapes (`\r\n`) are decoded by the
    /// YAML parser; the engine additionally decodes `\xNN`/`\r`/`\n` at runtime.
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub read: Option<usize>,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
}

/// A DNS request block.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "type")]
    pub qtype: Option<String>,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Condition,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

/// An SSL/TLS request block: connect and match on certificate fields.
#[derive(Debug, Clone, Deserialize)]
pub struct SslRequest {
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default, rename = "matchers-condition")]
    pub matchers_condition: Condition,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

/// Which portion of the response a matcher/extractor inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Part {
    #[default]
    Body,
    Header,
    /// nuclei's `all` / `response` — status line + headers + body.
    #[serde(alias = "response")]
    All,
    /// tcp/network primary payload (`raw`/`data`).
    #[serde(alias = "raw")]
    Data,
}

/// How multiple words/regexes (or matchers) combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
    #[default]
    And,
    Or,
}

/// A response matcher. Unsupported nuclei types (binary, dsl, ...) parse into
/// [`Matcher::Unsupported`] so the checker can flag them; M3 adds `dsl`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Matcher {
    Status {
        status: Vec<u16>,
        #[serde(default)]
        negative: bool,
    },
    Word {
        words: Vec<String>,
        #[serde(default)]
        part: Part,
        #[serde(default)]
        condition: Condition,
        #[serde(default)]
        negative: bool,
    },
    Regex {
        regex: Vec<String>,
        #[serde(default)]
        part: Part,
        #[serde(default)]
        condition: Condition,
        #[serde(default)]
        negative: bool,
    },
    Size {
        size: Vec<usize>,
        #[serde(default)]
        negative: bool,
    },
    Dsl {
        dsl: Vec<String>,
        #[serde(default)]
        condition: Condition,
        #[serde(default)]
        negative: bool,
    },
    #[serde(other)]
    Unsupported,
}

impl Matcher {
    pub fn is_supported(&self) -> bool {
        !matches!(self, Matcher::Unsupported)
    }
}

/// A response extractor. Only `regex` executes in M1.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Extractor {
    Regex {
        regex: Vec<String>,
        #[serde(default)]
        part: Part,
        #[serde(default)]
        group: Option<usize>,
        #[serde(default)]
        name: Option<String>,
    },
    Dsl {
        dsl: Vec<String>,
        #[serde(default)]
        name: Option<String>,
    },
    #[serde(other)]
    Unsupported,
}

impl Extractor {
    pub fn is_supported(&self) -> bool {
        !matches!(self, Extractor::Unsupported)
    }
}

fn default_method() -> String {
    "GET".to_string()
}

fn default_severity() -> Severity {
    Severity::Info
}

/// Lenient severity parsing: unknown/`unknown` values fall back to `Info`
/// rather than failing the whole template.
fn de_severity<'de, D>(d: D) -> Result<Severity, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    Ok(match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    })
}

/// Accept either a comma-separated string (`"a,b"`) or a YAML list.
fn de_tags<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Tags {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<Tags>::deserialize(d)? {
        None => Vec::new(),
        Some(Tags::One(s)) => s
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect(),
        Some(Tags::Many(v)) => v,
    })
}
