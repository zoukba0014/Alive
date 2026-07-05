use alive_core::Evidence;
use alive_dsl::{eval_bool, eval_string, DslValue, VarMap};
use alive_template::{Condition, Extractor, HttpRequest, Matcher, Part};
use regex::Regex;

use crate::http::HttpResponse;

/// Protocol-agnostic view of a response that matchers/extractors evaluate
/// against. HTTP, TCP, and TLS runners all build one of these, so matcher logic
/// (including `dsl:`) lives in exactly one place.
pub struct MatchInput {
    /// HTTP status; `None` for tcp/tls.
    pub status: Option<u16>,
    /// Primary payload: http body, tcp data, or rendered cert fields.
    pub body: String,
    /// Header text (http only; empty otherwise).
    pub header: String,
    /// Variables exposed to `dsl:` expressions.
    pub vars: VarMap,
}

impl MatchInput {
    /// Build from an HTTP response (status/body/headers + dsl vars).
    pub fn from_http(resp: &HttpResponse) -> Self {
        let header = resp.header_text();
        let mut vars = VarMap::new();
        vars.insert("status_code".into(), DslValue::Int(resp.status as i64));
        vars.insert("body".into(), DslValue::Str(resp.body.clone()));
        vars.insert("header".into(), DslValue::Str(header.clone()));
        vars.insert("all_headers".into(), DslValue::Str(header.clone()));
        vars.insert(
            "content_length".into(),
            DslValue::Int(resp.body.len() as i64),
        );
        Self {
            status: Some(resp.status),
            body: resp.body.clone(),
            header,
            vars,
        }
    }

    /// Build from a raw payload (tcp `data`, or rendered tls cert fields).
    pub fn from_data(data: &str) -> Self {
        let mut vars = VarMap::new();
        vars.insert("data".into(), DslValue::Str(data.to_string()));
        vars.insert("body".into(), DslValue::Str(data.to_string()));
        vars.insert("content_length".into(), DslValue::Int(data.len() as i64));
        Self {
            status: None,
            body: data.to_string(),
            header: String::new(),
            vars,
        }
    }

    fn part_text(&self, part: Part) -> String {
        match part {
            Part::Body | Part::Data => self.body.clone(),
            Part::Header => self.header.clone(),
            Part::All => format!("{}\n{}", self.header, self.body),
        }
    }
}

/// Evaluate matchers (+ extractors on success) against an input. Returns the
/// evidence snippets and extracted values on a match.
pub(crate) fn evaluate(
    matchers: &[Matcher],
    condition: Condition,
    extractors: &[Extractor],
    input: &MatchInput,
) -> Option<(Vec<Evidence>, Vec<String>)> {
    if matchers.is_empty() {
        return None;
    }

    let mut evidence = Vec::new();
    let mut any = false;
    let mut all = true;
    for m in matchers {
        let (matched, ev) = eval_matcher(m, input);
        any |= matched;
        all &= matched;
        if matched {
            evidence.extend(ev);
        }
    }

    let ok = match condition {
        Condition::And => all,
        Condition::Or => any,
    };
    if !ok {
        return None;
    }

    let extracted = extractors
        .iter()
        .flat_map(|e| run_extractor(e, input))
        .collect();
    Some((evidence, extracted))
}

/// HTTP convenience wrapper used by `run_http_template` and the clustering path.
/// Public so benchmarks can exercise the hot matcher path directly.
pub fn evaluate_http(
    req: &HttpRequest,
    resp: &HttpResponse,
) -> Option<(Vec<Evidence>, Vec<String>)> {
    let input = MatchInput::from_http(resp);
    evaluate(
        &req.matchers,
        req.matchers_condition,
        &req.extractors,
        &input,
    )
}

fn eval_matcher(m: &Matcher, input: &MatchInput) -> (bool, Vec<Evidence>) {
    match m {
        Matcher::Status { status, negative } => {
            let hit = input.status.map(|s| status.contains(&s)).unwrap_or(false);
            let ev = input
                .status
                .map(|s| {
                    vec![Evidence {
                        part: "status".into(),
                        snippet: s.to_string(),
                    }]
                })
                .unwrap_or_default();
            (hit ^ negative, if hit { ev } else { vec![] })
        }
        Matcher::Word {
            words,
            part,
            condition,
            negative,
        } => {
            let text = input.part_text(*part);
            let hits: Vec<&String> = words.iter().filter(|w| text.contains(w.as_str())).collect();
            let matched = match condition {
                Condition::And => hits.len() == words.len(),
                Condition::Or => !hits.is_empty(),
            };
            let ev = hits
                .iter()
                .map(|w| Evidence {
                    part: format!("response.{}", part_name(*part)),
                    snippet: (*w).clone(),
                })
                .collect();
            (matched ^ negative, if matched { ev } else { vec![] })
        }
        Matcher::Regex {
            regex,
            part,
            condition,
            negative,
        } => {
            let text = input.part_text(*part);
            let mut matched_count = 0usize;
            let mut ev = Vec::new();
            for pat in regex {
                if let Ok(re) = Regex::new(pat) {
                    if let Some(mat) = re.find(&text) {
                        matched_count += 1;
                        ev.push(Evidence {
                            part: format!("response.{}", part_name(*part)),
                            snippet: truncate(mat.as_str(), 200),
                        });
                    }
                }
            }
            let matched = match condition {
                Condition::And => matched_count == regex.len(),
                Condition::Or => matched_count > 0,
            };
            (matched ^ negative, if matched { ev } else { vec![] })
        }
        Matcher::Size { size, negative } => {
            let hit = size.contains(&input.body.len());
            (hit ^ negative, vec![])
        }
        Matcher::Dsl {
            dsl,
            condition,
            negative,
        } => {
            let results: Vec<bool> = dsl.iter().map(|e| eval_bool(e, &input.vars)).collect();
            let matched = match condition {
                Condition::And => results.iter().all(|&b| b),
                Condition::Or => results.iter().any(|&b| b),
            };
            let ev = if matched {
                dsl.iter()
                    .zip(&results)
                    .filter(|(_, &r)| r)
                    .map(|(e, _)| Evidence {
                        part: "dsl".into(),
                        snippet: truncate(e, 200),
                    })
                    .collect()
            } else {
                vec![]
            };
            (matched ^ negative, ev)
        }
        Matcher::Unsupported => (false, vec![]),
    }
}

fn run_extractor(e: &Extractor, input: &MatchInput) -> Vec<String> {
    match e {
        Extractor::Regex {
            regex, part, group, ..
        } => {
            let text = input.part_text(*part);
            let mut out = Vec::new();
            for pat in regex {
                if let Ok(re) = Regex::new(pat) {
                    if let Some(caps) = re.captures(&text) {
                        let idx = group.unwrap_or(0);
                        if let Some(m) = caps.get(idx) {
                            out.push(truncate(m.as_str(), 200));
                        }
                    }
                }
            }
            out
        }
        Extractor::Dsl { dsl, .. } => dsl
            .iter()
            .filter_map(|expr| eval_string(expr, &input.vars))
            .map(|s| truncate(&s, 200))
            .collect(),
        Extractor::Unsupported => vec![],
    }
}

fn part_name(part: Part) -> &'static str {
    match part {
        Part::Body => "body",
        Part::Header => "header",
        Part::All => "all",
        Part::Data => "data",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("Server".into(), "nginx".into())],
            body: body.to_string(),
        }
    }

    fn req(matchers: Vec<Matcher>, cond: Condition) -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            path: vec![],
            raw: vec![],
            headers: Default::default(),
            body: None,
            matchers_condition: cond,
            matchers,
            extractors: vec![],
        }
    }

    #[test]
    fn and_condition_requires_all() {
        let r = req(
            vec![
                Matcher::Status {
                    status: vec![200],
                    negative: false,
                },
                Matcher::Word {
                    words: vec!["hello".into()],
                    part: Part::Body,
                    condition: Condition::And,
                    negative: false,
                },
            ],
            Condition::And,
        );
        assert!(evaluate_http(&r, &http(200, "hello world")).is_some());
        assert!(evaluate_http(&r, &http(404, "hello world")).is_none());
    }

    #[test]
    fn negative_word_inverts() {
        let r = req(
            vec![Matcher::Word {
                words: vec!["forbidden".into()],
                part: Part::Body,
                condition: Condition::Or,
                negative: true,
            }],
            Condition::And,
        );
        assert!(evaluate_http(&r, &http(200, "welcome")).is_some());
        assert!(evaluate_http(&r, &http(200, "forbidden")).is_none());
    }

    #[test]
    fn dsl_matcher_over_http() {
        let r = req(
            vec![Matcher::Dsl {
                dsl: vec!["status_code == 200 && contains(body, \"root:\")".into()],
                condition: Condition::And,
                negative: false,
            }],
            Condition::And,
        );
        assert!(evaluate_http(&r, &http(200, "root:x:0:0")).is_some());
        assert!(evaluate_http(&r, &http(200, "nope")).is_none());
    }

    #[test]
    fn word_matcher_over_tcp_data() {
        let input = MatchInput::from_data("$2437\r\nredis_version:7.0.0\r\n");
        let matchers = vec![Matcher::Word {
            words: vec!["redis_version".into()],
            part: Part::Data,
            condition: Condition::And,
            negative: false,
        }];
        assert!(evaluate(&matchers, Condition::And, &[], &input).is_some());
    }
}
