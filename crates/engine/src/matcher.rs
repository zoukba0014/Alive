use alive_core::Evidence;
use alive_template::{Condition, Extractor, HttpRequest, Matcher, Part};
use regex::Regex;

use crate::http::HttpResponse;

/// Evaluate a request's matchers against a response. On success, returns the
/// evidence snippets and any extracted values.
///
/// Unsupported matchers evaluate to `false` (they never satisfy a match); the
/// `template-check` command is responsible for warning about them up front.
pub(crate) fn evaluate(
    req: &HttpRequest,
    resp: &HttpResponse,
) -> Option<(Vec<Evidence>, Vec<String>)> {
    if req.matchers.is_empty() {
        return None;
    }

    let mut evidence = Vec::new();
    let mut any = false;
    let mut all = true;

    for m in &req.matchers {
        let (matched, ev) = eval_matcher(m, resp);
        any |= matched;
        all &= matched;
        if matched {
            evidence.extend(ev);
        }
    }

    let ok = match req.matchers_condition {
        Condition::And => all,
        Condition::Or => any,
    };
    if !ok {
        return None;
    }

    let extracted = req
        .extractors
        .iter()
        .flat_map(|e| run_extractor(e, resp))
        .collect();
    Some((evidence, extracted))
}

fn part_text(part: Part, resp: &HttpResponse) -> String {
    match part {
        Part::Body => resp.body.clone(),
        Part::Header => resp.header_text(),
        Part::All => resp.all_text(),
    }
}

fn eval_matcher(m: &Matcher, resp: &HttpResponse) -> (bool, Vec<Evidence>) {
    match m {
        Matcher::Status { status, negative } => {
            let hit = status.contains(&resp.status);
            let ev = vec![Evidence {
                part: "status".into(),
                snippet: resp.status.to_string(),
            }];
            (hit ^ negative, if hit { ev } else { vec![] })
        }
        Matcher::Word {
            words,
            part,
            condition,
            negative,
        } => {
            let text = part_text(*part, resp);
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
            let text = part_text(*part, resp);
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
            let hit = size.contains(&resp.body.len());
            (hit ^ negative, vec![])
        }
        Matcher::Unsupported => (false, vec![]),
    }
}

fn run_extractor(e: &Extractor, resp: &HttpResponse) -> Vec<String> {
    match e {
        Extractor::Regex {
            regex, part, group, ..
        } => {
            let text = part_text(*part, resp);
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
        Extractor::Unsupported => vec![],
    }
}

fn part_name(part: Part) -> &'static str {
    match part {
        Part::Body => "body",
        Part::Header => "header",
        Part::All => "all",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str) -> HttpResponse {
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
        assert!(evaluate(&r, &resp(200, "hello world")).is_some());
        assert!(evaluate(&r, &resp(404, "hello world")).is_none());
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
        assert!(evaluate(&r, &resp(200, "welcome")).is_some());
        assert!(evaluate(&r, &resp(200, "forbidden")).is_none());
    }
}
