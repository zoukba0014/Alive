//! Benchmarks for the hottest engine paths: matcher evaluation and template
//! clustering. Run with `cargo bench -p alive-engine`.

use std::collections::BTreeMap;

use alive_core::Severity;
use alive_engine::{cluster_templates, evaluate_http, HttpResponse};
use alive_template::{Condition, HttpRequest, Info, Matcher, Part, Template};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn sample_request() -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        path: vec!["{{BaseURL}}/".into()],
        raw: vec![],
        headers: BTreeMap::new(),
        body: None,
        matchers_condition: Condition::And,
        matchers: vec![
            Matcher::Status {
                status: vec![200],
                negative: false,
            },
            Matcher::Word {
                words: vec!["server".into(), "login".into()],
                part: Part::Body,
                condition: Condition::And,
                negative: false,
            },
            Matcher::Regex {
                regex: vec!["v([0-9]+\\.[0-9]+)".into()],
                part: Part::Body,
                condition: Condition::Or,
                negative: false,
            },
        ],
        extractors: vec![],
    }
}

fn sample_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Server".into(), "nginx".into())],
        body: "server login page v1.2 ".repeat(64),
    }
}

fn template(id: &str) -> Template {
    Template {
        id: id.to_string(),
        info: Info {
            name: id.to_string(),
            author: None,
            severity: Severity::Info,
            tags: vec![],
            description: None,
        },
        http: vec![sample_request()],
        tcp: vec![],
        dns: vec![],
        ssl: vec![],
        extra: Default::default(),
    }
}

fn bench_matcher(c: &mut Criterion) {
    let req = sample_request();
    let resp = sample_response();
    c.bench_function("evaluate_http", |b| {
        b.iter(|| evaluate_http(black_box(&req), black_box(&resp)))
    });
}

fn bench_cluster(c: &mut Criterion) {
    let templates: Vec<Template> = (0..500).map(|i| template(&format!("t{i}"))).collect();
    c.bench_function("cluster_templates_500", |b| {
        b.iter(|| cluster_templates(black_box(&templates)))
    });
}

criterion_group!(benches, bench_matcher, bench_cluster);
criterion_main!(benches);
