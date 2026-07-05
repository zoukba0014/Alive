//! Benchmark for target de-duplication over a large range with duplicates.
//! Run with `cargo bench -p alive-discovery`.

use std::net::{IpAddr, Ipv4Addr};

use alive_discovery::{dedup, DedupMode};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// 50k (ip, port) pairs where every target appears twice.
fn sample_targets() -> Vec<(IpAddr, u16)> {
    let mut v = Vec::with_capacity(50_000);
    for i in 0..25_000u32 {
        let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
        v.push((ip, 80));
        v.push((ip, 80)); // duplicate
    }
    v
}

fn bench_dedup(c: &mut Criterion) {
    let targets = sample_targets();
    c.bench_function("dedup_exact_50k", |b| {
        b.iter(|| dedup(black_box(targets.clone()), DedupMode::Exact))
    });
    c.bench_function("dedup_bloom_50k", |b| {
        b.iter(|| dedup(black_box(targets.clone()), DedupMode::Bloom))
    });
}

criterion_group!(benches, bench_dedup);
criterion_main!(benches);
