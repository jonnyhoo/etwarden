//! # `event_throughput`
//!
//! **Purpose**: Criterion benchmark for ETW event parse throughput.
//! **Public API**: (none — benchmark binary)
//! **Dependencies**: —
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 0 / 200

use criterion::{criterion_group, criterion_main};

fn bench_placeholder(c: &mut criterion::Criterion) {
    c.bench_function("placeholder", |b| {
        b.iter(|| {
            // T34 will replace with real benchmark
        });
    });
}

criterion_group!(benches, bench_placeholder);
criterion_main!(benches);
