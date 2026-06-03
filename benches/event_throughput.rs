//! # `event_throughput`
//!
//! **Purpose**: Criterion benchmark for event-to-NDJSON pipeline throughput.
//! **Public API**: (none — benchmark binary)
//! **Dependencies**: `etwarden`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 75 / 200

use chrono::{TimeZone, Utc};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use etwarden::filter::{pid::PidFilter, Filter};
use etwarden::output::schema::event_to_line;
use etwarden::parser::types::{NetEvent, Protocol};

fn make_connect_event(pid: u32) -> NetEvent {
    NetEvent::Connect {
        timestamp: Utc
            .with_ymd_and_hms(2025, 1, 15, 12, 0, 0)
            .single()
            .expect("valid ts"),
        pid,
        proto: Protocol::Tcp,
        src: "10.0.0.1:49152".into(),
        dst: "93.184.216.34:443".into(),
        bytes_out: 1024,
        bytes_in: 4096,
    }
}

fn bench_event_to_line(c: &mut Criterion) {
    let event = make_connect_event(1234);
    c.bench_function("event_to_line", |b| {
        b.iter(|| event_to_line(&event));
    });
}

fn bench_filter_and_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("filter_serialize");
    for count in [100, 1000, 10_000] {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            b.iter(|| {
                let filter = PidFilter::single(1234);
                let mut buf = Vec::with_capacity(count * 128);
                for i in 0..count {
                    let event = make_connect_event(if i % 3 == 0 { 1234 } else { 9999 });
                    if filter.allow(&event) {
                        let line = event_to_line(&event);
                        let json = serde_json::to_string(&line).expect("serialize");
                        buf.extend_from_slice(json.as_bytes());
                        buf.push(b'\n');
                    }
                }
                std::hint::black_box(&buf);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_event_to_line, bench_filter_and_serialize);
criterion_main!(benches);
