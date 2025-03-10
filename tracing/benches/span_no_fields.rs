use criterion::{Criterion, criterion_group, criterion_main};
use tracing::{Level, span_internal};

mod shared;

fn bench(c: &mut Criterion) {
    shared::for_all_recording(&mut c.benchmark_group("span_no_fields"), |b| {
        b.iter(|| span_internal!(Level::TRACE, "span"))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
