//! Criterion benchmark — P1-EC-04: alloc_slice < 50 ns/call.
//!
//! Run with:  cargo bench --bench arena_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sg_arena::Arena;
use sg_common::traits::ArenaAllocator;
use sg_common::PacketHeader;

fn bench_alloc_slice(c: &mut Criterion) {
    let mut init = Arena::init();

    c.bench_function("alloc_slice::<PacketHeader>(1)", |b| {
        b.iter(|| {
            let slice = init
                .alloc_slice::<PacketHeader>(black_box(1))
                .expect("bench alloc must succeed");
            black_box(slice);
        });
    });
}

criterion_group!(benches, bench_alloc_slice);
criterion_main!(benches);