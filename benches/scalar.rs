#[macro_use]
extern crate criterion;

extern crate bls12_381;
use bls12_381::*;

use criterion::{black_box, Criterion};

fn criterion_benchmark(c: &mut Criterion) {
    let x = Scalar::from_raw([1, 2, 3, 4]);
    let y = Scalar::from_raw([5, 6, 7, 8]);
    let narrow = b"01234567801234567801234567801234";
    let wide = b"0123456780123456780123456780123456780123456780123456780123456780";

    c.bench_function("Scalar add", move |b| {
        b.iter(|| black_box(x) + black_box(y))
    });
    c.bench_function("Scalar sub", move |b| {
        b.iter(|| black_box(x) - black_box(y))
    });
    c.bench_function("Scalar double", move |b| b.iter(|| black_box(x).double()));
    c.bench_function("Scalar mul", move |b| {
        b.iter(|| black_box(x) * black_box(y))
    });
    c.bench_function("Scalar square", move |b| b.iter(|| black_box(x).square()));
    c.bench_function("Scalar sqrt", move |b| b.iter(|| black_box(x).sqrt()));
    c.bench_function("Scalar invert", move |b| b.iter(|| black_box(x).invert()));
    c.bench_function("Scalar pow", move |b| {
        b.iter(|| black_box(x).pow(&[1111111, 22222222, 33333333, 44444444]))
    });
    c.bench_function("Scalar from_bytes", move |b| {
        b.iter(|| Scalar::from_bytes(black_box(narrow)))
    });
    c.bench_function("Scalar from_bytes_wide", move |b| {
        b.iter(|| Scalar::from_bytes_wide(black_box(&wide)))
    });
    c.bench_function("Scalar to_bytes", move |b| {
        b.iter(|| black_box(x).to_bytes())
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
