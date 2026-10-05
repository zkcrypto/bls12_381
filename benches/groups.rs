#[macro_use]
extern crate criterion;

extern crate bls12_381;
use bls12_381::*;
use pairing::MultiMillerLoop;

use criterion::{Criterion, black_box};

#[allow(clippy::many_single_char_names)]
fn criterion_benchmark(c: &mut Criterion) {
    // Pairings
    {
        let g = G1Affine::generator();
        let h = G2Affine::generator();
        c.bench_function("full pairing", move |b| {
            b.iter(|| pairing(black_box(&g), black_box(&h)))
        });
        c.bench_function("G2 preparation for pairing", move |b| {
            b.iter(|| G2Prepared::from(h))
        });
        let prep = G2Prepared::from(h);
        c.bench_function("miller loop for pairing", move |b| {
            b.iter(|| multi_miller_loop(&[(&g, &prep)]))
        });
        c.bench_function("G2 reusable preparation for pairing", move |b| {
            b.iter(|| Bls12::prepare_reusable_g2(black_box(h)))
        });
        let reusable = Bls12::prepare_reusable_g2(h);
        c.bench_function("miller loop for reusable pairing", move |b| {
            b.iter(|| multi_miller_loop(&[(&g, &reusable)]))
        });
        let points = (1..=11)
            .map(|i| G1Affine::from(G1Projective::generator() * Scalar::from(i)))
            .collect::<Vec<_>>();
        let prepared = (1..=11)
            .map(|i| G2Prepared::from(G2Affine::from(G2Projective::generator() * Scalar::from(i))))
            .collect::<Vec<_>>();
        let terms = points.iter().zip(prepared.iter()).collect::<Vec<_>>();
        let reusable_prepared = (1..=11)
            .map(|i| {
                Bls12::prepare_reusable_g2(G2Affine::from(
                    G2Projective::generator() * Scalar::from(i),
                ))
            })
            .collect::<Vec<_>>();
        let reusable_terms = points
            .iter()
            .zip(reusable_prepared.iter())
            .collect::<Vec<_>>();
        c.bench_function("miller loop for three pairings", |b| {
            b.iter(|| multi_miller_loop(black_box(&terms[..3])))
        });
        c.bench_function("miller loop for eleven pairings", |b| {
            b.iter(|| multi_miller_loop(black_box(&terms)))
        });
        c.bench_function("miller loop for three reusable pairings", |b| {
            b.iter(|| multi_miller_loop(black_box(&reusable_terms[..3])))
        });
        c.bench_function("miller loop for eleven reusable pairings", |b| {
            b.iter(|| multi_miller_loop(black_box(&reusable_terms)))
        });
        let prep = G2Prepared::from(h);
        let r = multi_miller_loop(&[(&g, &prep)]);
        c.bench_function("final exponentiation for pairing", move |b| {
            b.iter(|| r.final_exponentiation())
        });
    }
    // G1Affine
    {
        let name = "G1Affine";
        let a = G1Affine::generator();
        let s = Scalar::from_raw([1, 2, 3, 4]);
        let compressed = [0u8; 48];
        let uncompressed = [0u8; 96];
        c.bench_function(&format!("{} check on curve", name), move |b| {
            b.iter(|| black_box(a).is_on_curve())
        });
        c.bench_function(&format!("{} check equality", name), move |b| {
            b.iter(|| black_box(a) == black_box(a))
        });
        c.bench_function(&format!("{} scalar multiplication", name), move |b| {
            b.iter(|| black_box(a) * black_box(s))
        });
        c.bench_function(&format!("{} subgroup check", name), move |b| {
            b.iter(|| black_box(a).is_torsion_free())
        });
        c.bench_function(
            &format!("{} deserialize compressed point", name),
            move |b| b.iter(|| G1Affine::from_compressed(black_box(&compressed))),
        );
        c.bench_function(
            &format!("{} deserialize uncompressed point", name),
            move |b| b.iter(|| G1Affine::from_uncompressed(black_box(&uncompressed))),
        );
    }

    // G1Projective
    {
        let name = "G1Projective";
        let a = G1Projective::generator();
        let a_affine = G1Affine::generator();
        let s = Scalar::from_raw([1, 2, 3, 4]);

        const N: usize = 10000;
        let v = vec![G1Projective::generator(); N];
        let mut q = vec![G1Affine::identity(); N];

        c.bench_function(&format!("{} check on curve", name), move |b| {
            b.iter(|| black_box(a).is_on_curve())
        });
        c.bench_function(&format!("{} check equality", name), move |b| {
            b.iter(|| black_box(a) == black_box(a))
        });
        c.bench_function(&format!("{} to affine", name), move |b| {
            b.iter(|| G1Affine::from(black_box(a)))
        });
        let point = a * s;
        c.bench_function("G1Projective to affine nontrivial", move |b| {
            b.iter(|| G1Affine::from(black_box(point)))
        });
        c.bench_function("G1Projective to affine vartime", move |b| {
            b.iter(|| black_box(&point).to_affine_vartime())
        });
        c.bench_function(&format!("{} doubling", name), move |b| {
            b.iter(|| black_box(a).double())
        });
        c.bench_function(&format!("{} addition", name), move |b| {
            b.iter(|| black_box(a).add(&a))
        });
        c.bench_function(&format!("{} mixed addition", name), move |b| {
            b.iter(|| black_box(a).add_mixed(&a_affine))
        });
        c.bench_function(&format!("{} scalar multiplication", name), move |b| {
            b.iter(|| black_box(a) * black_box(s))
        });
        c.bench_function(&format!("{} batch to affine n={}", name, N), move |b| {
            b.iter(|| {
                G1Projective::batch_normalize(black_box(&v), black_box(&mut q));
                black_box(&q)[0]
            })
        });
    }

    // G2Affine
    {
        let name = "G2Affine";
        let a = G2Affine::generator();
        let s = Scalar::from_raw([1, 2, 3, 4]);
        let compressed = [0u8; 96];
        let uncompressed = [0u8; 192];
        c.bench_function(&format!("{} check on curve", name), move |b| {
            b.iter(|| black_box(a).is_on_curve())
        });
        c.bench_function(&format!("{} check equality", name), move |b| {
            b.iter(|| black_box(a) == black_box(a))
        });
        c.bench_function(&format!("{} scalar multiplication", name), move |b| {
            b.iter(|| black_box(a) * black_box(s))
        });
        c.bench_function(&format!("{} subgroup check", name), move |b| {
            b.iter(|| black_box(a).is_torsion_free())
        });
        c.bench_function(
            &format!("{} deserialize compressed point", name),
            move |b| b.iter(|| G2Affine::from_compressed(black_box(&compressed))),
        );
        c.bench_function(
            &format!("{} deserialize uncompressed point", name),
            move |b| b.iter(|| G2Affine::from_uncompressed(black_box(&uncompressed))),
        );
    }

    // G2Projective
    {
        let name = "G2Projective";
        let a = G2Projective::generator();
        let a_affine = G2Affine::generator();
        let s = Scalar::from_raw([1, 2, 3, 4]);

        const N: usize = 10000;
        let v = vec![G2Projective::generator(); N];
        let mut q = vec![G2Affine::identity(); N];

        c.bench_function(&format!("{} check on curve", name), move |b| {
            b.iter(|| black_box(a).is_on_curve())
        });
        c.bench_function(&format!("{} check equality", name), move |b| {
            b.iter(|| black_box(a) == black_box(a))
        });
        c.bench_function(&format!("{} to affine", name), move |b| {
            b.iter(|| G2Affine::from(black_box(a)))
        });
        let point = a * s;
        c.bench_function("G2Projective to affine nontrivial", move |b| {
            b.iter(|| G2Affine::from(black_box(point)))
        });
        c.bench_function("G2Projective to affine vartime", move |b| {
            b.iter(|| black_box(&point).to_affine_vartime())
        });
        c.bench_function(&format!("{} doubling", name), move |b| {
            b.iter(|| black_box(a).double())
        });
        c.bench_function(&format!("{} addition", name), move |b| {
            b.iter(|| black_box(a).add(&a))
        });
        c.bench_function(&format!("{} mixed addition", name), move |b| {
            b.iter(|| black_box(a).add_mixed(&a_affine))
        });
        c.bench_function(&format!("{} scalar multiplication", name), move |b| {
            b.iter(|| black_box(a) * black_box(s))
        });
        c.bench_function(&format!("{} batch to affine n={}", name, N), move |b| {
            b.iter(|| {
                G2Projective::batch_normalize(black_box(&v), black_box(&mut q));
                black_box(&q)[0]
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
