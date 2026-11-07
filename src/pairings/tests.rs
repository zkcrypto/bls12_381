use super::*;

#[test]
// The compressed squaring schedule assumes a negative BLS parameter; MSRV Clippy flags any
// assertion on that constant.
#[allow(clippy::assertions_on_constants)]
fn test_compressed_cyclotomic_squaring() {
    use rand_core::SeedableRng;

    let last_checkpoint = COMPRESSED_FIRST_SQUARES + COMPRESSED_NEXT_SQUARES;
    let mut bit = last_checkpoint;
    let mut exponent = (1_u64 << COMPRESSED_FIRST_SQUARES) | (1_u64 << bit);
    for squarings in CYCLOTOMIC_TAIL_SQUARES {
        bit += squarings;
        exponent |= 1_u64 << bit;
    }
    assert_eq!(BLS_X, exponent << 1);
    assert!(BLS_X_IS_NEGATIVE);

    let generator = Gt::generator().0;
    let mut rng = rand_xorshift::XorShiftRng::from_seed([0x35; 16]);
    let sample = Fp12::try_random(&mut rng).unwrap();
    let unitary = sample.conjugate() * sample.invert().unwrap();
    let cyclotomic = unitary.frobenius_map().frobenius_map() * unitary;
    for (index, base) in [generator, generator.square(), Fp12::one(), cyclotomic]
        .into_iter()
        .enumerate()
    {
        let mut full = base;
        let mut ordinary = base;
        let mut compressed = CompressedCyclotomic::from(base);
        let mut checkpoint_first = None;
        let mut checkpoint_next = None;

        for exponent in 1..=last_checkpoint {
            full = cyclotomic_square(full);
            ordinary = ordinary.square();
            compressed = compressed_square(compressed);
            assert_eq!(full, ordinary);
            assert_eq!(compressed.g1, full.c0.c1);
            assert_eq!(compressed.g2, full.c0.c2);
            assert_eq!(compressed.g3, full.c1.c0);
            assert_eq!(compressed.g5, full.c1.c2);

            if exponent == COMPRESSED_FIRST_SQUARES {
                checkpoint_first = Some((compressed, full));
            } else if exponent == last_checkpoint {
                checkpoint_next = Some((compressed, full));
            }
        }

        let (compressed_first, full_first) = checkpoint_first.unwrap();
        let (compressed_next, full_next) = checkpoint_next.unwrap();
        if index != 2 {
            assert_eq!(
                decompress_pair(compressed_first, compressed_next),
                Some((full_first, full_next))
            );
        } else {
            assert_eq!(decompress_pair(compressed_first, compressed_next), None);
        }
        assert_eq!(cyclotomic_exp(base), cyclotomic_exp_full(base));
    }
}

#[test]
fn test_vartime_fp12_inversion() {
    use rand_core::SeedableRng;

    assert_eq!(invert_fp12_vartime(Fp12::zero()), None);
    let mut rng = rand_xorshift::XorShiftRng::from_seed([0x52; 16]);
    for _ in 0..32 {
        let value = Fp12::try_random(&mut rng).unwrap();
        let inverse = invert_fp12_vartime(value).unwrap();
        assert_eq!(inverse, value.invert().unwrap());
        assert_eq!(value * inverse, Fp12::one());
    }
}

#[test]
fn test_vartime_final_exponentiation_matches_original() {
    use rand_core::SeedableRng;

    fn check(value: Fp12) {
        let result = MillerLoopResult(value);
        assert_eq!(
            result.final_exponentiation_vartime(),
            result.final_exponentiation()
        );
    }

    // Identity, proper subfields, and nontrivial tower basis elements.
    for value in [
        Fp12::one(),
        -Fp12::one(),
        Fp12::from(Fp2 {
            c0: Fp::one(),
            c1: Fp::one(),
        }),
        Fp12 {
            c0: Fp6::zero(),
            c1: Fp6::one(),
        },
        Fp12::from(Fp6 {
            c0: Fp2::zero(),
            c1: Fp2::one(),
            c2: Fp2::zero(),
        }),
        Gt::generator().0,
    ] {
        check(value);
    }
    let mut rng = rand_xorshift::XorShiftRng::from_seed([0x65; 16]);
    for _ in 0..64 {
        let value = Fp12::try_random(&mut rng).unwrap();
        if !bool::from(value.is_zero()) {
            check(value);
        }
    }
}

#[test]
fn test_vartime_tower_inversion_and_frobenius_boundaries() {
    use rand_core::SeedableRng;

    assert_eq!(invert_fp6_vartime(Fp6::zero()), None);
    assert_eq!(invert_fp12_vartime(Fp12::zero()), None);
    let mut rng = rand_xorshift::XorShiftRng::from_seed([0x66; 16]);
    for _ in 0..128 {
        let value = Fp6::try_random(&mut rng).unwrap();
        assert_eq!(
            invert_fp6_vartime(value),
            Option::<Fp6>::from(value.invert())
        );
        let value = Fp12::try_random(&mut rng).unwrap();
        assert_eq!(
            invert_fp12_vartime(value),
            Option::<Fp12>::from(value.invert())
        );
        assert_eq!(
            frobenius_map_2(value),
            value.frobenius_map().frobenius_map()
        );
        let mut sixth = value;
        for _ in 0..6 {
            sixth = sixth.frobenius_map();
        }
        assert_eq!(value.conjugate(), sixth);
    }
    for value in [Fp12::zero(), Fp12::one(), -Fp12::one()] {
        assert_eq!(
            frobenius_map_2(value),
            value.frobenius_map().frobenius_map()
        );
        assert_eq!(
            invert_fp12_vartime(value),
            Option::<Fp12>::from(value.invert())
        );
    }
}

#[test]
fn test_random_compressed_checkpoints_and_exception_fallback() {
    use rand_core::SeedableRng;

    let identity = CompressedCyclotomic::from(Fp12::one());
    let generator = CompressedCyclotomic::from(Gt::generator().0);
    // Either checkpoint can independently trigger the zero-denominator fallback.
    assert_eq!(decompress_pair(identity, generator), None);
    assert_eq!(decompress_pair(generator, identity), None);
    assert_eq!(
        cyclotomic_exp(Fp12::one()),
        cyclotomic_exp_full(Fp12::one())
    );

    let mut rng = rand_xorshift::XorShiftRng::from_seed([0x67; 16]);
    for _ in 0..64 {
        let sample = Fp12::try_random(&mut rng).unwrap();
        let unitary = sample.conjugate() * sample.invert().unwrap();
        let base = unitary.frobenius_map().frobenius_map() * unitary;
        let mut full = base;
        let mut compressed = CompressedCyclotomic::from(base);
        let mut first = None;
        for i in 1..=COMPRESSED_FIRST_SQUARES + COMPRESSED_NEXT_SQUARES {
            full = full.square();
            compressed = compressed_square(compressed);
            assert_eq!(compressed.g1, full.c0.c1);
            assert_eq!(compressed.g2, full.c0.c2);
            assert_eq!(compressed.g3, full.c1.c0);
            assert_eq!(compressed.g5, full.c1.c2);
            if i == COMPRESSED_FIRST_SQUARES {
                first = Some((compressed, full));
            }
        }
        let (compressed_first, full_first) = first.unwrap();
        if let Some(pair) = decompress_pair(compressed_first, compressed) {
            assert_eq!(pair, (full_first, full));
        }
        assert_eq!(cyclotomic_exp(base), cyclotomic_exp_full(base));
    }
}

#[cfg(feature = "alloc")]
#[test]
fn test_random_reusable_preparation_and_mixed_miller_loops() {
    use ff::Field;
    use rand_core::SeedableRng;

    assert_eq!(
        multi_miller_loop(&[]).final_exponentiation_vartime(),
        Gt::identity()
    );
    let mut rng = rand_xorshift::XorShiftRng::from_seed([0x68; 16]);
    for index in 0..32 {
        let p = match index {
            0 => G1Affine::identity(),
            1 => -G1Affine::generator(),
            _ => G1Affine::from(G1Projective::generator() * Scalar::try_random(&mut rng).unwrap()),
        };
        let q = match index {
            0 | 2 => G2Affine::identity(),
            1 => -G2Affine::generator(),
            _ => G2Affine::from(G2Projective::generator() * Scalar::try_random(&mut rng).unwrap()),
        };
        let raw = G2Prepared::from(q);
        let normalized = Bls12::prepare_reusable_g2(q);
        let expected = pairing(&p, &q);
        assert_eq!(
            multi_miller_loop(&[(&p, &raw)]).final_exponentiation(),
            expected
        );
        let reusable_result = multi_miller_loop(&[(&p, &normalized)]);
        assert_eq!(reusable_result.final_exponentiation(), expected);
        assert_eq!(reusable_result.final_exponentiation_vartime(), expected);
        assert_eq!(
            multi_miller_loop(&[(&p, &raw), (&p, &normalized)]).final_exponentiation_vartime(),
            expected + expected,
        );
        assert_eq!(
            multi_miller_loop(&[(&p, &raw), (&-p, &normalized)]).final_exponentiation_vartime(),
            Gt::identity(),
        );
    }

    let p = G1Affine::generator();
    let raw = G2Prepared::from(G2Affine::generator());
    // Exercise zero-line-coefficient fallback at both ends and in the middle.
    for index in [0, 17, 67] {
        let mut with_zero = raw.clone();
        with_zero.coeffs[index].2 = Fp2::zero();
        let mut normalized = with_zero.clone();
        normalized.normalize_lines_vartime();
        assert_eq!(normalized.coeffs[index], with_zero.coeffs[index]);
        assert_eq!(
            multi_miller_loop(&[(&p, &with_zero)]).final_exponentiation(),
            multi_miller_loop(&[(&p, &normalized)]).final_exponentiation_vartime(),
        );
    }
}
