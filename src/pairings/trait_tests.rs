use super::*;

#[derive(Clone, Copy, Debug, Default)]
struct DefaultFinalExponentiation(MillerLoopResult);

impl Add for DefaultFinalExponentiation {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Add<&Self> for DefaultFinalExponentiation {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl AddAssign for DefaultFinalExponentiation {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl AddAssign<&Self> for DefaultFinalExponentiation {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
    }
}

impl pairing::MillerLoopResult for DefaultFinalExponentiation {
    type Gt = Gt;

    fn final_exponentiation(&self) -> Gt {
        self.0.final_exponentiation()
    }
}

#[test]
fn test_trait_default_final_exponentiation() {
    use pairing::MillerLoopResult as _;
    use rand_core::SeedableRng;

    let mut rng = rand_xorshift::XorShiftRng::from_seed([0x69; 16]);
    for value in [Fp12::one(), Gt::generator().0]
        .into_iter()
        .chain((0..16).map(|_| Fp12::try_random(&mut rng).unwrap()))
    {
        let result = DefaultFinalExponentiation(MillerLoopResult(value));
        assert_eq!(
            result.final_exponentiation_vartime(),
            result.final_exponentiation(),
        );
    }
}

#[test]
fn test_trait_override_final_exponentiation() {
    use rand_core::SeedableRng;

    fn check(value: Fp12) {
        let result = MillerLoopResult(value);
        let generic =
            <MillerLoopResult as pairing::MillerLoopResult>::final_exponentiation_vartime(&result);
        assert_eq!(generic, result.final_exponentiation_vartime());
        assert_eq!(generic, result.final_exponentiation());
    }

    check(Fp12::one());
    check(Gt::generator().0);
    let mut rng = rand_xorshift::XorShiftRng::from_seed([0x6a; 16]);
    for _ in 0..32 {
        let value = Fp12::try_random(&mut rng).unwrap();
        if !bool::from(value.is_zero()) {
            check(value);
        }
    }
}
