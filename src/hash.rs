use core::hash::{Hash, Hasher};

use crate::G1Affine;
use crate::G1Projective;
use crate::G2Affine;
use crate::G2Projective;

impl Hash for G1Affine {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.x.0.hash(state);
        self.y.0.hash(state);
        self.infinity.unwrap_u8().hash(state);
    }
}

impl Hash for G2Affine {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.x.c0.0.hash(state);
        self.x.c1.0.hash(state);
        self.y.c0.0.hash(state);
        self.y.c1.0.hash(state);
        self.infinity.unwrap_u8().hash(state);
    }
}

impl Hash for G1Projective {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.x.0.hash(state);
        self.y.0.hash(state);
        self.z.0.hash(state);
    }
}

impl Hash for G2Projective {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.x.c0.0.hash(state);
        self.x.c1.0.hash(state);
        self.y.c0.0.hash(state);
        self.y.c1.0.hash(state);
        self.z.c0.0.hash(state);
        self.z.c1.0.hash(state);
    }
}
