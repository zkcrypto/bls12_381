const { FpW } = require('../pkg/bls12_381.js');
// Here we can make an alias
const Fp = FpW;
const { strict } = require( 'node:assert' );

// check constructor
{
  const scalar = new Fp();
  const bytes = scalar.to_bytes();
  strict.deepEqual(bytes, new Uint8Array(48));
}

// check method one
{
  const one = Fp.one();
  const bytes = one.to_bytes();
  const exp = new Uint8Array(48);
  exp[47] = 1;
  strict.deepEqual(bytes, exp);
}

// check from_bytes
{
  const b = new Uint8Array(48);
  b[2] = 3;
  const scalar = Fp.from_bytes(b);
  const bytes = scalar.to_bytes();
  const exp = new Uint8Array(48);
  exp[2] = 3;
  strict.deepEqual(bytes, exp);
}
