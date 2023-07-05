const { Scalar } = require('../pkg/bls12_381.js');
const { strict } = require( 'node:assert' );

// check constructor
{
  const scalar = new Scalar();
  const bytes = scalar.to_bytes();
  strict.deepEqual(bytes, new Uint8Array(32));
}

// check method one
{
  const one = Scalar.one();
  const bytes = one.to_bytes();
  const exp = new Uint8Array(32);
  exp[0] = 1;
  strict.deepEqual(bytes, exp);
}

// check from_bytes
{
  const b = new Uint8Array(32);
  b[2] = 3;
  const scalar = Scalar.from_bytes(b);
  const bytes = scalar.to_bytes();
  const exp = new Uint8Array(32);
  exp[2] = 3;
  strict.deepEqual(bytes, exp);
}
