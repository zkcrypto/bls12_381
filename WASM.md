# `wasm` library features

For now the wasm library exports public structures/methods/functions.

The exported structures have name different to original. The library structures have suffix `W` in the end of the structure name. The performance of the solution can be found in file [`Benchmark.md`](./dist/Benchmark.md).

For example: `Scalar` -> `ScalarW`.

Some exported functions have suffix `_`. It is because the public functions are used in many places and I saved the original names for the Rust lib.

To have the same names on JS side use such code:

```js
const lib = require('./dist/pkg/bls12_381.js');
const Scalar = lib.ScalarW;
```

# How to build library

### Prerequisites

- [wasm-pack](https://rustwasm.github.io/wasm-pack/)
- [make](https://www.dartmouth.edu/~rc/classes/soft_dev/make.html)

To install `wasm-pack` run the command:
```
make prerequisite
```

### Build

To build use commands:
- for debug build
```
make build
```

- for release build
```
make release
```

The `build` and `release` commands accepts options:
- `target` - web | nodejs. Default is nodejs
- `features` - comma separated list of features. Default is empty

Example of complex command:
```
make build target=web features=experimental
```
