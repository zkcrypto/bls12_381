# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 0.8.0 - 28-04-21

### Fixed

- Fix `canonical-0.6` impl bugs. [#61](https://github.com/dusk-network/bls12_381/issues/61)

### Removed

- Remove unnecessary `.into()` calls. [#67](https://github.com/dusk-network/bls12_381/issues/67)

## [0.7.0] - 12-04-21

### Added

- `parallel` feature inclusion. [#54](https://github.com/dusk-network/bls12_381/issues/54)
  
### Fixed

- No_std support fixes. [#54](https://github.com/dusk-network/bls12_381/issues/54)
- Fix crate benchmarks. [#59](https://github.com/dusk-network/bls12_381/issues/59)

### Changed

- Update `canonical` to `0.6`. [#58](https://github.com/dusk-network/bls12_381/issues/58)

## [0.6.0] - 27-01-21

### Changed

- Canonical updated to v0.5 [#52](https://github.com/dusk-network/bls12_381/issues/52)

## [0.5.2] - 25-01-21

### Fixed

- Incorrect encoding for unchecked bytes serialization [#50](https://github.com/dusk-network/bls12_381/issues/50)

## [0.5.1] - 22-01-21

### Changed

- Update dusk-bytes and implement hex format tests

## [0.5.0] - 21-01-21

### Changed

- to/from bytes methods of BlsScalar, G1Affine, G2Affine refactored in favor of dusk-bytes

### Added

- Included `G1Affine::to_raw_bytes` and `G1Affine::from_slice_unchecked`
- Included `G2Affine::to_raw_bytes` and `G2Affine::from_slice_unchecked`
- Included `G2Prepared::to_raw_bytes` and `G2Prepared::from_slice_unchecked`

## [0.4.0] - 24-12-20

### Changed

- no-std compatibility for pairings feature
- isolate serde with `serde_req` feature

## [0.3.0] - 08-11-20

### Changed

- no-std compatibility
- export scalar as `BlsScalar`

## [0.1.5] - 29-10-20

### Changed

- Deriva Canon traits for Scalar
