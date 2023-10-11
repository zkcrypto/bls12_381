# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Expose `scalar::GENERATOR` constant

## [0.12.0] - 2023-06-07

### Added

- Align crate with upstream `zkcrypto/bls12_381` [#117]

### Removed

- Remove scalar field generator [#100]
- Remove canonical and canonical_derive dependency [#108]

### Changed

- Rename `serde_req` feature to `serde` [#117]
- Separate Dusk's additions from the original crate [#109]

## [0.11.3] - 2023-05-17

### Changed
- Update issue links in CHANGELOG [#84]

### Fixed

- Fix documentation links [#93]
- Fix `Cargo.toml` invalid categories [#75]

## [0.11.2] - 2022-10-26

### Fixed

- Fixed `rkyv-impl` feature by bringing in `rkyv/alloc` on `alloc` feature
- Make `g1` and `g2` `Archived*` structs only available on `rkyv-impl` 

## [0.11.1] - 2022-10-19

### Added
- Add support for `rkyv-impl` under `no_std`
- Add wrapper type for `subtle::Choice`

### Change
- Derive manual implementations of `rkyv` trait by introducing a wrapper for the
  `subtle::Choice` type

## [0.11.0] - 2022-08-17

### Added
- Add `rkyv-impl` feature
- Add implementation of `CheckBytes`

### Change
- Move `rkyv`-related implementations behind the `rkyv-impl` feature

### Remove
- `Sized` bound from `G2Prepared` `rkyv::Serialize` implementation [#94]

## [0.10.1] - 2022-07-27

### Added
- `rkyv` implementation behind feature gate [#90]
- Derive `Hash` for `BlsScalar`
- Apply patches from `zkcrypto` to improve the efficiency [#86]

## [0.10.0] - 2022-05-25

### Changed
- Change `invert` Scalar function signature [#78]

### Added
- Add `invert_ct` constant time Scalar inversion calculation [#78]

## [0.9.0] - 2022-02-24

### Changed
- Update canonical and canonical_derive to v0.7
- Update rust edition to 2021

## [0.8.0] - 2021-04-28

### Fixed

- Fix `canonical-0.6` impl bugs. [#61]

### Removed

- Remove unnecessary `.into()` calls. [#67]

## [0.7.0] - 2021-04-12

### Added

- `parallel` feature inclusion. [#54]

### Fixed

- No_std support fixes. [#54]
- Fix crate benchmarks. [#59]

### Changed

- Update `canonical` to `0.6`. [#58]

## [0.6.0] - 2021-01-27

### Changed

- Canonical updated to v0.5 [#52]

## [0.5.2] - 2021-01-25

### Fixed

- Incorrect encoding for unchecked bytes serialization [#50]

## [0.5.1] - 2021-01-22

### Changed

- Update dusk-bytes and implement hex format tests

## [0.5.0] - 2021-01-21

### Changed

- to/from bytes methods of BlsScalar, G1Affine, G2Affine refactored in favor of dusk-bytes

### Added

- Included `G1Affine::to_raw_bytes` and `G1Affine::from_slice_unchecked`
- Included `G2Affine::to_raw_bytes` and `G2Affine::from_slice_unchecked`
- Included `G2Prepared::to_raw_bytes` and `G2Prepared::from_slice_unchecked`

## [0.4.0] - 2020-12-24

### Changed

- no-std compatibility for pairings feature
- isolate serde with `serde_req` feature

## [0.3.0] - 2020-11-08

### Changed

- no-std compatibility
- export scalar as `BlsScalar`

## [0.2.0] - 2020-11-03

### Added

- Add `Canon` behind feature flag

## [0.1.5] - 2020-10-29

### Changed

- Derive Canon traits for Scalar

## [0.1.4] - 2020-09-11

### Changed

- Update `subtle` from `2.2.1` to `2.3.0`

### Fixed

- Fix benchmarks

## [0.1.3] - 2020-08-11

### Added

- Add `is_one` and `is_zero` for `Scalar`
- Add `pow_of_2` for `Scalar`

## [0.1.2] - 2020-07-20

### Added

- Add `random` for `Scalar`
- Add `Serde` for `G2Prepared`, `Fp6`, `Fp2`, `Fp`, `G2Affine`, `G1Affine`, `Scalar`
- Add `Product`, `Sum`, `PartialOrd`, `Ord`, `Xor` and `And` for `Scalar`
- Add `reduce` method for `Scalar`
- Add `std` feature as default feature

### Changed

- Change `to_base_4` method of `Scalar`
- Rename `S` to `TWO_ADACITY` and export it

<!-- Issues -->
[#117]: (https://github.com/dusk-network/bls12_381/issues/117)
[#109]: (https://github.com/dusk-network/bls12_381/issues/109)
[#108]: (https://github.com/dusk-network/bls12_381/issues/108)
[#100]: (https://github.com/dusk-network/bls12_381/issues/100)
[#93]: (https://github.com/dusk-network/bls12_381/issues/93)
[#75]: (https://github.com/dusk-network/bls12_381/issues/75)
[#84]: (https://github.com/dusk-network/bls12_381/issues/84)
[#94]: (https://github.com/dusk-network/bls12_381/issues/94)
[#90]: (https://github.com/dusk-network/bls12_381/issues/90)
[#86]: (https://github.com/dusk-network/bls12_381/issues/86)
[#78]: (https://github.com/dusk-network/bls12_381/issues/78)
[#61]: (https://github.com/dusk-network/bls12_381/issues/61)
[#67]: (https://github.com/dusk-network/bls12_381/issues/67)
[#54]: (https://github.com/dusk-network/bls12_381/issues/54)
[#59]: (https://github.com/dusk-network/bls12_381/issues/59)
[#58]: (https://github.com/dusk-network/bls12_381/issues/58)
[#52]: (https://github.com/dusk-network/bls12_381/issues/52)
[#50]: (https://github.com/dusk-network/bls12_381/issues/50)

<!-- Versions -->
[Unreleased]: https://github.com/dusk-network/bls12_381/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/dusk-network/bls12_381/compare/v0.11.3...v0.12.0
[0.11.3]: https://github.com/dusk-network/bls12_381/compare/v0.11.2...v0.11.3
[0.11.2]: https://github.com/dusk-network/bls12_381/compare/v0.11.1...v0.11.2
[0.11.1]: https://github.com/dusk-network/bls12_381/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/dusk-network/bls12_381/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/dusk-network/bls12_381/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/dusk-network/bls12_381/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/dusk-network/bls12_381/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/dusk-network/bls12_381/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/dusk-network/bls12_381/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/dusk-network/bls12_381/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/dusk-network/bls12_381/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/dusk-network/bls12_381/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/dusk-network/bls12_381/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/dusk-network/bls12_381/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dusk-network/bls12_381/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/dusk-network/bls12_381/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/dusk-network/bls12_381/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/dusk-network/bls12_381/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/dusk-network/bls12_381/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/dusk-network/bls12_381/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/dusk-network/bls12_381/releases/tag/v0.1.1
