# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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