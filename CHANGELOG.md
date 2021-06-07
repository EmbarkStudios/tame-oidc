# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[Unreleased]: https://github.com/EmbarkStudios/tame-oidc/compare/0.3.0...HEAD
[0.3.0]: https://github.com/EmbarkStudios/tame-oidc/releases/tag/0.3.0
[0.2.0]: https://github.com/EmbarkStudios/tame-oidc/releases/tag/0.2.0
[0.1.0]: https://github.com/EmbarkStudios/tame-oidc/releases/tag/0.1.0
[0.0.1]: https://github.com/EmbarkStudios/tame-oidc/releases/tag/0.0.1

## [Unreleased]

## [0.3.1] - 2021-05-07

- Update to [tame-oauth](https://crates.io/crates/tame-oauth) 0.5.

## [0.3.0] - 2021-04-07

### Changed

- `exchange_token_request` now optionally takes a code verifier as well as a
  client secret.

## [0.2.0] - 2021-03-01

### Added

- Make `Claim.sub` public.
- Implement `Clone` for `JWK`, `JWKS`, and `Claim`.

## [0.1.0] - 2021-02-26

### Changed

- `provider::token_data` renamed to `provider::verify_token`.

## [0.0.1] - 2021-02-26

### Added

- Initial version
