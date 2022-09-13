<!-- markdownlint-disable blanks-around-headings blanks-around-lists no-duplicate-heading -->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->
## [Unreleased] - ReleaseDate
### Changed
- Make claims flexible by accepting any user provided DeserializeOwned in functions, 
that extract claims.

## [0.5.0] - 2022-04-25
### Added
- `pkce` flow can have an optional `client_secret`

### Changed
- [PR#15](https://github.com/EmbarkStudios/tame-oidc/pull/15) implemented a strict certifiable OIDC flow.
- [PR#17](https://github.com/EmbarkStudios/tame-oidc/pull/17) removed the unneeded dependency on `chrono`, fixing [#16](https://github.com/EmbarkStudios/tame-oidc/issues/16).

## [0.4.0] - 2021-08-07
### Removed
- Removed `tame-oauth` dependency

## [0.3.1] - 2021-05-07
### Changed
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

<!-- next-url -->
[Unreleased]: https://github.com/EmbarkStudios/tame-oidc/compare/0.5.0...HEAD
[0.5.0]: https://github.com/EmbarkStudios/tame-oidc/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/EmbarkStudios/tame-oidc/compare/0.3.1...0.4.0
[0.3.1]: https://github.com/EmbarkStudios/tame-oidc/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/EmbarkStudios/tame-oidc/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/EmbarkStudios/tame-oidc/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/EmbarkStudios/tame-oidc/compare/0.0.1...0.1.0
[0.0.1]: https://github.com/EmbarkStudios/tame-oidc/releases/tag/0.0.1
