<div align="center">

# `🧬 tame-oidc`

**`tame-oidc` is a small [OpenID Connect](https://openid.net/connect/) crate that follows the [sans-io](https://sans-io.readthedocs.io/) approach.**

[![Embark](https://img.shields.io/badge/embark-open%20source-blueviolet.svg)](http://embark.games)
[![Embark](https://img.shields.io/badge/discord-ark-%237289da.svg?logo=discord)](https://discord.gg/dAuKfZS)
[![Crates.io](https://img.shields.io/crates/v/tame-oidc.svg)](https://crates.io/crates/tame-oidc)
[![Docs](https://docs.rs/tame-oidc/badge.svg)](https://docs.rs/tame-oidc)
[![dependency status](https://deps.rs/repo/github/EmbarkStudios/tame-oidc/status.svg)](https://deps.rs/repo/github/EmbarkStudios/tame-oidc)
[![Build status](https://github.com/gleam-lang/gleam/workflows/ci/badge.svg?branch=main)](https://github.com/EmbarkStudios/tame-oidc/actions)

</div>

Supported RFCs:

- [RFC7636 Proof Key for Code Exchange by OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636#page-3)

## Why?

- You want to control how you actually make OIDC HTTP requests

## Why not?

- The only auth flow that is currently implemented are the flows we are using internally. Other flows can be added, but right now that is the only one we need.
- This crate requires more boilerplate to use.

## Usage

See example code in `examples/embark.rs`

## Examples

### [embark](examples/embark.rs)

Usage: `cargo run --example embark`

A small example of using `tame-oidc` together with [reqwest](https://github.com/seanmonstar/reqwest).

## Contributing

[![Contributor Covenant](https://img.shields.io/badge/contributor%20covenant-v1.4-ff69b4.svg)](CODE_OF_CONDUCT.md)

We welcome community contributions to this project.

Please read our [Contributor Guide](CONTRIBUTING.md) for more information on how to get started.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
