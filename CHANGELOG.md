# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [0.3.2] - 2019-07-19
### Changed
 - Middleware accepts any `Fn` as a validator function instead of `FnMut` ([#11](https://github.com/svartalf/actix-web-httpauth/pull/11))

## [0.3.1] - 2019-06-09
### Fixed
 - Multiple calls to the middleware would result in panic

## [0.3.0] - 2019-06-05
### Changed
 - Crate edition was changed to `2018`, same as `actix-web`
 - Depends on `actix-web = "^1.0"` version now
 - `WWWAuthenticate` header struct was renamed into `WwwAuthenticate`
 - Challenges and extractor configs are now operating with `Cow<'static, str>` types instead of `String` types

## [0.2.0] - 2019-04-26
### Changed
 - `actix-web` dependency is used without default features now ([#6](https://github.com/svartalf/actix-web-httpauth/pull/6))
 - `base64` dependency version was bumped to `0.10`

## [0.1.0] - 2018-09-08
### Changed
 - Update to `actix-web = "0.7"` version

## [0.0.4] - 2018-07-01
### Fixed
 - Fix possible panic at `IntoHeaderValue` implementation for `headers::authorization::Basic`
 - Fix possible panic at `headers::www_authenticate::challenge::bearer::Bearer::to_bytes` call
