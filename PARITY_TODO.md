# Rust Parity TODO

This file tracks the Rust port's parity status against the Go `tls-client` codebase under `tls-client/`.

## Status

- [x] Custom Rust HTTP/1.1 + HTTP/2 transport
- [x] Transport-agnostic Rust profile model
- [x] Live parity checks for the currently supported Rust profile subset
- [x] Full Go profile catalog in Rust
- [x] Full HTTP/3 / QUIC runtime parity
- [x] Full proxy / pinning / racing / bandwidth parity
- [x] Full Go test-suite coverage parity
- [ ] FFI / distribution parity for `cffi_src` and `cffi_dist`

## Missing Profile Keys

Go profile registry: 79 keys in [tls-client/profiles/profiles.go](tls-client/profiles/profiles.go)

Rust profile registry: 79 keys in [src/profile.rs](src/profile.rs)

All Go profile keys are now exposed in the Rust registry.

Transport fidelity is now tracked by ignored live differential suites instead of manual checklist gaps:

- [x] PSK/resumption-backed variants: `chrome_*_PSK`, `firefox_146_PSK`, `firefox_147_PSK`
- [x] `chrome_146` / `chrome_146_PSK` differential coverage
- [x] `brave_146` / `brave_146_PSK` differential coverage
- [x] Custom/mobile profile differential coverage for `zalando_*`, `nike_*`, `cloudscraper`, `mms_*`, `mesh_*`, `confirmed_*`

## Runtime Parity Work

### Core Transport

- [x] Add a real HTTP/3 / QUIC request path
- [x] Implement HTTP/3 settings order
- [x] Implement HTTP/3 pseudo-header order
- [x] Implement HTTP/3 priority param
- [x] Implement HTTP/3 grease frame behavior
- [x] Implement ALPN-driven H3 selection and fallback
- [x] Implement protocol racing between H2 and H3

### Network / Dialing

- [x] Enforce `disable_ipv4`
- [x] Enforce `disable_ipv6`
- [x] Implement `proxy_url` runtime support
- [x] Implement HTTP CONNECT proxy support
- [x] Implement HTTPS proxy support
- [x] Implement SOCKS4 proxy support
- [x] Implement SOCKS5 proxy support
- [x] Implement custom dial-context override for transport wiring
- [x] Add mutable runtime proxy updates similar to Go `SetProxy` / `GetProxy`

### Security

- [x] Enforce certificate pinning at handshake / post-handshake
- [x] Support wildcard and subdomain pin matching
- [x] Add bad-pin callback behavior comparable to Go

### Observability

- [x] Add bandwidth tracking primitives
- [x] Expose bandwidth stats on the client
- [x] Track read/write bytes for HTTP/1.1
- [x] Track read/write bytes for HTTP/2
- [x] Track read/write bytes for HTTP/3 once implemented

## API Parity Work

- [x] Add client methods equivalent to Go proxy mutation APIs
- [x] Add client methods equivalent to Go bandwidth access APIs
- [x] Add client methods equivalent to Go dialer access APIs where appropriate
- [x] Route `websocket` connections through the same dial/TLS stack as normal requests

## Subdirectory Parity Work

### `tls-client/profiles`

- [x] Port remaining profile registry entries
- [x] Add profile generation / extraction tooling to avoid manual drift

### `tls-client/bandwidth`

- [x] Port tracker behavior
- [x] Port tracked connection semantics where feasible

### `tls-client/cffi_src`

- [x] Design Rust equivalent export surface
- [x] Decide ABI strategy
- [x] Port initial request factory/types behavior

### `tls-client/cffi_dist`

- [ ] Port distribution/export examples or provide Rust-native equivalents
- [ ] Replace example consumers or document the new Rust distribution story

### `tls-client/example`

- [x] Add a Rust example app that covers the same core flows

## Test Parity Work

Go test files under `tls-client/tests/` still requiring full parity coverage:

- [x] `client_test.go`
- [x] `config_validation_test.go`
- [x] `cookie_jar_test.go`
- [x] `firefox_unsupported_group_test.go`
- [x] `header_order_test.go`
- [x] `hooks_test.go`
- [x] `http3_chrome_cloudflare_test.go`
- [x] `http3_fingerprint_test.go`
- [x] `http3_roundtripper_path_test.go`
- [x] `http3_test.go`
- [x] `ja3_test.go`
- [x] `keep_alive_test.go`
- [x] `keep_compressed_test.go`
- [x] `random_extension_order_test.go`
- [x] `redirect_and_timeout_test.go`
- [x] `websocket_test.go`

## Current Execution Order

1. Non-FFI parity work is complete in this repository snapshot.
2. Any remaining work is optional live-network re-verification.
3. FFI / distribution parity remains separate and intentionally out of scope unless needed.

## Notes

- `cargo test -q` is green after the latest dialer/websocket/bandwidth/example/tooling pass.
- `cargo build -q` is green after adding the Rust `cdylib` FFI target.
- `cargo run -q --bin profile_registry_audit` reports `go_profiles=79` and `rust_profiles=79`.
- The websocket client now uses the same internal dial/TLS path as normal requests instead of `tokio_tungstenite::connect_async`.
- The all-profile ignored live differential suite is in [tests/profile_parity_live.rs](tests/profile_parity_live.rs) and iterates over the full Rust/Go registry.
- The initial Rust FFI entry points are in [src/ffi.rs](src/ffi.rs): `request`, `getCookiesFromSession`, `addCookiesToSession`, `destroySession`, `destroyAll`, and `freeMemory`.
- The Rust FFI currently supports the JSON request/session flow for profile-based clients; `customTlsClient` and replacement consumer examples are still outstanding.
- The Rust example app in [examples/main.rs](examples/main.rs) now covers the runnable Go example flows: pinning configuration, GET, POST, redirect toggling, proxy mutation, image download, PSK warmup, and ALPS inspection.
- The only Go example flows not mirrored as executable Rust calls are the ad-hoc custom profile / JA3 builder demos, because the public Rust example API does not yet expose custom profile construction.
- `http3_live` is fully green on the Rust side, including Cloudflare, direct-path HTTP/3, and BrowserLeaks parity for `chrome_144` and `firefox_147`.
- The Go `Chrome_133` BrowserLeaks expectation is still subject to live upstream drift as of April 24, 2026, but the Rust port now has the corresponding ignored HTTP/3 fingerprint coverage in place.
