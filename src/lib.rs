//! # koh
//!
//! mosh (the mobile shell), reimplemented in Rust over [iroh](https://iroh.computer) p2p QUIC.
//! A resilient peer-to-peer remote shell: instant local echo on laggy links, survival across
//! suspend/resume and IP changes, transparent reconnect/reattach, and no head-of-line blocking.
//!
//! This crate is both the library and the `koh` binary. It is a state-synchronization system
//! whose payload happens to be a terminal — each side holds an authoritative object and the
//! protocol brings the peer to the **latest** version of it, collapsing intermediate states.
//!
//! ## Module map
//!
//! - [`wire`] — SSP instruction envelope, postcard codec, fragmenter/reassembler.
//! - [`ssp`] — the `SyncState` trait + generic `Transport<Local, Remote>` + send scheduler, with
//!   a deterministic lossy/reordering chaos sim harness ([`ssp::testkit`]).
//! - [`terminal`] — `TerminalScreen` state (vt100-backed) + the `ServerTerminal` live emulator.
//! - [`input`] — `UserInput` state: keystrokes + resize as an append-only synced log.
//! - [`predict`] — local-echo prediction engine (overlays, epochs, adaptive engage) over any
//!   [`predict::ScreenView`]. Depends only on `vt100` + `unicode-width` (no `crate::` imports), so
//!   it is a standalone, transport- and koh-agnostic terminal-prediction library — reusable as-is
//!   by a different front-end.
//! - [`transport_iroh`] — iroh endpoint setup, persistent (encrypted) identity, datagram channel,
//!   RTT, and a 1-byte connection-admission ack (authorization is the node-id allowlist checked in
//!   `koh serve`).
//! - [`pty`] — PTY allocation, shell spawn, SIGWINCH, child reaping.
//! - [`server`] — a [`server::SessionHost`] (PTY + emulator by default) + `Transport<State, Input>`
//!   over iroh, plus `koh serve` and the generic [`server::serve_with`].
//! - [`client`] — input + `Transport<Input, State>` + predictor + a backend-agnostic renderer
//!   (the [`client::backend`] seam: `termina` by default; `crossterm` / `qwertty` optional), plus
//!   `koh connect` and the generic [`embed::Connection`] over any [`client::ClientState`].
//! - [`identity`] — opaque unlocked identities, private credential storage/prompting and reset leases.
//! - [`embed`] — transport-independent authenticated connections and hosted application sessions.
//! - [`keycmd`] — `koh key`: change the identity key's encryption passphrase (`ssh-keygen -p`-style).
//!
//! Dependency direction is strict: `wire ← ssp ← {terminal, input}`, with `predict` over
//! `{terminal, input}`, `transport_iroh` over `wire`, and `server`/`client` on top. The entire
//! protocol (`ssp`, `terminal`, `input`, `predict`, `wire`) is transport-agnostic — only
//! `transport_iroh`, `identity`, `embed`, `server`, and `client` touch iroh. (A CI check enforces the load-bearing edges:
//! `predict` imports nothing from `crate::`, and `server`/`client` never `use crate::wire` directly.)
//!
//! ## Public API stability
//!
//! koh ships **binary-first**, but the entry points are designed to be embedded. The *supported*
//! library surface is:
//!
//! - [`server::serve`] with [`server::ServeConfig`],
//! - [`client::connect`] with [`client::ConnectConfig`],
//! - [`client::run_id`] with [`client::IdConfig`],
//! - [`keycmd::run`] with [`keycmd::KeyConfig`],
//! - the [`SyncState`](ssp::SyncState) / [`Transport`](ssp::Transport) protocol core in [`ssp`],
//! - since 0.11, the generic seams: [`server::SessionHost`], [`server::HostProvider`]
//!   ([`server::PtyHosts`], [`server::SharedHost`]), [`server::serve_with`] with [`server::Hosts`],
//!   [`server::ClientId`]; [`client::ClientState`], [`client::ClientTerminal`],
//!   [`embed::Connection`], [`client::run_client`], [`client::BellHook`]; [`predict::ScreenView`];
//!   [`transport_iroh::TERMINAL_ALPN`]; and [`terminal::ServerTerminal`]'s `progress` /
//!   `take_unhandled_oscs` accessors.
//!
//! **The synced state type a connection carries is selected by its ALPN** (KH-02):
//! [`transport_iroh::TERMINAL_ALPN`] (`koh/iroh/1`) is the [`terminal::TerminalScreen`] every koh
//! release speaks; an embedding server registers its own ALPN per state via
//! [`server::Hosts`], and a client dials the ALPN of the state it renders. `TerminalScreen` on
//! the wire is unchanged and `PROTOCOL_VERSION` stays 3.
//!
//! The config types have public fields and no clap dependency. Everything else is `pub` only so the
//! in-tree integration tests and the `chaos` example can drive it as a downstream dependency; treat
//! it as **internal and unstable** — it may change in any release without a semver-major bump. Do
//! not build external code against it. That includes [`ssp::testkit`] (the sim harness, `Rng`,
//! `LogState`, `GridState`) and the `ClientState` impl for `GridState`: `#[doc(hidden)]` test
//! infrastructure that the integration tests need to reach from outside the crate.
//!
//! ## Features
//!
//! - `cli` (default): pulls in clap and enables the `koh` binary plus the `*Args` adapter structs
//!   (`ServeArgs`, `ConnectArgs`, `IdArgs`, `KeyArgs`), each `Into` its config type. Those adapters
//!   are *not* part of the stable surface.
//! - `backend-termina` (default) / `backend-crossterm` / `backend-qwertty`: the client's terminal
//!   backend; exactly one must be enabled.
//!
//! Embedding koh: `koh = { version = "0.11", default-features = false, features =
//! ["backend-termina"] }`, then e.g. `server::serve(ServeConfig { allow, command, ..Default::default() })`,
//! or `serve_with(config, Hosts::new().with(b"my/state/1", SharedHost::new(|| Ok(MyHost::new()))))`
//! to sync a state of your own.

pub mod client;
pub mod embed;
pub mod identity;
pub mod input;
pub mod keycmd;
pub mod predict;
pub mod pty;
pub mod server;
pub mod ssp;
pub mod terminal;
pub mod transport_iroh;
pub mod wire;

/// In-process integration + chaos driver (wires client/server transports through the
/// deterministic chaotic link in [`ssp::testkit`]). Used by `tests/integration.rs` and the
/// `chaos` example; hidden from the public docs.
#[doc(hidden)]
pub mod sim;
