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
//! - [`predict`] — local-echo prediction engine (overlays, epochs, adaptive engage). Depends only
//!   on `vt100` + `unicode-width` (no `crate::` imports), so it is a standalone, transport- and
//!   koh-agnostic terminal-prediction library — reusable as-is by a different front-end.
//! - [`transport_iroh`] — iroh endpoint setup, persistent identity, datagram channel, RTT, auth.
//! - [`pty`] — PTY allocation, shell spawn, SIGWINCH, child reaping.
//! - [`server`] — PTY + emulator + `Transport<Screen, Input>` over iroh, plus `koh serve`.
//! - [`client`] — input + `Transport<Input, Screen>` + predictor + termina render, plus `koh connect`.
//!
//! Dependency direction is strict: `wire ← ssp ← {terminal, input}`, with `predict` over
//! `{terminal, input}`, `transport_iroh` over `wire`, and `server`/`client` on top. The entire
//! protocol (`ssp`, `terminal`, `input`, `predict`, `wire`) is transport-agnostic — only
//! `transport_iroh`, `server`, and `client` touch iroh. (A CI check enforces the load-bearing edges:
//! `predict` imports nothing from `crate::`, and `server`/`client` never `use crate::wire` directly.)
//!
//! ## Public API stability
//!
//! koh ships **binary-first**. The *supported* library surface is [`server::serve`],
//! [`client::connect`], [`client::run_id`], [`keycmd::run`], and the [`SyncState`](ssp::SyncState) /
//! [`Transport`](ssp::Transport) protocol core in [`ssp`]. Everything else is `pub` only so the in-tree
//! integration tests and the `chaos` example can drive it as a downstream dependency; treat it as
//! **internal and unstable** — it may change in any release without a semver-major bump. Do not build
//! external code against it.

pub mod client;
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
