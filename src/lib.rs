//! # koh
//!
//! Authenticated connectivity over iroh, with two explicit products:
//!
//! - The `gateway` feature forwards opaque bytes to an independently owned local service.
//!   It owns authorization, connectivity and bounded reconnect state. It does not interpret
//!   fux/zor messages, own their processes or decide application retries.
//! - The `shell` feature hosts PTYs and synchronizes terminal state, with predictive echo
//!   and rendering. A terminal backend feature enables this product.
//!
//! Default builds enable the gateway, CLI and standalone shell with the termina backend.
//! `--no-default-features --features cli,gateway` builds the gateway CLI without shell PTYs,
//! terminal emulation, prediction or backends. It retains identity display and key management.
//!
//! ## Ownership and modules
//!
//! [`transport_iroh`] owns endpoint setup, encrypted persistent identity plumbing, connection
//! admission and network profiles. [`identity`] provides unlocked identities, credentials
//! and reset leases. [`idcmd`] and [`keycmd`] provide shell-independent identity commands.
//! [`wire`] and [`ssp`] provide the generic state synchronization protocol; they contain no
//! terminal emulator or application policy.
//!
//! With `gateway`, the `gateway` module provides authorized opaque local-service forwarding.
//! Current fux integration uses this process boundary, not the standalone shell embedding API.
//! Gateway reconnect does not provide predictive rendering or authorize recreating an agent.
//!
//! With `shell`, `terminal`, `input`, `predict` and `pty` implement the remote-shell payload.
//! `server` hosts sessions; `client` supplies terminal backends and rendering; `embed` provides
//! generic session hosting/connection APIs. These modules are absent from gateway-only builds.
//! `sim` is shell test infrastructure. Shell embedding consumers select a backend feature,
//! for example `default-features = false, features = ["backend-termina"]`.
//!
//! The config types are clap-free. The `cli` feature adds argument adapters and the binary.
//! Gateway library consumers can select only `gateway`. Shared transport changes require
//! independent verification of gateway and shell configurations.
//!
//! Public APIs outside the documented product entry points and configuration types are
//! internal and may change without a semver-major release.

#[cfg(feature = "shell")]
pub mod client;
#[cfg(feature = "shell")]
pub mod embed;
pub mod identity;
#[cfg(feature = "shell")]
pub mod input;
pub mod keycmd;
#[cfg(feature = "shell")]
pub mod predict;
#[cfg(feature = "shell")]
pub mod pty;
#[cfg(feature = "shell")]
pub mod server;
pub mod ssp;
#[cfg(feature = "shell")]
pub mod terminal;
pub mod transport_iroh;
pub mod wire;

/// In-process integration + chaos driver (wires client/server transports through the
/// deterministic chaotic link in `ssp::testkit`). Used by `tests/integration.rs` and the
/// `chaos` example; hidden from the public docs.
#[doc(hidden)]
#[cfg(all(feature = "shell", any(test, feature = "test-support")))]
pub mod sim;

#[cfg(feature = "gateway")]
pub mod gateway;
pub mod idcmd;
