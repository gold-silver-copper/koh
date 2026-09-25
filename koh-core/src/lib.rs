//! # koh-core
//!
//! The library behind the `koh` remote shell: `koh serve` hosts a PTY for allowlisted peers and
//! `koh connect` renders it with predictive local echo, reconnecting transparently.
//!
//! ## Modules
//!
//! [`transport_iroh`] owns endpoint setup, the identity key file and connection admission.
//! [`identity`] loads identities and holds their reset leases; [`idcmd`] and [`keycmd`] implement
//! `koh id` and `koh key`. [`proto`] is the wire protocol: input messages on one stream, screen
//! frames on their own. [`terminal`], [`predict`] and [`pty`] implement the remote-shell payload;
//! [`server`] hosts detachable sessions and [`client`] renders them on the tty. The `koh` crate
//! adds the command line.
//!
//! Production code here is panic-free by construction: `Cargo.toml` forbids the panic lints, lossy
//! casts and unchecked arithmetic, and a `forbid` cannot be lifted by a local `#[allow]` or
//! `#[expect]`. Tests may panic (see `clippy.toml`).
//!
//! The library exists so the binary, its tests and the fuzz targets share code. Everything in it
//! is internal and may change in any release.

pub mod client;
pub mod idcmd;
pub mod identity;
pub mod keycmd;
pub mod predict;
pub mod proto;
pub mod pty;
pub mod server;
pub mod terminal;
pub mod transport_iroh;

#[cfg(test)]
mod test_runtime;
