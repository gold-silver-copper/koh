//! `koh key` — inspect or reset the on-disk identity key.
//!
//! The key file holds the node's secret key, protected by its permissions (0600). `info` prints the
//! endpoint id it gives; `reset` deletes it, so the next use creates a new identity.

use std::path::PathBuf;

use crate::transport_iroh::{default_key_path, format_endpoint_id};

#[cfg(feature = "cli")]
pub use crate::args::KeyArgs;

/// What [`run`] should do to the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOp {
    /// Print the key file and its endpoint id (never the secret).
    Info,
    /// Remove an unused identity after acknowledging endpoint-ID and allowlist changes.
    Reset { confirmed: bool },
}

/// Configuration for [`run`] — the clap-free, library-facing form of `koh key`'s arguments.
#[derive(Debug, Clone)]
pub struct KeyConfig {
    /// The operation to perform.
    pub op: KeyOp,
    /// Which identity key to operate on. `None` = the client key path (as `koh id` uses); pass a
    /// server key explicitly to manage it.
    pub key_file: Option<PathBuf>,
}

/// Run `koh key`. Accepts a [`KeyConfig`] or anything convertible into one (`KeyArgs` under
/// the `cli` feature).
pub fn run(config: impl Into<KeyConfig>) -> anyhow::Result<()> {
    let args: KeyConfig = config.into();
    let key_file = match args.key_file {
        Some(p) => p,
        None => default_key_path("client")?,
    };
    match args.op {
        KeyOp::Reset { confirmed } => {
            anyhow::ensure!(
                confirmed,
                "reset permanently deletes {}; the next use changes the endpoint ID and requires \
                 allowlist updates. Stop active users, then repeat with --yes",
                key_file.display()
            );
            crate::identity::reset(&key_file)?;
            println!(
                "Removed {}. The next use creates a new endpoint ID; update remote allowlists.",
                key_file.display()
            );
        }
        KeyOp::Info => {
            anyhow::ensure!(
                key_file.exists(),
                "no identity key at {} — run `koh id` (or `koh connect`/`koh serve`) to create one \
                 first, or pass --key-file",
                key_file.display()
            );
            let identity = crate::identity::load(&key_file)?;
            println!("key file    : {}", key_file.display());
            println!("endpoint id : {}", format_endpoint_id(&identity.secret.public()));
        }
    }
    Ok(())
}
