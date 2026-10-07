//! `koh id` and `koh key`: show or reset the on-disk identity key.
//!
//! The key file holds the node's secret key, protected by its permissions (0600). `id` prints the
//! endpoint id it gives, creating the key if there is none; `info` also prints the key file; `reset`
//! deletes it, so the next use creates a new identity.

use std::path::PathBuf;

/// What [`run`] should do to the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOp {
    /// Print the endpoint id alone (`koh id`), creating the key if there is none.
    Id,
    /// Print the key file and its endpoint id (never the secret).
    Info,
    /// Remove an unused identity after acknowledging endpoint-ID and allowlist changes.
    Reset { confirmed: bool },
}

/// The clap-free form of `koh id`'s and `koh key`'s arguments.
#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub op: KeyOp,
    /// Which identity key to operate on. `None` = the client key path; pass a server key
    /// explicitly to manage it.
    pub key_file: Option<PathBuf>,
}

/// Run `koh id` or `koh key`.
pub fn run(config: KeyConfig) -> anyhow::Result<()> {
    let key_file = crate::identity::KeyFile::locate(config.key_file, "client")?;
    match config.op {
        KeyOp::Id => println!("{}", crate::identity::load(&key_file)?.endpoint_id()),
        KeyOp::Reset { confirmed } => {
            anyhow::ensure!(
                confirmed,
                "reset permanently deletes {key_file}; the next use changes the endpoint ID and \
                 requires allowlist updates. Stop active users, then repeat with --yes"
            );
            crate::identity::reset(&key_file)?;
            println!(
                "Removed {key_file}. The next use creates a new endpoint ID; update remote \
                 allowlists."
            );
        }
        KeyOp::Info => {
            let identity = crate::identity::load_existing(&key_file)?;
            println!("key file    : {key_file}");
            println!("endpoint id : {}", identity.endpoint_id());
        }
    }
    Ok(())
}
