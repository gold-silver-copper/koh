//! `koh key` — manage the on-disk identity key's passphrase.
//!
//! The analogue of `ssh-keygen -p`: change the passphrase that encrypts the identity key (the
//! `koh-key-v1` format — Argon2id + AES-256-GCM; see [`crate::transport_iroh`]). The key is always
//! encrypted — there is no plaintext format and no way to remove encryption. The key material is
//! never changed, so the node's endpoint id is preserved across a passphrase change.

use std::path::PathBuf;

use anyhow::Context;
#[cfg(feature = "cli")]
use clap::{Args, Subcommand};

use crate::transport_iroh::{
    default_key_path, enforce_passphrase_strength, format_endpoint_id, write_identity_key,
};

/// What [`run`] should do to the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOp {
    /// Change the passphrase encrypting the identity key (like `ssh-keygen -p`). The key stays
    /// encrypted — there is no way to store it in plaintext.
    Passwd,
    /// Print the key's encryption status and endpoint id (never the secret).
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

/// Arguments for `koh key` (the clap adapter over [`KeyConfig`]; `cli` feature only).
#[cfg(feature = "cli")]
#[derive(Args, Debug)]
pub struct KeyArgs {
    #[command(subcommand)]
    cmd: KeyCmd,
    /// Which identity key to operate on. Defaults to the client key path (as `koh id` uses); pass a
    /// server key explicitly to manage it.
    #[arg(long, global = true)]
    key_file: Option<PathBuf>,
}

#[cfg(feature = "cli")]
#[derive(Subcommand, Debug)]
enum KeyCmd {
    /// Change the passphrase encrypting the identity key (like `ssh-keygen -p`). The key stays
    /// encrypted — there is no way to store it in plaintext.
    Passwd,
    /// Print the key's encryption status and endpoint id (never the secret).
    Info,
    /// Delete an unused identity; the next use creates a new endpoint ID.
    Reset {
        /// Acknowledge permanent identity loss and required allowlist updates.
        #[arg(long)]
        yes: bool,
    },
}

#[cfg(feature = "cli")]
impl From<KeyArgs> for KeyConfig {
    fn from(a: KeyArgs) -> Self {
        Self {
            op: match a.cmd {
                KeyCmd::Passwd => KeyOp::Passwd,
                KeyCmd::Info => KeyOp::Info,
                KeyCmd::Reset { yes } => KeyOp::Reset { confirmed: yes },
            },
            key_file: a.key_file,
        }
    }
}

/// Run `koh key`. Accepts a [`KeyConfig`] or anything convertible into one ([`KeyArgs`] under
/// the `cli` feature). `Passwd` prompts on the terminal unless `$KOH_KEY_NEW_PASSPHRASE` is set.
pub fn run(config: impl Into<KeyConfig>) -> anyhow::Result<()> {
    let args: KeyConfig = config.into();
    let key_file = match args.key_file {
        Some(p) => p,
        None => default_key_path("client")?,
    };
    if let KeyOp::Reset { confirmed } = args.op {
        anyhow::ensure!(confirmed, "reset permanently deletes {}; the next use changes the endpoint ID and requires allowlist updates. Stop active users, then repeat with --yes", key_file.display());
        crate::identity::reset(&key_file)?;
        println!(
            "Removed {}. The next use creates a new endpoint ID; update remote allowlists.",
            key_file.display()
        );
        return Ok(());
    }
    anyhow::ensure!(
        key_file.exists(),
        "no identity key at {} — run `koh id` (or `koh connect`/`koh serve`) to create one first, \
         or pass --key-file",
        key_file.display()
    );
    // Loading prompts for the CURRENT passphrase ($KOH_KEY_PASSPHRASE or a TTY prompt) and yields the
    // secret key, whose bytes we then re-persist unchanged — preserving the endpoint id.
    let identity = crate::identity::load(&key_file)?;
    let secret = &identity.secret;

    match args.op {
        KeyOp::Info => {
            println!("key file    : {}", key_file.display());
            println!("encryption  : koh-key-v1 (Argon2id + AES-256-GCM)");
            println!("endpoint id : {}", format_endpoint_id(&secret.public()));
        }
        KeyOp::Reset { .. } => anyhow::bail!("reset was not dispatched"),
        KeyOp::Passwd => {
            let _prompt = crate::identity::PromptTerminal::protect()?;
            // The NEW passphrase: `$KOH_KEY_NEW_PASSPHRASE` (automation/CI) or a confirmed prompt.
            // It must be non-empty — encryption is mandatory. The CURRENT passphrase was supplied to
            // the load above via `$KOH_KEY_PASSPHRASE` or its prompt.
            let new = if let Ok(p) = std::env::var("KOH_KEY_NEW_PASSPHRASE") {
                anyhow::ensure!(
                    !p.is_empty(),
                    "$KOH_KEY_NEW_PASSPHRASE is empty; identity keys are always encrypted"
                );
                p
            } else {
                let p1 = rpassword::prompt_password("New passphrase: ")
                    .context("reading new passphrase")?;
                anyhow::ensure!(
                    !p1.is_empty(),
                    "an empty passphrase is not allowed; identity keys are always encrypted"
                );
                let p2 = rpassword::prompt_password("Confirm passphrase: ")
                    .context("reading confirmation")?;
                anyhow::ensure!(p1 == p2, "passphrases did not match");
                p1
            };
            enforce_passphrase_strength(&new)?;
            write_identity_key(&key_file, secret, &new)?;
            eprintln!(
                "koh: identity key re-encrypted at {} (koh-key-v1). Set $KOH_KEY_PASSPHRASE for \
                 unattended `koh serve`.",
                key_file.display()
            );
        }
    }
    Ok(())
}
