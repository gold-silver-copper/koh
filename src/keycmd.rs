//! `koh key` — manage at-rest encryption of the on-disk identity key.
//!
//! The analogue of `ssh-keygen -p`: add, change, or remove the passphrase that encrypts the identity
//! key (the `koh-key-v1` format — Argon2id + AES-256-GCM; see [`crate::transport_iroh`]). The key
//! material is never changed, so the node's endpoint id is preserved across a passphrase change.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Subcommand};

use crate::transport_iroh::{
    default_key_path, format_endpoint_id, identity_key_is_encrypted, load_or_create_secret_key,
    write_identity_key,
};

/// Arguments for `koh key`.
#[derive(Args, Debug)]
pub struct KeyArgs {
    #[command(subcommand)]
    cmd: KeyCmd,
    /// Which identity key to operate on. Defaults to the client key path (as `koh id` uses); pass a
    /// server key explicitly to manage it.
    #[arg(long, global = true)]
    key_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum KeyCmd {
    /// Set, change, or remove the passphrase encrypting the identity key (like `ssh-keygen -p`).
    /// An empty new passphrase removes encryption (stores plaintext hex again).
    Passwd,
    /// Print the key's at-rest encryption status and endpoint id (never the secret).
    Info,
}

/// Run `koh key`.
pub fn run(args: KeyArgs) -> anyhow::Result<()> {
    let key_file = args.key_file.unwrap_or_else(|| default_key_path("client"));
    anyhow::ensure!(
        key_file.exists(),
        "no identity key at {} — run `koh id` (or `koh connect`/`koh serve`) to create one first, \
         or pass --key-file",
        key_file.display()
    );
    // Status is read from the file header (no secret access / no prompt).
    let was_encrypted = identity_key_is_encrypted(&key_file);
    // Loading prompts for the CURRENT passphrase if the key is encrypted, and yields the secret key
    // (whose bytes we then re-persist unchanged — preserving the endpoint id).
    let secret = load_or_create_secret_key(&key_file)
        .with_context(|| format!("loading identity key from {}", key_file.display()))?;

    match args.cmd {
        KeyCmd::Info => {
            println!("key file    : {}", key_file.display());
            println!(
                "encryption  : {}",
                if was_encrypted {
                    "koh-key-v1 (Argon2id + AES-256-GCM)"
                } else {
                    "none (plaintext hex — protected only by file permissions)"
                }
            );
            println!("endpoint id : {}", format_endpoint_id(&secret.public()));
        }
        KeyCmd::Passwd => {
            // Non-interactive override (for automation / CI): if `$KOH_KEY_NEW_PASSPHRASE` is set,
            // use it verbatim (an empty value removes encryption); otherwise prompt with confirmation.
            // The CURRENT passphrase, if the key is already encrypted, was supplied to the load above
            // via `$KOH_KEY_PASSPHRASE` or its prompt.
            let new = if let Ok(p) = std::env::var("KOH_KEY_NEW_PASSPHRASE") {
                p
            } else {
                let p1 =
                    rpassword::prompt_password("New passphrase (empty to remove encryption): ")
                        .context("reading new passphrase")?;
                if !p1.is_empty() {
                    let p2 = rpassword::prompt_password("Confirm passphrase: ")
                        .context("reading confirmation")?;
                    anyhow::ensure!(p1 == p2, "passphrases did not match");
                }
                p1
            };
            if new.is_empty() {
                write_identity_key(&key_file, &secret, None)?;
                eprintln!(
                    "koh: identity key stored UNENCRYPTED at {} (plaintext hex; protected only by \
                     file permissions).",
                    key_file.display()
                );
            } else {
                write_identity_key(&key_file, &secret, Some(&new))?;
                eprintln!(
                    "koh: identity key encrypted at {} (koh-key-v1). Set $KOH_KEY_PASSPHRASE for \
                     unattended `koh serve`.",
                    key_file.display()
                );
            }
        }
    }
    Ok(())
}
