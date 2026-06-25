//! `koh key` — manage the on-disk identity key's passphrase.
//!
//! The analogue of `ssh-keygen -p`: change the passphrase that encrypts the identity key (the
//! `koh-key-v1` format — Argon2id + AES-256-GCM; see [`crate::transport_iroh`]). The key is always
//! encrypted — there is no plaintext format and no way to remove encryption. The key material is
//! never changed, so the node's endpoint id is preserved across a passphrase change.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Args, Subcommand};

use crate::transport_iroh::{
    default_key_path, enforce_passphrase_strength, format_endpoint_id, load_or_create_secret_key,
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
    /// Change the passphrase encrypting the identity key (like `ssh-keygen -p`). The key stays
    /// encrypted — there is no way to store it in plaintext.
    Passwd,
    /// Print the key's encryption status and endpoint id (never the secret).
    Info,
}

/// Run `koh key`.
pub fn run(args: KeyArgs) -> anyhow::Result<()> {
    let key_file = match args.key_file {
        Some(p) => p,
        None => default_key_path("client")?,
    };
    anyhow::ensure!(
        key_file.exists(),
        "no identity key at {} — run `koh id` (or `koh connect`/`koh serve`) to create one first, \
         or pass --key-file",
        key_file.display()
    );
    // Loading prompts for the CURRENT passphrase ($KOH_KEY_PASSPHRASE or a TTY prompt) and yields the
    // secret key, whose bytes we then re-persist unchanged — preserving the endpoint id.
    let secret = load_or_create_secret_key(&key_file)
        .with_context(|| format!("loading identity key from {}", key_file.display()))?;

    match args.cmd {
        KeyCmd::Info => {
            println!("key file    : {}", key_file.display());
            println!("encryption  : koh-key-v1 (Argon2id + AES-256-GCM)");
            println!("endpoint id : {}", format_endpoint_id(&secret.public()));
        }
        KeyCmd::Passwd => {
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
            write_identity_key(&key_file, &secret, &new)?;
            eprintln!(
                "koh: identity key re-encrypted at {} (koh-key-v1). Set $KOH_KEY_PASSPHRASE for \
                 unattended `koh serve`.",
                key_file.display()
            );
        }
    }
    Ok(())
}
