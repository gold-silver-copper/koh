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
    let path = crate::identity::KeyFile::path_for(config.key_file, "client")?;
    // Refused before the key's directory is created or judged: an unconfirmed reset touches nothing.
    anyhow::ensure!(
        config.op != KeyOp::Reset { confirmed: false },
        "reset permanently deletes {}; the next use changes the endpoint ID and requires allowlist \
         updates. Stop active users, then repeat with --yes",
        path.display()
    );
    match config.op {
        KeyOp::Id => {
            let key_file = crate::identity::KeyFile::open(&path)?;
            println!("{}", crate::identity::load(&key_file)?.endpoint_id());
        }
        KeyOp::Reset { confirmed: _ } => {
            let key_file = crate::identity::KeyFile::open(&path)?;
            key_file.reset()?;
            println!(
                "Removed {key_file}. The next use creates a new endpoint ID; update remote \
                 allowlists."
            );
        }
        // Creates nothing, so asking about a key that is not there leaves no trace.
        KeyOp::Info => {
            let identity = crate::identity::load_existing(&path)?;
            println!("key file    : {}", path.display());
            println!("endpoint id : {}", identity.endpoint_id());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unconfirmed_reset_creates_and_judges_nothing() {
        let root = std::env::temp_dir().join(format!("koh-keycmd-{}", std::process::id()));
        let missing = root.join("newdir");
        let error = run(KeyConfig {
            op: KeyOp::Reset { confirmed: false },
            key_file: Some(missing.join("id.key")),
        })
        .expect_err("refused without --yes");
        assert!(format!("{error:#}").contains("--yes"), "{error:#}");
        assert!(
            !missing.exists(),
            "an unconfirmed reset created the key's directory"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn info_on_a_missing_key_creates_nothing() {
        let root = std::env::temp_dir().join(format!("koh-keycmd-info-{}", std::process::id()));
        let missing = root.join("newdir");
        let error = run(KeyConfig {
            op: KeyOp::Info,
            key_file: Some(missing.join("id.key")),
        })
        .expect_err("there is no key");
        assert!(format!("{error:#}").contains("run `koh id`"), "{error:#}");
        assert!(!root.exists(), "info created the key's directory");
    }

    #[test]
    fn a_given_key_path_is_used_as_given() {
        let path = PathBuf::from("some/where.key");
        assert_eq!(
            crate::identity::KeyFile::path_for(Some(path.clone()), "client").unwrap(),
            path
        );
    }
}
