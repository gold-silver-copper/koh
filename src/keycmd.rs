//! `koh id` and `koh key`: show or reset the on-disk identity keys.
//!
//! A key file holds a node's secret key, protected by its permissions (0600). A machine has two:
//! the client key (`koh connect`) and the server key (`koh serve`). `id` prints the client key's
//! endpoint id, creating the key if there is none; `info` prints both key files and their ids;
//! `reset` deletes one, so the next use creates a new identity.

use std::path::PathBuf;

/// What [`run`] should do to the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOp {
    /// Print the endpoint id alone (`koh id`), creating the key if there is none.
    Id,
    /// Print the key files and their endpoint ids (never the secret).
    Info,
    /// Remove an unused identity after acknowledging endpoint-ID and allowlist changes.
    Reset { confirmed: bool },
}

/// The clap-free form of `koh id`'s and `koh key`'s arguments.
#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub op: KeyOp,
    /// Which key: `"client"` (as `koh id` uses) or `"server"`.
    pub role: &'static str,
    /// The key file, if not the role's default path. `info` with neither shows both keys.
    pub key_file: Option<PathBuf>,
    /// Whether the role was named (`koh key reset server`), so `info` shows that key alone.
    pub role_named: bool,
}

/// Run `koh id` or `koh key`.
pub fn run(config: &KeyConfig) -> anyhow::Result<()> {
    let path = crate::identity::KeyFile::path_for(config.key_file.clone(), config.role)?;
    // Refused before the key's directory is created or judged: an unconfirmed reset touches nothing.
    anyhow::ensure!(
        config.op != KeyOp::Reset { confirmed: false },
        "reset permanently deletes the {} key {}; {} Stop active users, then repeat with --yes",
        config.role,
        path.display(),
        who_loses_access(config.role)
    );
    match config.op {
        KeyOp::Id => {
            let key_file = crate::identity::KeyFile::open(&path)?;
            println!("{}", crate::identity::load(&key_file)?.endpoint_id());
        }
        KeyOp::Reset { confirmed: _ } => {
            reset(&path)?;
            println!(
                "Removed {}. The next use creates a new endpoint ID; {}",
                path.display(),
                who_loses_access(config.role)
            );
        }
        // Creates nothing, so asking about a key that is not there leaves no trace.
        KeyOp::Info if config.key_file.is_some() || config.role_named => {
            let identity = crate::identity::load_existing(&path)?;
            println!("key file    : {}", path.display());
            println!("endpoint id : {}", identity.endpoint_id());
        }
        KeyOp::Info => {
            let mut found = false;
            for role in ["client", "server"] {
                let path = crate::identity::KeyFile::path_for(None, role)?;
                println!("{role} key  : {}", path.display());
                match crate::identity::load_existing(&path) {
                    Ok(identity) => {
                        found = true;
                        println!("endpoint id : {}", identity.endpoint_id());
                    }
                    Err(_none_yet) => println!("endpoint id : none yet ({})", creates(role)),
                }
            }
            anyhow::ensure!(
                found,
                "no identity key yet — run `koh id` (or `koh connect`/`koh serve`) to create one"
            );
        }
    }
    Ok(())
}

/// Delete the key at `path`; refused while any koh holds it.
pub fn reset(path: &std::path::Path) -> anyhow::Result<()> {
    crate::identity::KeyFile::open(path)?.reset()
}

/// What resetting the `role` key breaks, and what to do about it.
pub fn who_loses_access(role: &str) -> &'static str {
    if role == "server" {
        "every client that connects here must save this server's new id (`koh servers add`)."
    } else {
        "every server that allows you must allow your new client id (`koh clients add` there)."
    }
}

/// The command that creates the `role` key.
pub fn creates(role: &str) -> &'static str {
    if role == "server" {
        "`koh serve` creates it"
    } else {
        "`koh id` creates it"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unconfirmed_reset_creates_and_judges_nothing() {
        let root = std::env::temp_dir().join(format!("koh-keycmd-{}", std::process::id()));
        let missing = root.join("newdir");
        let error = run(&KeyConfig {
            op: KeyOp::Reset { confirmed: false },
            role: "client",
            key_file: Some(missing.join("id.key")),
            role_named: false,
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
        let error = run(&KeyConfig {
            op: KeyOp::Info,
            role: "client",
            key_file: Some(missing.join("id.key")),
            role_named: false,
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
