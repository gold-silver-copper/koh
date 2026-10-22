//! `koh id` and `koh key reset`: print or delete an on-disk identity key.
//!
//! A machine has two keys, each a file of its secret, protected by its permissions (0600): the
//! client key (`koh connect`) and the server key (`koh serve`). `id` prints one's endpoint id,
//! creating the key if there is none; `reset` deletes one, so the next use creates a new identity.

use std::path::PathBuf;

/// What [`run`] does to the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOp {
    /// Print its endpoint id, creating the key if there is none.
    Id,
    /// Delete it.
    Reset,
}

/// The clap-free form of `koh id`'s and `koh key reset`'s arguments.
#[derive(Debug, Clone)]
pub struct KeyConfig {
    pub op: KeyOp,
    /// Which key: `"client"` or `"server"`.
    pub role: &'static str,
    /// The key file, if not the role's default path.
    pub key_file: Option<PathBuf>,
}

/// Run `koh id` or `koh key reset`.
pub fn run(config: &KeyConfig) -> anyhow::Result<()> {
    use std::io::Write as _;
    let path = crate::identity::KeyFile::path_for(config.key_file.clone(), config.role)?;
    let mut out = std::io::stdout().lock();
    match config.op {
        KeyOp::Id => {
            let key = crate::identity::KeyFile::open(&path)?;
            writeln!(out, "{}", crate::identity::load(&key)?.public())?;
        }
        KeyOp::Reset => {
            reset(&path)?;
            writeln!(
                out,
                "Removed {}. The next use creates a new endpoint ID; {}",
                path.display(),
                who_loses_access(config.role)
            )?;
        }
    }
    Ok(())
}

/// Delete the key at `path`.
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
