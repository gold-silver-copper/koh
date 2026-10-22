//! Identities: a machine's client and server keys, each in a [`KeyFile`].
use anyhow::Context as _;
use iroh::SecretKey;

mod key_file;
pub(crate) use key_file::open_private_log;
pub use key_file::KeyFile;

/// Load the key at `key`, creating it if absent. The file is the key's raw bytes, protected by its
/// permissions (0600) like an SSH host key.
pub fn load(key: &KeyFile) -> anyhow::Result<SecretKey> {
    load_or_create(key, true)
}

/// Load the key at `path`, `None` if there is none. Creates nothing, not even its directory.
pub fn load_existing(path: &std::path::Path) -> anyhow::Result<Option<SecretKey>> {
    KeyFile::open_existing(path)?
        .map(|key| load_or_create(&key, false))
        .transpose()
}

fn no_key(key: impl std::fmt::Display) -> String {
    format!(
        "no identity key at {key} — run `koh id` (or `koh connect`/`koh serve`) to create one \
         first, or pass --key-file"
    )
}

fn load_or_create(key: &KeyFile, create: bool) -> anyhow::Result<SecretKey> {
    match key.read_secret() {
        Ok(None) if create => key.create_secret(),
        read => read,
    }
    .with_context(|| format!("loading identity at {key}"))?
    .with_context(|| no_key(key))
}
