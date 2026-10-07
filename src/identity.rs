//! Identities. A loaded one holds a shared lease (an `flock` beside the key file) while any clone
//! lives, so `koh key reset` refuses to delete a key in use.
use anyhow::Context as _;
use std::sync::Arc;

mod key_file;
pub(crate) use key_file::open_private_log;
use key_file::IdentityLease;
pub use key_file::KeyFile;

#[derive(Clone)]
pub struct Identity {
    pub(crate) secret: iroh::SecretKey,
    /// Held, never read: dropping the last clone releases the key's shared lock.
    _lease: Option<Arc<IdentityLease>>,
}

impl Identity {
    /// A new identity with no key file behind it. Fails only if the OS has no randomness.
    pub fn generate() -> std::io::Result<Self> {
        Ok(Self {
            secret: crate::transport_iroh::generate_secret_key()?,
            _lease: None,
        })
    }

    #[must_use]
    pub fn endpoint_id(&self) -> iroh::EndpointId {
        self.secret.public()
    }
}

/// Load the identity at `key`, creating it if absent. The file is the key's raw bytes, protected
/// by its permissions (0600) like an SSH host key.
pub fn load(key: &KeyFile) -> anyhow::Result<Identity> {
    load_or_create(key, true)
}

/// Load the identity at `key`, which must exist.
pub fn load_existing(key: &KeyFile) -> anyhow::Result<Identity> {
    load_or_create(key, false)
}

fn load_or_create(key: &KeyFile, create: bool) -> anyhow::Result<Identity> {
    let lease = Arc::new(key.lease(false)?);
    let secret = match key.read_secret() {
        Ok(None) if create => key.create_secret(),
        read => read,
    }
    .with_context(|| format!("loading identity at {key}"))?
    .with_context(|| {
        format!(
            "no identity key at {key} — run `koh id` (or `koh connect`/`koh serve`) to create one \
             first, or pass --key-file"
        )
    })?;
    Ok(Identity {
        secret,
        _lease: Some(lease),
    })
}

/// Delete an identity key, whatever the file holds. Fails while any koh process still holds its
/// lease, and refuses any path a load would refuse.
pub fn reset(key: &KeyFile) -> anyhow::Result<()> {
    let _lease = key.lease(true)?;
    key.remove()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    #[test]
    fn cloned_leases_block_reset_until_the_last_owner_drops() -> anyhow::Result<()> {
        struct TestDirectory(PathBuf);
        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = TestDirectory(
            std::env::temp_dir().join(format!("koh-lease-{}", Identity::generate()?.endpoint_id())),
        );
        let path = directory.0.join("identity.key");
        let key = KeyFile::open(&path)?;
        // Reset must also work on a file that is not a valid key, without loading it.
        std::fs::write(&path, b"corrupt disposable key")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let identity = Identity {
            secret: crate::transport_iroh::generate_secret_key()?,
            _lease: Some(Arc::new(key.lease(false)?)),
        };
        let clone = identity.clone();
        anyhow::ensure!(reset(&key).is_err(), "reset while two leases are held");
        drop(identity);
        anyhow::ensure!(
            reset(&key).is_err(),
            "reset while the clone's lease is held"
        );
        anyhow::ensure!(path.exists(), "a refused reset removed the key");
        drop(clone);
        reset(&key)?;
        anyhow::ensure!(!path.exists(), "reset left the key in place");
        Ok(())
    }

    /// The rule for trusting an identity path is one rule: a key that `load` accepts (or that it
    /// rejects with `NotAKey`, whose message says to run `koh key reset`) is one `reset` can remove.
    #[test]
    fn reset_accepts_every_key_path_that_load_accepts() -> anyhow::Result<()> {
        struct TestDirectory(PathBuf);
        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = TestDirectory(
            std::env::temp_dir().join(format!("koh-trust-{}", Identity::generate()?.endpoint_id())),
        );
        std::fs::create_dir(&directory.0)?;
        // A 0755 dir, like a default-umask ~/.config/koh: `load` trusts it (it only warns).
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o755))?;

        let path = directory.0.join("identity.key");
        std::fs::write(&path, [7u8; crate::transport_iroh::KEY_LEN])?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let key = KeyFile::open(&path)?;
        let identity = load(&key)?;
        drop(identity);
        reset(&key).map_err(|e| {
            anyhow::anyhow!("load accepted {} but reset refused: {e:#}", path.display())
        })?;
        anyhow::ensure!(!path.exists(), "reset left the key in place");

        // A 31-byte file: load says to run `koh key reset`, which must then work.
        let bad = directory.0.join("short.key");
        std::fs::write(&bad, [7u8; 31])?;
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o600))?;
        let bad_key = KeyFile::open(&bad)?;
        let error = load(&bad_key)
            .err()
            .context("load accepted a 31-byte key")?;
        anyhow::ensure!(format!("{error:#}").contains("koh key reset"), "{error:#}");
        reset(&bad_key).map_err(|e| {
            anyhow::anyhow!(
                "load told the user to reset {} but reset refused: {e:#}",
                bad.display()
            )
        })?;
        Ok(())
    }
}
