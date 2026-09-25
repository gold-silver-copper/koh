//! Unlocked identities and the credential operations behind `koh serve`, `connect`, `id` and `key`.
//!
//! Loading an identity holds a shared lease (an `flock` beside the key file) for as long as any
//! clone of it lives, so `koh key reset` refuses to delete a key a running koh is still using.
use anyhow::{ensure, Context as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
pub struct Identity {
    pub(crate) secret: iroh::SecretKey,
    /// Held, never read: dropping the last clone releases the key's shared lock.
    _lease: Option<Arc<IdentityLease>>,
}

impl Identity {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            secret: crate::transport_iroh::generate_secret_key(),
            _lease: None,
        }
    }

    #[must_use]
    pub fn endpoint_id(&self) -> String {
        crate::transport_iroh::format_endpoint_id(&self.secret.public())
    }
}

pub fn default_path(role: &str) -> anyhow::Result<PathBuf> {
    Ok(crate::transport_iroh::default_key_path(role)?)
}

pub fn load(path: &Path) -> anyhow::Result<Identity> {
    let lease = Arc::new(IdentityLease::acquire(path, false)?);
    let secret = crate::transport_iroh::load_or_create_secret_key(path)
        .with_context(|| format!("loading identity at {}", path.display()))?;
    Ok(Identity {
        secret,
        _lease: Some(lease),
    })
}

pub fn load_client(path: Option<&Path>) -> anyhow::Result<Identity> {
    match path {
        Some(path) => load(path),
        None => load(&default_path("client")?),
    }
}

/// Delete an identity key. Fails while any koh process still holds its lease, and refuses unsafe
/// paths (symlinks, foreign owners, non-private directories).
pub fn reset(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let _lease = IdentityLease::acquire(path, true)?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting identity at {}", path.display()))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = std::fs::symlink_metadata(parent)?;
    ensure!(
        directory.is_dir()
            && !directory.file_type().is_symlink()
            && directory.permissions().mode().trailing_zeros() >= 6
            && metadata.uid() == directory.uid()
            && metadata.is_file()
            && !metadata.file_type().is_symlink(),
        "refusing to reset an unsafe identity path or non-private containing directory: {}",
        path.display()
    );
    std::fs::remove_file(path).with_context(|| format!("removing identity at {}", path.display()))
}

struct IdentityLease {
    _lock: nix::fcntl::Flock<std::fs::File>,
}

impl IdentityLease {
    fn acquire(path: &Path, exclusive: bool) -> anyhow::Result<Self> {
        use nix::fcntl::{Flock, FlockArg};
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        crate::transport_iroh::create_dir_private(parent)?;
        crate::transport_iroh::ensure_state_dir_secure(parent)?;
        let path = parent
            .canonicalize()?
            .join(path.file_name().context("identity path has no filename")?);
        let mut lock_name = path
            .file_name()
            .context("identity filename")?
            .to_os_string();
        lock_name.push(".koh-lock");
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path.with_file_name(lock_name))?;
        let meta = lock.metadata()?;
        ensure!(
            meta.is_file()
                && meta.uid() == nix::unistd::geteuid().as_raw()
                && meta.permissions().mode().trailing_zeros() >= 6,
            "unsafe identity lease file"
        );
        let kind = if exclusive {
            FlockArg::LockExclusiveNonblock
        } else {
            FlockArg::LockSharedNonblock
        };
        let lock = Flock::lock(lock, kind).map_err(|(_, error)| {
            anyhow::anyhow!(
                "identity {} is in use or being reset: {error}; stop its active users before reset",
                path.display()
            )
        })?;
        Ok(Self { _lock: lock })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn cloned_leases_block_reset_until_the_last_owner_drops() -> anyhow::Result<()> {
        struct TestDirectory(PathBuf);
        impl Drop for TestDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = TestDirectory(
            std::env::temp_dir().join(format!("koh-lease-{}", Identity::generate().endpoint_id())),
        );
        crate::transport_iroh::create_dir_private(&directory.0)?;
        let path = directory.0.join("identity.key");
        // Reset must also work on a file that is not a valid key, without loading it.
        std::fs::write(&path, b"corrupt disposable key")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let identity = Identity {
            secret: crate::transport_iroh::generate_secret_key(),
            _lease: Some(Arc::new(IdentityLease::acquire(&path, false)?)),
        };
        let clone = identity.clone();
        anyhow::ensure!(reset(&path).is_err(), "reset while two leases are held");
        drop(identity);
        anyhow::ensure!(
            reset(&path).is_err(),
            "reset while the clone's lease is held"
        );
        anyhow::ensure!(path.exists(), "a refused reset removed the key");
        drop(clone);
        reset(&path)?;
        anyhow::ensure!(!path.exists(), "reset left the key in place");
        Ok(())
    }
}
