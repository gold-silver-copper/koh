//! Opaque prepared identities and credential operations for applications embedding koh.
//!
//! Credentials are resolved before an application starts input readers. Network consumers receive
//! an `Identity`, never a transport-specific secret key. Transfer buffers are only for private,
//! same-user IPC; they are not an on-disk format and must never be logged or persisted.
use anyhow::{ensure, Context as _};
use std::collections::BTreeMap;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Identity {
    pub(crate) secret: iroh::SecretKey,
    lease: Option<Arc<IdentityLease>>,
}

impl Identity {
    #[must_use]
    pub fn generate() -> Self {
        Self {
            secret: crate::transport_iroh::generate_secret_key(),
            lease: None,
        }
    }

    #[must_use]
    pub fn endpoint_id(&self) -> String {
        crate::transport_iroh::format_endpoint_id(&self.secret.public())
    }

    /// Export only to a private, authenticated local IPC channel. Never log or persist this buffer.
    #[must_use]
    pub fn transfer(&self) -> Zeroizing<Vec<u8>> {
        let path = self
            .lease
            .as_ref()
            .map_or(&[][..], |lease| lease.path.as_os_str().as_bytes());
        let mut bytes = Zeroizing::new(Vec::with_capacity(10 + path.len() + 32));
        bytes.extend_from_slice(b"KOHID1");
        bytes.extend_from_slice(&u32::try_from(path.len()).unwrap_or(u32::MAX).to_be_bytes());
        bytes.extend_from_slice(path);
        bytes.extend_from_slice(&self.secret.to_bytes());
        bytes
    }

    /// Consume a private IPC payload, clearing it on both success and failure.
    pub fn receive(bytes: &mut [u8]) -> anyhow::Result<Self> {
        let owned = Zeroizing::new(bytes.to_vec());
        bytes.fill(0);
        ensure!(
            owned.get(..6) == Some(b"KOHID1"),
            "invalid koh identity transfer version"
        );
        let length = u32::from_be_bytes(
            owned
                .get(6..10)
                .context("truncated identity transfer")?
                .try_into()?,
        ) as usize;
        ensure!(
            length <= 4096 && owned.len() == 10 + length + 32,
            "invalid koh identity transfer length"
        );
        let lease = if length == 0 {
            None
        } else {
            let path = PathBuf::from(std::ffi::OsString::from_vec(
                owned
                    .get(10..10 + length)
                    .context("truncated identity path")?
                    .to_vec(),
            ));
            Some(Arc::new(IdentityLease::acquire(&path, false)?))
        };
        let raw = Zeroizing::new(<[u8; 32]>::try_from(
            owned
                .get(10 + length..)
                .context("truncated identity secret")?,
        )?);
        Ok(Self {
            secret: iroh::SecretKey::from_bytes(&raw),
            lease,
        })
    }
}

/// Invocation-scoped cache. Neither passphrases nor prepared identities are cached process-wide.
#[derive(Default)]
pub struct IdentityStore {
    loaded: BTreeMap<PathBuf, Identity>,
}

impl IdentityStore {
    pub fn load(&mut self, path: &Path) -> anyhow::Result<Identity> {
        if let Some(identity) = self.loaded.get(path) {
            return Ok(identity.clone());
        }
        let identity = load(path)?;
        self.loaded.insert(path.to_owned(), identity.clone());
        Ok(identity)
    }
}

pub fn default_path(role: &str) -> anyhow::Result<PathBuf> {
    Ok(crate::transport_iroh::default_key_path(role)?)
}

pub fn load(path: &Path) -> anyhow::Result<Identity> {
    let _terminal = PromptTerminal::protect()?;
    let lease = Arc::new(IdentityLease::acquire(path, false)?);
    let secret = crate::transport_iroh::load_or_create_secret_key(path)
        .with_context(|| format!("unlocking identity at {}", path.display()))?;
    Ok(Identity {
        secret,
        lease: Some(lease),
    })
}

pub fn load_client(path: Option<&Path>) -> anyhow::Result<Identity> {
    match path {
        Some(path) => load(path),
        None => load(&default_path("client")?),
    }
}

/// Reset an identity only after the application has excluded active users and concurrent startup.
/// Applications retain ownership of their workspace lifetime; koh owns path validation/removal.
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

/// Transfer a startup identity pair without exposing key sizes or encoding to the application.
#[must_use]
pub fn transfer_pair(client: &Identity, server: &Identity) -> Zeroizing<Vec<u8>> {
    let client = client.transfer();
    let server = server.transfer();
    let mut bytes = Zeroizing::new(Vec::with_capacity(4 + client.len() + server.len()));
    bytes.extend_from_slice(
        &u32::try_from(client.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&client);
    bytes.extend_from_slice(&server);
    bytes
}

pub fn receive_pair(bytes: &mut [u8]) -> anyhow::Result<(Identity, Identity)> {
    let mut owned = Zeroizing::new(bytes.to_vec());
    bytes.fill(0);
    let length = u32::from_be_bytes(
        owned
            .get(..4)
            .context("truncated koh identity bundle")?
            .try_into()?,
    ) as usize;
    ensure!(
        length <= 8192 && owned.len() >= 4 + length,
        "invalid koh identity bundle length"
    );
    let (client, server) = owned
        .get_mut(4..)
        .context("truncated identity bundle")?
        .split_at_mut(length);
    let client = Identity::receive(client);
    let server = Identity::receive(server);
    Ok((client?, server?))
}

struct IdentityLease {
    path: PathBuf,
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
        Ok(Self { path, _lock: lock })
    }
}

/// Restore terminal settings when a credential prompt is interrupted.
///
/// The synchronous password reader cannot unwind on a fatal signal. During a prompt, a signal
/// watcher restores the controlling terminal before exiting. No daemon child or input producer
/// may be started in this scope. Normal return closes and joins the watcher before continuing.
pub struct PromptTerminal {
    watcher: Option<(signal_hook::iterator::Handle, std::thread::JoinHandle<()>)>,
}

impl PromptTerminal {
    pub fn protect() -> anyhow::Result<Self> {
        use nix::sys::termios::{tcgetattr, tcsetattr, SetArg};
        use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
        let Ok(tty) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
        else {
            return Ok(Self { watcher: None });
        };
        let saved = tcgetattr(&tty)?;
        let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM, SIGHUP])?;
        let handle = signals.handle();
        let watcher = std::thread::Builder::new()
            .name("koh-prompt-signals".into())
            .spawn(move || {
                if let Some(signal) = signals.forever().next() {
                    let _ = tcsetattr(&tty, SetArg::TCSANOW, &saved);
                    std::process::exit(128 + signal);
                }
            })?;
        Ok(Self {
            watcher: Some((handle, watcher)),
        })
    }
}

impl Drop for PromptTerminal {
    fn drop(&mut self) {
        if let Some((handle, watcher)) = self.watcher.take() {
            handle.close();
            let _ = watcher.join();
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn transfers_preserve_identity_and_clear_input_on_every_decode_path() -> anyhow::Result<()> {
        let identity = Identity::generate();
        let original = identity.transfer();
        let mut valid = original.to_vec();
        assert_eq!(
            Identity::receive(&mut valid)?.endpoint_id(),
            identity.endpoint_id()
        );
        assert!(valid.iter().all(|byte| *byte == 0));
        for length in 0..original.len() {
            let mut truncated = original.get(..length).context("prefix")?.to_vec();
            assert!(Identity::receive(&mut truncated).is_err());
            assert!(truncated.iter().all(|byte| *byte == 0));
        }
        let other = Identity::generate();
        let mut bundle = transfer_pair(&identity, &other);
        let (client, server) = receive_pair(&mut bundle)?;
        assert_eq!(client.endpoint_id(), identity.endpoint_id());
        assert_eq!(server.endpoint_id(), other.endpoint_id());
        assert!(bundle.iter().all(|byte| *byte == 0));
        let mut malformed = transfer_pair(&identity, &other);
        *malformed.last_mut().context("bundle tail")? = 7;
        malformed.push(1); // trailing data invalidates the second identity
        assert!(receive_pair(&mut malformed).is_err());
        assert!(malformed.iter().all(|byte| *byte == 0));
        Ok(())
    }

    #[test]
    fn transferred_and_cloned_leases_block_reset_until_the_last_owner_drops() -> anyhow::Result<()>
    {
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
        // Reset must also support unreadable/corrupt encrypted content without unlocking it.
        std::fs::write(&path, b"corrupt disposable key")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let identity = Identity {
            secret: crate::transport_iroh::generate_secret_key(),
            lease: Some(Arc::new(IdentityLease::acquire(&path, false)?)),
        };
        let clone = identity.clone();
        let transferred = Identity::receive(&mut identity.transfer())?;
        assert!(reset(&path).is_err());
        drop(identity);
        drop(clone);
        assert!(reset(&path).is_err());
        assert!(path.exists());
        drop(transferred);
        reset(&path)?;
        assert!(!path.exists());
        Ok(())
    }
}
