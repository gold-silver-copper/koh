//! The one owner of trust in an identity path. A [`KeyFile`] can only be made by [`KeyFile::open`],
//! which judges the key's directory once; every file in it (the key and its lock) is opened without
//! following a symlink and judged by [`check_private`], as `$KOH_LOG` is. Its fields are private to
//! this module, so the code that loads or resets a key cannot reach the path to apply rules of its
//! own.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use iroh::SecretKey;

use crate::transport_iroh::{SetupError, KEY_LEN};

/// An identity key's path whose directory was found safe: it exists, and no other user can replace
/// a file in it.
pub struct KeyFile {
    /// The directory's canonical path, locked to create a key.
    dir: PathBuf,
    /// The key in that directory, where every file is opened.
    path: PathBuf,
    /// The path as given, for messages.
    shown: PathBuf,
}

impl std::fmt::Display for KeyFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.shown.display().fmt(f)
    }
}

impl KeyFile {
    /// `path`, or else the default key path for `role` (`"client"` or `"server"`).
    pub fn locate(path: Option<PathBuf>, role: &str) -> anyhow::Result<Self> {
        Self::open(&path.map_or_else(|| crate::transport_iroh::default_key_path(role), Ok)?)
    }

    /// Create the key's directory if it is missing (0700), then judge it: refused if another user
    /// could replace the key in it, warned about if it is merely loose.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let name = path.file_name().context("identity path has no filename")?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let parent = parent.canonicalize()?;
        let mode = std::fs::metadata(&parent)?.permissions().mode();
        // Only other-writable without the sticky bit (which limits unlink to owners, as in /tmp's
        // 1777) lets another user replace the key. Group-writable is allowed: Android's
        // /data/local/tmp is 0771, and a single-user device has no co-tenant.
        if mode & 0o002 != 0 && mode & 0o1000 == 0 {
            return Err(SetupError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "state dir {} is world-writable without the sticky bit (mode {:o}); any user \
                     could replace the secret key — chmod 700 it, add the sticky bit, or pass \
                     --key-file pointing at a private path",
                    parent.display(),
                    mode & 0o7777
                ),
            ))
            .into());
        }
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %parent.display(),
                mode = format!("{:o}", mode & 0o7777),
                "state dir is group/other-accessible; the key is still 0600, but prefer chmod 700"
            );
        }
        Ok(Self {
            path: parent.join(name),
            dir: parent,
            shown: path.to_path_buf(),
        })
    }

    /// A `flock` on the key's lock file (`<key>.koh-lock`), shared by users and exclusive for a
    /// reset.
    pub(super) fn lease(&self, exclusive: bool) -> anyhow::Result<IdentityLease> {
        let mut lock_name = self.path.as_os_str().to_os_string();
        lock_name.push(".koh-lock");
        let lock = open_private(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600),
            Path::new(&lock_name),
        )?;
        let locked = if exclusive {
            lock.try_lock()
        } else {
            lock.try_lock_shared()
        };
        locked.map_err(|error| {
            anyhow::anyhow!(
                "identity {self} is in use or being reset: {error}; stop its active users before \
                 reset"
            )
        })?;
        Ok(IdentityLease { _lock: lock })
    }

    /// The key, or `None` if there is no file. A symlink (even a dangling one) is refused, never
    /// followed, and a file that is not exactly [`KEY_LEN`] bytes is not a key.
    pub(super) fn read_secret(&self) -> Result<Option<SecretKey>, SetupError> {
        use std::io::Read as _;
        let file = match open_private(OpenOptions::new().read(true), &self.path) {
            Ok(file) => file,
            Err(SetupError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        // Read one byte past a key, so an oversized file is detected without reading all of it.
        let mut bytes = Vec::with_capacity(KEY_LEN.saturating_add(1));
        let limit = u64::try_from(KEY_LEN.saturating_add(1)).unwrap_or(u64::MAX);
        file.take(limit).read_to_end(&mut bytes)?;
        let Ok(raw) = <[u8; KEY_LEN]>::try_from(bytes.as_slice()) else {
            return Err(SetupError::NotAKey(self.to_string()));
        };
        Ok(Some(SecretKey::from_bytes(&raw)))
    }

    /// Create a key, without replacing one another process published first (whose key is then the
    /// identity): with the directory locked, check the key is still absent, write a born-private
    /// (0600) temporary file and rename it into place.
    ///
    /// Not a hard link, which would need no lock: Android's SELinux policy denies `link` to the
    /// shell and to apps.
    pub(super) fn create_secret(&self) -> Result<Option<SecretKey>, SetupError> {
        use std::io::Write as _;
        let secret = crate::transport_iroh::generate_secret_key()?;
        // Held until this returns: creators take turns, so only the first finds the key absent,
        // and a reader sees no key or a whole one.
        let directory = File::open(&self.dir)?;
        directory.lock()?;
        match std::fs::symlink_metadata(&self.path) {
            Ok(_) => return self.read_secret(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let (tmp, mut file) = loop {
            let tmp = self.path.with_extension(format!(
                "tmp.{}.{:016x}",
                std::process::id(),
                getrandom::u64().map_err(std::io::Error::from)?
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
            {
                Ok(file) => break (tmp, file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        };
        let result = (|| {
            file.write_all(&secret.to_bytes())?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&tmp, &self.path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(tmp);
        }
        Ok(result.map(|()| Some(secret))?)
    }

    /// Remove the key, whatever it holds, under an exclusive lease: fails while any koh process
    /// still holds the key, and refuses only what every load refuses (a symlink, a file that is not
    /// regular, or another user's file). The file is never opened, so a key the user cannot read
    /// can still be reset, and a FIFO at the path is refused rather than waited on. The check and
    /// the unlink are two steps, but only users [`KeyFile::open`] trusted can write the directory,
    /// and an unlink never follows a link.
    pub fn reset(&self) -> anyhow::Result<()> {
        let _lease = self.lease(true)?;
        let context = || format!("removing identity at {self}");
        let meta = std::fs::symlink_metadata(&self.path).with_context(context)?;
        check_owned(&meta, &self.path).with_context(context)?;
        std::fs::remove_file(&self.path).with_context(context)
    }
}

/// Open `$KOH_LOG` as a private file: never through a symlink, and only truncated once it passes
/// the same check as a key, as debug logs can be sensitive.
pub fn open_private_log(path: &Path) -> Result<File, SetupError> {
    let file = open_private(
        OpenOptions::new().write(true).create(true).mode(0o600),
        path,
    )
    .map_err(|error| {
        // Named for what it is: the shared error speaks of a key.
        if matches!(error, SetupError::BadKeyFile) {
            refuse(path, "it is a symlink or not a regular file")
        } else {
            error
        }
    })?;
    file.set_len(0)?;
    Ok(file)
}

/// A `flock` on the identity's lock file; closing the file releases it.
pub(super) struct IdentityLease {
    _lock: File,
}

/// Open `path` with `options` and no symlink followed, then [`check_private`] it.
fn open_private(options: &mut OpenOptions, path: &Path) -> Result<File, SetupError> {
    let file = match options.custom_flags(fuxix::file::NOFOLLOW).open(path) {
        Ok(file) => file,
        // The open refused a symlink (ELOOP); asking afterwards only names the refusal.
        Err(_) if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) => {
            tracing::warn!(path = %path.display(), "refusing a symlinked identity file");
            return Err(SetupError::BadKeyFile);
        }
        Err(error) => return Err(error.into()),
    };
    check_private(&file, path)?;
    Ok(file)
}

/// The one rule for a private file: a regular file of this user's, readable by no one else. A
/// loose mode, say from a permissive backup, is tightened to 0600 through the descriptor; a file
/// that cannot be tightened is refused.
fn check_private(file: &File, path: &Path) -> Result<(), SetupError> {
    let meta = file.metadata()?;
    check_owned(&meta, path)?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                refuse(
                    path,
                    &format!(
                        "mode {:o} is group/other-accessible and could not be tightened ({error}); \
                         fix it with `chmod 600`",
                        mode & 0o777
                    ),
                )
            })?;
        tracing::warn!(
            path = %path.display(),
            prev_mode = format!("{:o}", mode & 0o777),
            "identity file was group/other-accessible; tightened to 0600 (via fd)"
        );
    }
    Ok(())
}

/// The part of [`check_private`] a reset also applies: a regular file (not a symlink, FIFO or
/// device) owned by this user.
fn check_owned(meta: &std::fs::Metadata, path: &Path) -> Result<(), SetupError> {
    if !meta.is_file() {
        tracing::warn!(path = %path.display(), "refusing an identity file that is not a regular file");
        return Err(SetupError::BadKeyFile);
    }
    let euid = fuxix::process::geteuid();
    if meta.uid() != euid {
        return Err(refuse(
            path,
            &format!("it is owned by uid {}, not by uid {euid}", meta.uid()),
        ));
    }
    Ok(())
}

fn refuse(path: &Path, why: &str) -> SetupError {
    std::io::Error::other(format!("refusing {}: {why}", path.display())).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{load, load_existing};
    use crate::transport_iroh::{generate_secret_key, parse_endpoint_id};

    /// A fresh directory under the temp dir with `mode`, removed on drop.
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(name: &str, mode: u32) -> Self {
            let dir = std::env::temp_dir().join(format!("koh-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            Self(dir)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    #[test]
    fn a_created_key_is_its_raw_bytes_and_loads_back_to_the_same_identity() {
        let dir = Scratch::new("key-test", 0o700);
        let path = dir.0.join("id.key");
        let key = KeyFile::open(&path).unwrap();
        let first = load(&key).expect("create a key");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            first.secret.to_bytes(),
            "the file is the raw key"
        );
        assert_eq!(mode_of(&path), 0o600, "a created key is owner-only");
        let second = load(&key).expect("load it back");
        assert_eq!(first.endpoint_id(), second.endpoint_id(), "round-trips");
        let id = first.endpoint_id();
        assert_eq!(parse_endpoint_id(&id.to_string()).unwrap(), id);
    }

    #[test]
    fn a_missing_directory_is_created_private() {
        let dir = Scratch::new("key-perm", 0o700);
        let path = dir.0.join("state").join("id.key");
        load(&KeyFile::open(&path).unwrap()).expect("create a key");
        assert_eq!(mode_of(&dir.0.join("state")), 0o700);
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn concurrent_first_key_creation_publishes_exactly_one_identity() {
        let dir = Scratch::new("key-create-race", 0o700);
        let path = dir.0.join("id.key");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let key = KeyFile::open(&path).unwrap();
            let barrier = std::sync::Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                key.create_secret().unwrap().unwrap().to_bytes()
            }));
        }
        barrier.wait();
        // Each creator ends with the one published key, whoever published it.
        for thread in threads {
            let secret = thread.join().unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), secret);
        }
    }

    #[test]
    fn preplanted_predictable_temporary_name_cannot_block_key_creation() {
        let dir = Scratch::new("key-preplant", 0o700);
        let path = dir.0.join("id.key");
        let predictable = path.with_extension(format!("tmp.{}.1", std::process::id()));
        std::fs::write(&predictable, b"attacker-owned").unwrap();
        let key = KeyFile::open(&path).unwrap();
        let secret = key.create_secret().unwrap().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), secret.to_bytes());
        assert_eq!(std::fs::read(&predictable).unwrap(), b"attacker-owned");
    }

    #[test]
    fn only_a_nonsticky_world_writable_directory_is_refused() {
        // A merely group-writable dir (Android's /data/local/tmp is 0771) and a sticky
        // world-writable one (/tmp's 1777, where only owners unlink) are allowed, else koh can't
        // start in those standard locations.
        let dir = Scratch::new("ww", 0o777);
        let path = dir.0.join("id.key");
        assert!(KeyFile::open(&path).is_err(), "0777 is refused");
        for mode in [0o700, 0o755, 0o771, 0o1777] {
            std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(KeyFile::open(&path).is_ok(), "{mode:o} is allowed");
        }
    }

    #[test]
    fn a_symlinked_key_is_refused_and_its_target_left_alone() {
        let dir = Scratch::new("symlink", 0o700);
        let target = dir.0.join("victim");
        std::fs::write(&target, [7u8; KEY_LEN]).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.0.join("server.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let key = KeyFile::open(&link).unwrap();
        assert!(matches!(key.read_secret(), Err(SetupError::BadKeyFile)));
        assert!(load(&key).is_err(), "load refuses it too");
        assert!(key.reset().is_err(), "and so does reset");
        assert_eq!(mode_of(&target), 0o644, "the target is not re-permissioned");
        assert!(target.exists() && link.exists());
    }

    #[test]
    fn a_dangling_symlink_is_refused_instead_of_creating_or_missing_a_key() {
        let dir = Scratch::new("dangling-keylink", 0o700);
        let link = dir.0.join("server.key");
        std::os::unix::fs::symlink(dir.0.join("missing"), &link).unwrap();
        let key = KeyFile::open(&link).unwrap();
        for result in [load(&key), load_existing(&key)] {
            let error = result.err().expect("refused");
            assert!(
                matches!(error.downcast_ref(), Some(SetupError::BadKeyFile)),
                "{error:#}"
            );
        }
        assert!(!dir.0.join("missing").exists(), "nothing was created");
    }

    #[test]
    fn a_missing_key_is_not_created_by_load_existing() {
        let dir = Scratch::new("no-key", 0o700);
        let path = dir.0.join("id.key");
        let error = load_existing(&KeyFile::open(&path).unwrap()).err().unwrap();
        assert!(format!("{error:#}").contains("run `koh id`"), "{error:#}");
        assert!(!path.exists());
    }

    #[test]
    fn loose_key_and_lock_files_are_tightened_through_the_descriptor() {
        let dir = Scratch::new("loose", 0o700);
        let path = dir.0.join("server.key");
        let lock = dir.0.join("server.key.koh-lock");
        let secret = generate_secret_key().unwrap();
        std::fs::write(&path, secret.to_bytes()).unwrap();
        std::fs::write(&lock, b"").unwrap();
        for file in [&path, &lock] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let identity = load(&KeyFile::open(&path).unwrap()).expect("a loose key still loads");
        assert_eq!(identity.endpoint_id(), secret.public());
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(mode_of(&lock), 0o600);
    }

    #[test]
    fn a_file_of_another_user_is_refused() {
        // Root owns /etc/passwd; to root, every file is its own, so there is nothing to test.
        if fuxix::process::geteuid() == 0 {
            return;
        }
        let path = Path::new("/etc/passwd");
        let file = File::open(path).unwrap();
        let error = check_private(&file, path).expect_err("a foreign file is refused");
        assert!(error.to_string().contains("owned by uid 0"), "{error}");
    }

    #[test]
    fn a_file_that_is_not_exactly_a_key_is_refused_with_the_reset_hint() {
        let dir = Scratch::new("notakey", 0o700);
        let path = dir.0.join("id.key");
        let key = KeyFile::open(&path).unwrap();
        let old_format = format!("koh-key-v1\n{}\n", "A".repeat(120));
        for contents in [
            Vec::new(),
            vec![7u8; KEY_LEN - 1],
            vec![7u8; KEY_LEN + 1],
            old_format.into_bytes(),
        ] {
            std::fs::write(&path, &contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let error = key.read_secret().expect_err("refused");
            assert!(matches!(error, SetupError::NotAKey(_)), "{error:?}");
            let message = error.to_string();
            assert!(message.contains("koh key reset"), "{message}");
            assert!(message.contains(&path.display().to_string()), "{message}");
            assert!(!message.contains("koh-key-v1"), "{message}");
        }
    }

    #[test]
    fn a_symlinked_log_is_refused_before_its_target_is_truncated() {
        let dir = Scratch::new("log", 0o700);
        let target = dir.0.join("victim");
        std::fs::write(&target, b"precious").unwrap();
        let link = dir.0.join("koh.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = open_private_log(&link).expect_err("a symlinked log is refused");
        assert!(error.to_string().contains("symlink"), "{error}");
        assert!(
            !error.to_string().contains("key"),
            "a log is not a key: {error}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"precious");

        let log = dir.0.join("real.log");
        std::fs::write(&log, b"old").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
        open_private_log(&log).expect("a real log opens");
        assert_eq!(std::fs::read(&log).unwrap(), b"", "truncated");
        assert_eq!(mode_of(&log), 0o600);
    }

    #[test]
    fn reset_removes_a_key_its_owner_cannot_read() {
        let dir = Scratch::new("unreadable", 0o700);
        let path = dir.0.join("id.key");
        let key = KeyFile::open(&path).unwrap();
        for mode in [0o000, 0o200] {
            std::fs::write(&path, [7u8; KEY_LEN]).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            key.reset()
                .unwrap_or_else(|error| panic!("mode {mode:o}: {error:#}"));
            assert!(!path.exists(), "mode {mode:o}: reset left the key");
        }
    }

    #[test]
    fn reset_refuses_a_fifo_without_waiting_for_a_writer() {
        let dir = Scratch::new("fifo", 0o700);
        let path = dir.0.join("id.key");
        let made = std::process::Command::new("mkfifo").arg(&path).status();
        if !made.is_ok_and(|status| status.success()) {
            return; // No mkfifo here, so nothing to test.
        }
        let key = KeyFile::open(&path).unwrap();
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || done.send(key.reset().is_err()));
        let refused = result
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("reset blocked on the FIFO");
        assert!(refused, "a FIFO is not a key");
        assert!(path.exists(), "the refused FIFO is left in place");
    }
}
