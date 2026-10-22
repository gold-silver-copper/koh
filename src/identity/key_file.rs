//! The one owner of trust in an identity path. A [`KeyFile`] can only be made by [`KeyFile::open`]
//! (or [`KeyFile::open_existing`], which creates nothing), which judges the key's directory once;
//! every file in it is opened without following a symlink and judged by [`check_private`], as
//! `$KOH_LOG` is. Its fields are private to this module, so the code that loads or resets a key
//! cannot reach the path to apply rules of its own.

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
    /// The key path to use: `path`, or else the default key path for `role` (`"client"` or
    /// `"server"`).
    pub fn path_for(path: Option<PathBuf>, role: &str) -> Result<PathBuf, SetupError> {
        path.map_or_else(|| crate::transport_iroh::default_key_path(role), Ok)
    }

    /// [`KeyFile::open`] at [`KeyFile::path_for`] `path` and `role`.
    pub fn locate(path: Option<PathBuf>, role: &str) -> anyhow::Result<Self> {
        Self::open(&Self::path_for(path, role)?)
    }

    /// Create the key's directory if it is missing (0700), then judge it: refused if another user
    /// could replace the key in it, warned about if it is merely loose.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let (name, parent) = split(path)?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        Self::judge(path, name, parent)
    }

    /// The key at `path` if there is a file there (even one that is not a key), judged as
    /// [`KeyFile::open`] judges it, or `None` if there is none. Creates nothing, not even the
    /// directory.
    pub fn open_existing(path: &Path) -> anyhow::Result<Option<Self>> {
        let (name, parent) = split(path)?;
        let key = match Self::judge(path, name, parent) {
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(None)
            }
            judged => judged?,
        };
        match std::fs::symlink_metadata(&key.path) {
            Ok(_) => Ok(Some(key)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Judge the existing directory `parent` by [`directory_refusal`], warning if it is loose.
    fn judge(path: &Path, name: &std::ffi::OsStr, parent: &Path) -> anyhow::Result<Self> {
        let parent = parent.canonicalize()?;
        let meta = std::fs::metadata(&parent)?;
        let mode = meta.permissions().mode();
        if let Some(why) = directory_refusal(meta.uid(), mode, fuxix::process::geteuid()) {
            return Err(refuse(&parent, &why).into());
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

    /// The key, or `None` if there is no file. A symlink (even a dangling one) is refused, never
    /// followed, and a file that is not exactly [`KEY_LEN`] bytes is not a key.
    pub(super) fn read_secret(&self) -> Result<Option<SecretKey>, SetupError> {
        use std::io::Read as _;
        let file = match open_private(OpenOptions::new().read(true), &self.path, IDENTITY) {
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
        let secret = crate::transport_iroh::generate_secret_key()?;
        // Held until this returns: creators take turns, so only the first finds the key absent,
        // and a reader sees no key or a whole one.
        let _locked = self.lock_dir()?;
        match std::fs::symlink_metadata(&self.path) {
            Ok(_) => return self.read_secret(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        publish(&self.path, &secret.to_bytes())?;
        Ok(Some(secret))
    }

    /// The file `name` in the key's directory (a list of names, say), read as the key is: never
    /// through a symlink, a regular file of this user's, a loose mode tightened. `None` if there is
    /// none; refused past [`BESIDE_LIMIT`] bytes or if it is not UTF-8.
    pub(crate) fn read_beside(&self, name: &str) -> Result<Option<String>, SetupError> {
        use std::io::Read as _;
        let path = self.beside(name)?;
        let file = match open_private(OpenOptions::new().read(true), &path, BESIDE) {
            Ok(file) => file,
            Err(SetupError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        let limit = u64::try_from(BESIDE_LIMIT.saturating_add(1)).unwrap_or(u64::MAX);
        file.take(limit).read_to_end(&mut bytes)?;
        if bytes.len() > BESIDE_LIMIT {
            return Err(refuse(&path, "it is larger than koh writes"));
        }
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_not_utf8| refuse(&path, "it is not UTF-8 text"))
    }

    /// Replace the file `name` beside the key with what `update` makes of its contents (`None` if
    /// there is none); `update` returning `None` leaves it as it is. The directory is locked
    /// throughout, so two writers take turns and neither loses the other's change, and the new
    /// contents are published as a key is, so a reader sees the old file or the new one whole.
    pub(crate) fn update_beside(
        &self,
        name: &str,
        update: impl FnOnce(Option<String>) -> anyhow::Result<Option<String>>,
    ) -> anyhow::Result<()> {
        let _locked = self.lock_dir()?;
        if let Some(contents) = update(self.read_beside(name)?)? {
            publish(&self.beside(name)?, contents.as_bytes())?;
        }
        Ok(())
    }

    /// The directory's lock, held until dropped: a private file in it, which no other user can
    /// open, and so hold to hang koh, as they could the directory itself.
    fn lock_dir(&self) -> Result<File, SetupError> {
        let lock = open_private(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600),
            &self.dir.join(".koh-dir-lock"),
            BESIDE,
        )?;
        lock.lock()?;
        Ok(lock)
    }

    /// `name`'s path in the key's directory: a plain file name, never a path.
    fn beside(&self, name: &str) -> Result<PathBuf, SetupError> {
        let plain = !name.is_empty()
            && name != "."
            && name != ".."
            && !name.contains(std::path::is_separator);
        if !plain {
            return Err(refuse(Path::new(name), "it is not a plain file name"));
        }
        Ok(self.dir.join(name))
    }

    /// Remove the key, whatever it holds, refusing only what every load refuses (a symlink, a file
    /// that is not regular, or another user's file). The file is never opened, so a key the user cannot read
    /// can still be reset, and a FIFO at the path is refused rather than waited on. The check and
    /// the unlink are two steps, but only users [`KeyFile::open`] trusted can write the directory,
    /// and an unlink never follows a link.
    pub fn reset(&self) -> anyhow::Result<()> {
        let context = || format!("removing identity at {self}");
        let meta = std::fs::symlink_metadata(&self.path).with_context(context)?;
        check_owned(&meta, &self.path, IDENTITY).with_context(context)?;
        std::fs::remove_file(&self.path).with_context(context)
    }
}

/// Most bytes a file beside the key ([`KeyFile::read_beside`]) may hold: far more than any list of
/// names koh writes.
pub const BESIDE_LIMIT: usize = 1024 * 1024;

/// Write `bytes` to `target` as a key is created: to a born-private (0600) temporary file beside
/// it, synced, then renamed into place, so a reader sees no file or a whole one. The caller holds
/// the directory's lock.
fn publish(target: &Path, bytes: &[u8]) -> Result<(), SetupError> {
    use std::io::Write as _;
    let (tmp, mut file) = loop {
        let tmp = target.with_extension(format!(
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
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, target)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    Ok(result?)
}

/// Open `$KOH_LOG` as a private file: never through a symlink, never a FIFO or device (which could
/// block the open), and only truncated once it passes the same check as a key, as debug logs can be
/// sensitive.
pub fn open_private_log(path: &Path) -> Result<File, SetupError> {
    let file = open_private(
        OpenOptions::new().write(true).create(true).mode(0o600),
        path,
        LOG,
    )?;
    file.set_len(0)?;
    Ok(file)
}

/// The error for a symlink, FIFO or device where a regular file, `what`, was expected.
fn not_regular(path: &Path, what: &str) -> SetupError {
    tracing::warn!(path = %path.display(), "refusing a {what} that is a symlink or not a regular file");
    refuse(path, "it is a symlink or not a regular file")
}

/// What each private file is, for its errors and warnings.
const IDENTITY: &str = "identity file";
const LOG: &str = "log file";
/// A file beside the key: the names of servers or clients, or the directory's lock.
const BESIDE: &str = "koh file";

/// Open `path` with `options` and no symlink followed, then [`check_private`] it. Anything but a
/// regular file is refused before the open, so a FIFO cannot block it.
fn open_private(options: &mut OpenOptions, path: &Path, what: &str) -> Result<File, SetupError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() => return Err(not_regular(path, what)),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let file = match options.custom_flags(fuxix::file::NOFOLLOW).open(path) {
        Ok(file) => file,
        // The open refused a symlink (ELOOP) planted since; asking afterwards only names the
        // refusal.
        Err(_) if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) => {
            return Err(not_regular(path, what));
        }
        Err(error) => return Err(error.into()),
    };
    check_private(&file, path, what)?;
    Ok(file)
}

/// The one rule for a private file: a regular file of this user's, under this one name (a hard
/// link is another way in, and a truncation through it would reach this file), readable by no one
/// else. A loose mode, say from a permissive backup, is tightened to 0600 through the descriptor; a file
/// that cannot be tightened, or that stays loose (a filesystem that ignores chmod), is refused.
fn check_private(file: &File, path: &Path, what: &str) -> Result<(), SetupError> {
    let meta = file.metadata()?;
    check_owned(&meta, path, what)?;
    if meta.nlink() != 1 {
        return Err(refuse(
            path,
            &format!(
                "it has {} hard links, so another name reaches it",
                meta.nlink()
            ),
        ));
    }
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
        let now = file.metadata()?.permissions().mode();
        if now & 0o077 != 0 {
            return Err(refuse(
                path,
                &format!(
                    "mode {:o} is group/other-accessible and stayed so after a chmod to 600 (does \
                     its filesystem ignore modes?); move it to one that keeps them",
                    now & 0o777
                ),
            ));
        }
        tracing::warn!(
            path = %path.display(),
            prev_mode = format!("{:o}", mode & 0o777),
            "{what} was group/other-accessible; tightened to 0600 (via fd)"
        );
    }
    Ok(())
}

/// The part of [`check_private`] a reset also applies: a regular file (not a symlink, FIFO or
/// device) owned by this user.
fn check_owned(meta: &std::fs::Metadata, path: &Path, what: &str) -> Result<(), SetupError> {
    if !meta.is_file() {
        return Err(not_regular(path, what));
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

/// Why a key directory with `owner` and `mode` is unsafe for `euid`, if it is. Its owner, if not
/// this user or root, could replace the key (as OpenSSH's `StrictModes` reasons); so could anyone,
/// if it is other-writable without the sticky bit (which limits unlink to owners, as in /tmp's
/// 1777). Group-writable is allowed: Android's /data/local/tmp is 0771, owned by the shell uid
/// that runs koh there, and a single-user device has no co-tenant.
fn directory_refusal(owner: u32, mode: u32, euid: u32) -> Option<String> {
    if owner != euid && owner != 0 {
        return Some(format!(
            "the key's directory is owned by uid {owner}, not by uid {euid} or root, so its owner \
             could replace the key; pass --key-file pointing at a directory of your own"
        ));
    }
    (mode & 0o002 != 0 && mode & 0o1000 == 0).then(|| {
        format!(
            "the key's directory is world-writable without the sticky bit (mode {:o}), so any \
             user could replace the key; chmod 700 it, add the sticky bit, or pass --key-file \
             pointing at a private path",
            mode & 0o7777
        )
    })
}

/// A key path's file name and its directory, `.` for a bare name.
fn split(path: &Path) -> anyhow::Result<(&std::ffi::OsStr, &Path)> {
    let name = path.file_name().context("identity path has no filename")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok((name, parent))
}

fn refuse(path: &Path, why: &str) -> SetupError {
    SetupError::Refused {
        path: path.display().to_string(),
        why: why.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{load, load_existing};

    /// A fresh directory with `mode`, removed on drop.
    fn scratch(name: &str, mode: u32) -> koh_testkit::Scratch {
        let dir = crate::test_runtime::scratch(name);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        dir
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    fn write(path: &Path, bytes: &[u8], mode: u32) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_key_is_created_private_as_its_raw_bytes_and_loads_back() {
        let dir = scratch("key-create", 0o700);
        let path = dir.join("state").join("id.key");
        assert!(load_existing(&path).unwrap().is_none());
        assert!(!dir.join("state").exists(), "load_existing created nothing");
        let key = KeyFile::open(&path).unwrap();
        // A temporary name planted where a creator might pick it blocks nothing.
        let planted = path.with_extension(format!("tmp.{}.1", std::process::id()));
        std::fs::write(&planted, b"attacker-owned").unwrap();
        let first = load(&key).expect("create a key");
        assert_eq!(std::fs::read(&path).unwrap(), first.to_bytes());
        assert_eq!(std::fs::read(&planted).unwrap(), b"attacker-owned");
        assert_eq!(
            (mode_of(&dir.join("state")), mode_of(&path)),
            (0o700, 0o600)
        );
        // A loose key still loads, tightened through its descriptor.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let again = load_existing(&path).unwrap().expect("there now");
        assert_eq!(again.public(), first.public());
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn only_a_directory_another_user_could_replace_the_key_in_is_refused() {
        // Group-writable (Android's /data/local/tmp is 0771) and sticky world-writable (/tmp's
        // 1777) are allowed, else koh can't start in those standard locations.
        let dir = scratch("ww", 0o777);
        let path = dir.join("id.key");
        assert!(KeyFile::open(&path).is_err(), "0777 is refused");
        for mode in [0o700, 0o755, 0o771, 0o1777] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(KeyFile::open(&path).is_ok(), "{mode:o} is allowed");
        }
        let euid = 1000;
        for (owner, mode, refused) in [
            (euid, 0o700, false),
            (0, 0o755, false),
            (0, 0o1777, false),
            (0, 0o777, true),
            (1001, 0o700, true),
        ] {
            let refusal = directory_refusal(owner, mode, euid);
            assert_eq!(refusal.is_some(), refused, "{owner} {mode:o}");
        }
        // A real root-owned directory: judged, with nothing created there.
        KeyFile::open(Path::new("/koh-no-such.key")).expect("/ is root's");
        assert!(!Path::new("/koh-no-such.key").exists());
    }

    #[test]
    fn symlinks_and_hard_links_are_refused_and_what_they_reach_left_alone() {
        let dir = scratch("links", 0o700);
        let target = dir.join("victim");
        write(&target, &[7u8; KEY_LEN], 0o644);
        let link = dir.join("server.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let key = KeyFile::open(&link).unwrap();
        assert!(matches!(key.read_secret(), Err(SetupError::Refused { .. })));
        assert!(load(&key).is_err() && key.reset().is_err());
        let log_link = dir.join("koh.log");
        std::os::unix::fs::symlink(&target, &log_link).unwrap();
        let log = open_private_log(&log_link).expect_err("a symlinked log is refused");
        assert!(
            log.to_string().contains("symlink") && !log.to_string().contains("key"),
            "{log}"
        );
        assert_eq!(mode_of(&target), 0o644, "the target is not re-permissioned");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            [7u8; KEY_LEN],
            "nor truncated"
        );
        // A dangling one is refused, not taken for no key.
        let dangling = dir.join("client.key");
        std::os::unix::fs::symlink(dir.join("missing"), &dangling).unwrap();
        let key = KeyFile::open(&dangling).unwrap();
        for error in [load(&key).err(), load_existing(&dangling).err()] {
            let error = error.expect("refused");
            assert!(
                matches!(error.downcast_ref(), Some(SetupError::Refused { .. })),
                "{error:#}"
            );
        }
        assert!(!dir.join("missing").exists(), "nothing was created");
        // `$KOH_LOG` pointed at a key by another name: truncating it would destroy the key.
        let path = dir.join("id.key");
        let key = KeyFile::open(&path).unwrap();
        let secret = load(&key).unwrap().to_bytes();
        std::fs::hard_link(&path, dir.join("linked.log")).unwrap();
        assert!(open_private_log(&dir.join("linked.log")).is_err());
        assert!(load(&key).is_err(), "nor is the key itself used");
        assert_eq!(std::fs::read(&path).unwrap(), secret);
        // A real log opens, emptied and tightened.
        let real = dir.join("real.log");
        write(&real, b"old", 0o644);
        open_private_log(&real).expect("a real log opens");
        assert_eq!(std::fs::read(&real).unwrap(), b"");
        assert_eq!(mode_of(&real), 0o600);
    }

    #[test]
    fn a_fifo_log_or_key_is_refused_without_waiting_for_a_reader() {
        let dir = scratch("fifo-log", 0o700);
        let path = dir.join("koh.log");
        let made = koh_testkit::command("mkfifo", &dir)
            .unwrap()
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success(), "mkfifo: {made}");
        let key = KeyFile::open(&path).unwrap();
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let log = open_private_log(&path).map(drop);
            let load = load(&key).map(drop);
            done.send((log, load, key.reset().is_err(), path.exists()))
        });
        let (log, load, reset_refused, left) = result
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the open blocked on the FIFO");
        assert!(
            reset_refused && left,
            "a reset refuses it and leaves it in place"
        );
        let log = log.expect_err("a FIFO log is refused");
        assert!(log.to_string().starts_with("refusing "), "{log}");
        let load = load.expect_err("a FIFO key is refused");
        assert!(
            matches!(load.downcast_ref(), Some(SetupError::Refused { .. })),
            "{load:#}"
        );
    }

    /// A file `load` refuses as no key says to reset it, and the reset then works, even on a key
    /// its owner cannot read, in a loose (0755) directory `load` only warns about.
    #[test]
    fn a_file_that_is_not_a_key_says_to_reset_and_reset_removes_it() {
        let dir = scratch("notakey", 0o755);
        let path = dir.join("id.key");
        let key = KeyFile::open(&path).unwrap();
        let old_format = format!("koh-key-v1\n{}\n", "A".repeat(120));
        for contents in [
            Vec::new(),
            vec![7u8; KEY_LEN - 1],
            vec![7u8; KEY_LEN + 1],
            old_format.into_bytes(),
        ] {
            write(&path, &contents, 0o600);
            let error = key.read_secret().expect_err("refused");
            assert!(matches!(error, SetupError::NotAKey(_)), "{error:?}");
            let message = error.to_string();
            assert!(message.contains("koh key reset"), "{message}");
            assert!(message.contains(&path.display().to_string()), "{message}");
            assert!(!message.contains("koh-key-v1"), "{message}");
            key.reset().unwrap();
            assert!(!path.exists(), "reset left the file");
        }
        for mode in [0o000, 0o200, 0o600] {
            write(&path, &[7u8; KEY_LEN], mode);
            key.reset()
                .unwrap_or_else(|error| panic!("mode {mode:o}: {error:#}"));
            assert!(!path.exists(), "mode {mode:o}: reset left the key");
        }
    }

    #[test]
    fn a_file_of_another_user_is_refused() {
        // A file of root's, read as another user; to root, every file is its own.
        let path = Path::new("/etc/passwd");
        let Ok(file) = File::open(path) else {
            return;
        };
        let owner = file.metadata().map(|meta| meta.uid());
        if owner.ok() != Some(0) || fuxix::process::geteuid() == 0 {
            return;
        }
        let error = check_private(&file, path, IDENTITY).expect_err("a foreign file is refused");
        assert_eq!(
            error.to_string(),
            format!(
                "refusing /etc/passwd: it is owned by uid 0, not by uid {}",
                fuxix::process::geteuid()
            )
        );
    }
}
