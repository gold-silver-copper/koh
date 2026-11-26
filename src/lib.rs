//! koh: ultra-minimal peer-to-peer remote shell, headless jobs, delta sync,
//! and interactive fux sessions over iroh QUIC.
#![forbid(unsafe_code)]

pub mod client;
pub mod jobs;
pub mod keys;
pub mod net;
mod pane;
pub mod proto;
pub mod server;
mod session;
pub mod sync;

use std::fmt;

/// Strict CLI exit codes for scripts and agents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exit(pub u8);

impl Exit {
    pub const OK: Self = Self(0);
    pub const FAILED: Self = Self(1);
    pub const USAGE: Self = Self(2);
    pub const UNREACHABLE: Self = Self(3);
    pub const REFUSED: Self = Self(4);
    pub const BUSY: Self = Self(75);
    pub const TIMEOUT: Self = Self(124);
    pub const CANNOT_START: Self = Self(126);
    pub const NOT_FOUND: Self = Self(127);
    pub const INTERNAL: Self = Self(255);
}

/// Structured koh error carrying exit code and machine-readable kind for `--json`.
#[derive(Debug)]
pub struct KohError {
    pub code: Exit,
    pub kind: &'static str,
    pub message: String,
}

impl KohError {
    pub fn new(code: Exit, kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            kind,
            message: message.into(),
        }
    }

    pub fn usage(msg: impl Into<String>) -> Self {
        Self::new(Exit::USAGE, "usage", msg)
    }

    pub fn unreachable(msg: impl Into<String>) -> Self {
        Self::new(Exit::UNREACHABLE, "unreachable", msg)
    }

    pub fn refused(msg: impl Into<String>) -> Self {
        Self::new(Exit::REFUSED, "refused", msg)
    }

    pub fn failed(msg: impl Into<String>) -> Self {
        Self::new(Exit::FAILED, "failed", msg)
    }

    pub fn timeout(msg: impl Into<String>) -> Self {
        Self::new(Exit::TIMEOUT, "timeout", msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(Exit::INTERNAL, "internal", msg)
    }

    pub fn json_line(&self) -> String {
        serde_json::json!({
            "error": {
                "kind": self.kind,
                "message": self.message,
                "code": self.code.0,
            }
        })
        .to_string()
    }
}

impl fmt::Display for KohError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for KohError {}

impl From<anyhow::Error> for KohError {
    fn from(err: anyhow::Error) -> Self {
        match err.downcast::<KohError>() {
            Ok(ke) => ke,
            Err(err) => Self::internal(format!("{err:#}")),
        }
    }
}

pub type Result<T> = std::result::Result<T, KohError>;

/// The time `long` after `from`: what every limit somebody else chose is made with (a peer's
/// seconds, a flag's). One that is out of range means no limit, and is refused nowhere: more
/// than thirty years is thirty years, the timer's own "never", and a time the clock cannot
/// say (`Duration::MAX` is one) would panic where it is added. (And were the clock itself that
/// near its end, the time is `from`: a deadline that has come.)
pub(crate) fn after(from: tokio::time::Instant, long: std::time::Duration) -> tokio::time::Instant {
    const NEVER: std::time::Duration = std::time::Duration::from_secs(30 * 365 * 86_400);
    from.checked_add(long.min(NEVER)).unwrap_or(from)
}

/// A folder that goes, given another name beside where it was and removed when this is let go.
/// (A name of its own that begins with a dot: nothing lists it as a session, and a folder that
/// has the name already is not written over.) Giving it the name is one call however much the
/// folder holds, and is what is done under a lock; the removing is done after, with nothing held.
pub(crate) struct Aside(Option<std::path::PathBuf>);

impl Aside {
    /// `dir` put aside; `Ok(None)` if nothing was there, `Err(e)` if moving it aside failed.
    pub(crate) fn try_of(dir: &std::path::Path) -> std::io::Result<Option<Self>> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nth = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let aside = dir.with_file_name(format!(".gone.{}.{nth}", std::process::id()));
        match std::fs::rename(dir, &aside) {
            Ok(()) => Ok(Some(Self(Some(aside)))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `dir` put aside; `None` if it was not (nothing is there, as a rule), and then it is as it was.
    pub(crate) fn of(dir: &std::path::Path) -> Option<Self> {
        Self::try_of(dir).ok().flatten()
    }

    /// Puts the folder back at `dir`; if rename fails, disarms drop so it stays on disk and
    /// returns its retained path with the error.
    pub(crate) fn restore(
        mut self,
        dir: &std::path::Path,
    ) -> std::result::Result<(), (std::path::PathBuf, std::io::Error)> {
        if let Some(aside) = self.0.take()
            && let Err(e) = std::fs::rename(&aside, dir)
        {
            return Err((aside, e));
        }
        Ok(())
    }
}

impl Drop for Aside {
    fn drop(&mut self) {
        if let Some(aside) = &self.0 {
            let _ = std::fs::remove_dir_all(aside);
        }
    }
}

/// Valid single path component (no slashes, no `.` or `..`, printable ASCII/UTF-8 without controls).
pub fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Atomically writes `data` to `path` via a sibling `.new` temp file + rename.
pub fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = path.with_file_name(format!(".{name}.new"));
    std::fs::write(&tmp, data)?;
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aside_restore_failure_reports_retained_path_and_keeps_files() {
        let base = std::env::temp_dir().join(format!("koh-aside-{}", std::process::id()));
        let dir = base.join("keep");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&dir).ok();
        std::fs::write(dir.join("log"), b"saved").ok();
        let old = Aside::of(&dir);
        assert!(old.is_some());
        std::fs::create_dir_all(dir.join("blocker")).ok();
        let res = old.map(|a| a.restore(&dir));
        assert!(matches!(res, Some(Err(_))));
        if let Some(Err((kept, _))) = res {
            let text = fuxix::open_regular(kept.join("log")).and_then(std::io::read_to_string);
            assert_eq!(text.ok().as_deref(), Some("saved"));
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
