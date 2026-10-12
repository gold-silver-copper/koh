//! What koh's tests share, and the one place they may do what `clippy.toml` bans.
//!
//! Every koh test crate starts with `#![forbid(clippy::disallowed_methods)]`, so no file can lift
//! the bans on starting a program, spawning a task or writing to the system temp dir. A test does
//! those here: it starts programs through [`command`], whose list never holds one that
//! authenticates; it spawns tasks through [`spawn`], on a runtime from [`current_thread`] or
//! [`multi_thread`]; and it writes files in a [`Scratch`] directory under `target/`.

use std::ffi::OsStr;
use std::future::Future;
use std::io;
use std::ops::Deref;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;

/// The programs besides koh a test may start.
const HARMLESS: &[&str] = &["nvim"];

/// A command for `program`: the `koh` binary (by path, the file named `koh`) or a program of
/// [`HARMLESS`]. Anything else is refused: never a program that authenticates, as `sudo` or
/// `passwd` do, since a test that typed a wrong password into one would be a failed login on the
/// machine running the tests.
///
/// # Errors
///
/// `PermissionDenied` for a program off the list.
pub fn command(program: impl AsRef<OsStr>) -> io::Result<Command> {
    let program = program.as_ref();
    let name = Path::new(program).file_name().and_then(OsStr::to_str);
    if name == Some("koh") || name.is_some_and(|name| HARMLESS.contains(&name)) {
        #[expect(
            clippy::disallowed_methods,
            reason = "the tests' one way to start a program"
        )]
        Ok(Command::new(program))
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "tests may not run {}: only koh and {HARMLESS:?}",
                program.display()
            ),
        ))
    }
}

/// Run `future` as a task on the test's runtime, which ends it with the test.
pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    #[expect(
        clippy::disallowed_methods,
        reason = "a test's tasks end with its runtime"
    )]
    tokio::spawn(future)
}

/// A single-threaded runtime, so a test's tasks interleave the same way every run.
/// `#[tokio::test]` is not used: its expansion `allow`s `clippy::expect_used`, which koh forbids,
/// and a `forbid` rejects that `allow`.
///
/// # Errors
///
/// When the runtime cannot be built.
pub fn current_thread() -> io::Result<Runtime> {
    Builder::new_current_thread().enable_all().build()
}

/// A runtime with `workers` threads.
///
/// # Errors
///
/// When the runtime cannot be built.
pub fn multi_thread(workers: usize) -> io::Result<Runtime> {
    Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
}

/// A private (0700) directory of a test's own, removed when dropped, on a panic too. Never in the
/// system temp dir: integration tests make theirs with [`scratch!`], under `CARGO_TARGET_TMPDIR`.
pub struct Scratch(PathBuf);

impl Scratch {
    /// A new directory `koh-<name>-…` under `root`, which is created if missing.
    ///
    /// # Errors
    ///
    /// When the directory cannot be created.
    pub fn new(root: impl AsRef<Path>, name: &str) -> io::Result<Self> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = root.as_ref();
        std::fs::create_dir_all(root)?;
        let dir = root.join(format!(
            "koh-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        // A crashed run with the same pid may have left one behind.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(Self(dir))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A [`Scratch`] directory under the integration test's `CARGO_TARGET_TMPDIR`.
#[macro_export]
macro_rules! scratch {
    ($name:expr) => {
        $crate::Scratch::new(env!("CARGO_TARGET_TMPDIR"), $name)
    };
}

/// Everything a PTY's output channel delivers, gathered by a task, to wait on.
#[derive(Clone)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    pub fn new(mut output: Receiver<Vec<u8>>) -> Self {
        let all = Arc::new(Mutex::new(Vec::new()));
        let sink = all.clone();
        spawn(async move {
            while let Some(chunk) = output.recv().await {
                let Ok(mut all) = sink.lock() else { break };
                all.extend_from_slice(&chunk);
            }
        });
        Self(all)
    }

    /// The captured text from byte `from` on.
    pub fn text_from(&self, from: usize) -> String {
        self.0.lock().map_or_else(
            |_| String::new(),
            |all| String::from_utf8_lossy(all.get(from..).unwrap_or_default()).into_owned(),
        )
    }

    /// Wait up to `secs` for `needle` after byte `from`: the byte after the match.
    ///
    /// # Errors
    ///
    /// What was captured, if `needle` never came.
    pub async fn wait_for(&self, from: usize, needle: &str, secs: u64) -> Result<usize, String> {
        for _ in 0..secs.saturating_mul(10) {
            if let Some(at) = self.text_from(from).find(needle) {
                return Ok(from.saturating_add(at).saturating_add(needle.len()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(format!(
            "never saw {needle:?}; captured:\n{}",
            self.text_from(0)
        ))
    }
}

impl Capture {
    /// Type with `write` every second until `needle` shows after byte `from`, for up to `secs`:
    /// the byte after the match. Keys typed before a session is up are dropped, so this is how a
    /// test waits for one, instead of sleeping; `needle` must be what only the session prints.
    ///
    /// # Errors
    ///
    /// What was captured, if `needle` never came.
    pub async fn type_until(
        &self,
        from: usize,
        needle: &str,
        secs: u64,
        mut write: impl FnMut(),
    ) -> Result<usize, String> {
        for _ in 0..secs {
            write();
            if let Ok(at) = self.wait_for(from, needle, 1).await {
                return Ok(at);
            }
        }
        self.wait_for(from, needle, 0).await
    }
}

/// Read `output` until what it delivered holds `marker`, for up to 20 s: everything read.
///
/// # Errors
///
/// What was read, if the channel closed or the time ran out first.
pub async fn read_until(output: &mut Receiver<Vec<u8>>, marker: &str) -> Result<String, String> {
    let mut read = String::new();
    let found = tokio::time::timeout(Duration::from_secs(20), async {
        while !read.contains(marker) {
            let Some(chunk) = output.recv().await else {
                return false;
            };
            read.push_str(&String::from_utf8_lossy(&chunk));
        }
        true
    })
    .await;
    if found == Ok(true) {
        Ok(read)
    } else {
        Err(format!("never read {marker:?}; read:\n{read}"))
    }
}

/// The lines `child` writes to its piped stderr, read to the end by a thread of their own, so it
/// never blocks on a full pipe.
pub fn stderr_lines(child: &mut Child) -> std::sync::mpsc::Receiver<String> {
    use std::io::BufRead as _;
    let (lines, received) = std::sync::mpsc::channel();
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            for line in io::BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = lines.send(line);
            }
        });
    }
    received
}

/// A seeded random sequence (splitmix64), so a failure names the seed that reproduces it.
#[derive(Default)]
pub struct Rng(pub u64);

impl Rng {
    pub fn u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)`, from the top 32 bits.
    pub fn unit(&mut self) -> f64 {
        f64::from(u32::try_from(self.u64() >> 32).unwrap_or(u32::MAX)) / 4_294_967_296.0
    }

    /// True with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }

    /// A number in `0..n` (0 when `n` is 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.u64().checked_rem(n).unwrap_or(0)
    }
}
