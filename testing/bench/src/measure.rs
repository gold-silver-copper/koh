//! The network measures: bytes on the wire for a workload, and keystroke-to-paint latency beside
//! a flood.

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use tokio::time::Instant;

use crate::proxy::{Count, Counts, Profile};
use crate::remote::{Remote, Setup, System};
use crate::workloads::{logged, Workload};

/// How long the link must carry nothing for a step to count as done.
const QUIET: Duration = Duration::from_millis(300);

/// The longest a step may take.
const STEP: Duration = Duration::from_secs(60);

/// What a workload cost on the wire, beyond the connection's setup.
#[derive(Clone, Copy, Debug, Default)]
pub struct Wire {
    pub counts: Counts,
    /// The bytes the client wrote to the user's terminal.
    pub written: u64,
    /// How many times koh's client painted, and over how long.
    pub paints: u64,
    pub seconds: f64,
}

fn minus(a: Count, b: Count) -> Count {
    Count {
        packets: a.packets.saturating_sub(b.packets),
        bytes: a.bytes.saturating_sub(b.bytes),
    }
}

/// Play `workload` through `system` on a clean link, step by step, and count what crossed it.
pub async fn wire(
    system: System,
    setup: &Setup,
    workload: &Workload,
    dir: &Path,
    seed: u64,
) -> anyhow::Result<Wire> {
    let script = workload.script(dir)?;
    let program = vec!["sh".to_owned(), script.display().to_string()];
    let remote = Remote::connect(
        system,
        setup,
        &program,
        (workload.rows, workload.cols),
        Profile::default(),
        seed,
    )
    .await
    .with_context(|| format!("{} connecting", system.name()))?;
    let result = play(&remote, workload, dir).await;
    remote.stop().await;
    result
}

async fn play(remote: &Remote, workload: &Workload, dir: &Path) -> anyhow::Result<Wire> {
    // The connection's setup, done.
    remote
        .quiet(Duration::from_millis(500), Duration::from_secs(20))
        .await;
    let before = remote.counts();
    let written_before = remote
        .shown
        .written
        .load(std::sync::atomic::Ordering::Relaxed);
    let paints_before = *remote.shown.paints.borrow();
    let start = Instant::now();
    for (index, step) in workload.steps.iter().enumerate() {
        let gated = workload.every.is_none() || index == 0;
        if !gated {
            break;
        }
        if let Some((rows, cols)) = step.resize {
            remote.resize(rows, cols).await?;
        }
        remote.send(&[0x01]).await?;
        let written = format!("{index} written");
        let deadline = Instant::now()
            .checked_add(STEP)
            .ok_or_else(|| anyhow!("no deadline"))?;
        while !logged(dir, &written) {
            anyhow::ensure!(
                Instant::now() < deadline,
                "{}: {} step {index} never written",
                remote.system.name(),
                workload.name
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        if workload.every.is_none() {
            remote.quiet(QUIET, STEP).await;
        }
    }
    if workload.every.is_some() {
        let deadline = Instant::now()
            .checked_add(STEP)
            .ok_or_else(|| anyhow!("no deadline"))?;
        while !logged(dir, "done") {
            anyhow::ensure!(Instant::now() < deadline, "{} never done", workload.name);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        remote.quiet(QUIET, STEP).await;
    }
    let after = remote.counts();
    Ok(Wire {
        counts: Counts {
            to_server: minus(after.to_server, before.to_server),
            to_client: minus(after.to_client, before.to_client),
        },
        written: remote
            .shown
            .written
            .load(std::sync::atomic::Ordering::Relaxed)
            .saturating_sub(written_before),
        paints: remote.shown.paints.borrow().saturating_sub(paints_before),
        seconds: start.elapsed().as_secs_f64(),
    })
}

/// The program for the latency measure: a flood written to the top row as fast as `awk` can,
/// its cursor saved and restored around each write, beside `cat` echoing what is typed below.
const FLOOD: &str = "stty raw -echo\n\
printf '\\033[2J\\033[H\\r\\n'\n\
awk 'BEGIN { for (i = 0; ; i++) { printf \"\\0337\\033[1;1H%012d flood flood flood flood\\0338\", i; fflush() } }' &\n\
exec cat\n";

/// Keystroke latencies: how long each typed key took to show, and for koh how long to show on
/// the screen the server sent (its echo, without prediction).
#[derive(Clone, Debug, Default)]
pub struct Latency {
    pub shown: Vec<Duration>,
    pub echoed: Vec<Duration>,
    pub missed: usize,
}

/// The `x`s below the top row of `screen`.
fn typed(screen: &fux_vt::Screen) -> usize {
    let (rows, cols) = screen.size();
    (1..rows)
        .flat_map(|row| (0..cols).map(move |col| (row, col)))
        .filter(|&(row, col)| screen.cell(row, col).is_some_and(|c| c.contents() == "x"))
        .count()
}

/// The `x`s below the top row of koh's synced screen.
fn typed_synced(remote: &Remote) -> usize {
    remote.synced.as_ref().map_or(0, |synced| {
        synced
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map_or(0, |state| {
                let grid = state.screen();
                let size = state.size();
                (1..size.rows)
                    .flat_map(|row| (0..size.cols).map(move |col| (row, col)))
                    .filter(|&(row, col)| grid.cell(row, col).is_some_and(|c| c.contents() == "x"))
                    .count()
            })
    })
}

/// Type `samples` keys through `system` over `profile` while the program floods the screen.
pub async fn latency(
    system: System,
    setup: &Setup,
    profile: Profile,
    samples: usize,
    dir: &Path,
    seed: u64,
) -> anyhow::Result<Latency> {
    std::fs::create_dir_all(dir)?;
    let script = dir.join("flood.sh");
    std::fs::write(&script, FLOOD)?;
    let program = vec!["sh".to_owned(), script.display().to_string()];
    let remote = Remote::connect(system, setup, &program, (40, 120), profile, seed).await?;
    let result = keys(&remote, samples).await;
    remote.stop().await;
    result
}

async fn keys(remote: &Remote, samples: usize) -> anyhow::Result<Latency> {
    let mut paints = remote.shown.paints.clone();
    let started = Instant::now();
    while !remote
        .shown
        .with(|s| s.cell(0, 13).is_some_and(|c| c.contents() == "f"))
    {
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(30),
            "{}: the flood never showed",
            remote.system.name()
        );
        let _ = tokio::time::timeout(Duration::from_millis(100), paints.changed()).await;
    }
    let mut latency = Latency::default();
    let mut rng = seed_rng(samples);
    for k in 1..=samples {
        let sent = Instant::now();
        remote.send(b"x").await?;
        let mut shown = None;
        let mut echoed = None;
        while sent.elapsed() < Duration::from_secs(10) {
            if shown.is_none() && remote.shown.with(typed) >= k {
                shown = Some(sent.elapsed());
            }
            if echoed.is_none() && remote.synced.is_some() && typed_synced(remote) >= k {
                echoed = Some(sent.elapsed());
            }
            if shown.is_some() && (echoed.is_some() || remote.synced.is_none()) {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(5), paints.changed()).await;
        }
        match shown {
            Some(d) => latency.shown.push(d),
            None => latency.missed = latency.missed.saturating_add(1),
        }
        if let Some(d) = echoed {
            latency.echoed.push(d);
        }
        // Keys a typist's distance apart, not in a burst.
        tokio::time::sleep(Duration::from_millis(
            150u64.saturating_add(next(&mut rng).checked_rem(100).unwrap_or(0)),
        ))
        .await;
    }
    Ok(latency)
}

fn seed_rng(seed: usize) -> u64 {
    u64::try_from(seed).unwrap_or(0)
}

fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The `percent`-th percentile of `values`, by nearest rank.
pub fn percentile(values: &[Duration], percent: usize) -> Option<Duration> {
    let mut sorted = values.to_vec();
    sorted.sort();
    let rank = percent
        .saturating_mul(sorted.len())
        .saturating_add(99)
        .checked_div(100)?;
    sorted.get(rank.saturating_sub(1)).copied()
}

/// An action whose time until the screen settles is measured: the program it runs in, and what
/// the user does, again and again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    PageDown,
    Search,
    Split,
    Listing,
    Resize,
    QuietKey,
}

impl Action {
    pub const ALL: [Self; 6] = [
        Self::QuietKey,
        Self::PageDown,
        Self::Search,
        Self::Split,
        Self::Listing,
        Self::Resize,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::PageDown => "nvim, page down",
            Self::Search => "nvim, a search jump",
            Self::Split => "nvim, a split opened or closed",
            Self::Listing => "ls -l of 2,000 files",
            Self::Resize => "nvim, a resize",
            Self::QuietKey => "a key typed into a quiet cat",
        }
    }

    pub const fn key(self) -> &'static str {
        match self {
            Self::PageDown => "page-down",
            Self::Search => "search",
            Self::Split => "split",
            Self::Listing => "listing",
            Self::Resize => "resize",
            Self::QuietKey => "quiet-key",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.key() == key)
    }
}

/// How long the screen must not change to count as settled.
const SETTLED: Duration = Duration::from_millis(500);

/// A digest of what `screen` shows: every cell's text and attributes, and the cursor.
fn digest(screen: &fux_vt::Screen) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let (rows, cols) = screen.size();
    for row in 0..rows {
        for col in 0..cols {
            if let Some(cell) = screen.cell(row, col) {
                cell.contents().hash(&mut hasher);
                format!("{:?}", cell.attributes()).hash(&mut hasher);
            }
        }
    }
    screen.cursor_position().hash(&mut hasher);
    hasher.finish()
}

/// Wait until what `remote` shows has not changed for [`SETTLED`], up to `cap`; when it last
/// changed, if it settled.
async fn settled(remote: &Remote, cap: Duration) -> Option<Instant> {
    let mut paints = remote.shown.paints.clone();
    let start = Instant::now();
    let mut last = remote.shown.with(digest);
    let mut changed = start;
    while start.elapsed() < cap {
        let wait = SETTLED.saturating_sub(changed.elapsed());
        if wait.is_zero() {
            return Some(changed);
        }
        let _ = tokio::time::timeout(wait, paints.changed()).await;
        let now = remote.shown.with(digest);
        if now != last {
            last = now;
            changed = Instant::now();
        }
    }
    None
}

/// The time until the screen settles after `action`, `repeats` times, through `system` over
/// `profile`. Only the repeats whose screen changed are counted: the first change starts it.
pub async fn settle(
    system: System,
    setup: &Setup,
    profile: Profile,
    action: Action,
    repeats: usize,
    dir: &Path,
    seed: u64,
) -> anyhow::Result<Vec<Duration>> {
    std::fs::create_dir_all(dir)?;
    // A source file of koh's for nvim, and a directory of 2,000 files for ls.
    let text = dir.join("text.rs");
    let source = include_str!("../../../src/client/render.rs");
    std::fs::write(&text, source.repeat(3))?;
    let files = dir.join("files");
    if action == Action::Listing && !files.exists() {
        std::fs::create_dir_all(&files)?;
        for i in 0..2000 {
            std::fs::write(files.join(format!("file-{i:04}.txt")), b"")?;
        }
    }
    let nvim = || {
        vec![
            "nvim".to_owned(),
            "--clean".to_owned(),
            "-n".to_owned(),
            text.display().to_string(),
        ]
    };
    let program = match action {
        Action::PageDown | Action::Search | Action::Split | Action::Resize => nvim(),
        Action::Listing => vec!["sh".to_owned()],
        Action::QuietKey => vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "stty raw -echo; exec cat".to_owned(),
        ],
    };
    let remote = Remote::connect(system, setup, &program, (40, 120), profile, seed).await?;
    let result = repeat(&remote, action, repeats, &files).await;
    remote.stop().await;
    result
}

async fn repeat(
    remote: &Remote,
    action: Action,
    repeats: usize,
    files: &Path,
) -> anyhow::Result<Vec<Duration>> {
    let cap = Duration::from_secs(20);
    // The program started and drew its first screen.
    tokio::time::sleep(Duration::from_millis(500)).await;
    settled(remote, cap)
        .await
        .ok_or_else(|| anyhow!("{}: the first screen never settled", remote.system.name()))?;
    let mut times = Vec::new();
    for i in 0..repeats {
        let before = remote.shown.with(digest);
        let sent = Instant::now();
        match action {
            Action::PageDown => remote.send(b"\x06").await?,
            Action::Search => remote.send(b"/fn \r").await?,
            Action::Split => {
                remote
                    .send(if i % 2 == 0 {
                        b":vsplit\r"
                    } else {
                        b":close\r"
                    })
                    .await?;
            }
            Action::Listing => {
                let line = format!("clear; ls -l {}\r", files.display());
                remote.send(line.as_bytes()).await?;
            }
            Action::Resize => {
                let (rows, cols) = if i % 2 == 0 { (30, 100) } else { (40, 120) };
                remote.resize(rows, cols).await?;
            }
            Action::QuietKey => remote.send(b"x").await?,
        }
        if let Some(changed) = settled(remote, cap).await {
            if remote.shown.with(digest) != before {
                times.push(changed.saturating_duration_since(sent));
            }
        }
    }
    Ok(times)
}
