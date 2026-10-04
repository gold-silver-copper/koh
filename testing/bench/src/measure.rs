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
