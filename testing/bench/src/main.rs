//! koh's scoreboard: koh beside mosh and plain ssh, on the corpus's recordings and on synthetic
//! workloads, by bytes on the wire, keystroke latency beside a flood, server memory per session,
//! and the instructions koh's server and client retire. `testing/scoreboard.sh` builds koh and
//! this, and runs it from the repository's root; see `testing/bench/README.md`.

mod children;
#[expect(
    dead_code,
    reason = "the scoreboard uses the fault link's counts, not its outages or its sent counts"
)]
#[path = "../../../tests/net/link.rs"]
mod link;
mod measure;
mod netns;
mod proxy;
#[expect(
    dead_code,
    reason = "the scoreboard measures, and has no use for the recordings the user's terminal is \
              known to show otherwise than the server"
)]
#[path = "../../corpus/recording.rs"]
mod recording;
mod remote;
mod scrollback;
mod workloads;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

use anyhow::anyhow;

use crate::measure::{percentile, Action, Latency, Wire};
use crate::proxy::Profile;
use crate::remote::{which, Setup, Sshd, System};
use crate::workloads::Workload;

/// What to run, from the command line.
struct Args {
    koh: PathBuf,
    out: PathBuf,
    recordings: Option<Vec<String>>,
    systems: Vec<System>,
    samples: usize,
    /// How many times latency and settling are measured; their medians and ranges are reported.
    runs: usize,
    /// How many times each action is repeated, a run.
    repeats: usize,
    wire: bool,
    latency: bool,
    settle: bool,
    memory: bool,
    instructions: bool,
}

const USAGE: &str = "koh-bench --koh BIN [--out FILE] [--recordings all|none|a,b] \
                     [--systems koh,mosh,ssh] [--samples N] [--runs N] [--repeats N] \
                     [--skip wire,latency,settle,memory,instructions]";

fn args() -> anyhow::Result<Args> {
    let mut args = Args {
        koh: PathBuf::from("target/release/koh"),
        out: PathBuf::from("docs/SCOREBOARD.md"),
        recordings: None,
        systems: vec![System::Koh, System::Mosh, System::Ssh],
        samples: 100,
        runs: 3,
        repeats: 5,
        wire: true,
        latency: true,
        settle: true,
        memory: true,
        instructions: true,
    };
    let mut words = std::env::args().skip(1);
    while let Some(word) = words.next() {
        let mut value = || {
            words
                .next()
                .ok_or_else(|| anyhow!("{word} needs a value\n{USAGE}"))
        };
        match word.as_str() {
            "--koh" => args.koh = PathBuf::from(value()?),
            "--out" => args.out = PathBuf::from(value()?),
            "--recordings" => {
                let v = value()?;
                args.recordings = match v.as_str() {
                    "all" => None,
                    "none" => Some(Vec::new()),
                    list => Some(list.split(',').map(str::to_owned).collect()),
                };
            }
            "--systems" => {
                args.systems = value()?
                    .split(',')
                    .map(|s| match s {
                        "koh" => Ok(System::Koh),
                        "mosh" => Ok(System::Mosh),
                        "ssh" => Ok(System::Ssh),
                        other => Err(anyhow!("no system {other}")),
                    })
                    .collect::<anyhow::Result<_>>()?;
            }
            "--samples" => args.samples = value()?.parse()?,
            "--runs" => args.runs = value()?.parse::<usize>()?.max(1),
            "--repeats" => args.repeats = value()?.parse::<usize>()?.max(1),
            "--skip" => {
                for skip in value()?.split(',') {
                    match skip {
                        "wire" => args.wire = false,
                        "latency" => args.latency = false,
                        "settle" => args.settle = false,
                        "memory" => args.memory = false,
                        "instructions" => args.instructions = false,
                        other => return Err(anyhow!("cannot skip {other}")),
                    }
                }
            }
            other => return Err(anyhow!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    Ok(args)
}

/// The output of `program args`, first line, or what went wrong.
fn first_line(program: &str, args: &[&str]) -> String {
    Command::new(program).args(args).output().map_or_else(
        |e| format!("unavailable ({e})"),
        |out| {
            let text = if out.stdout.is_empty() {
                out.stderr
            } else {
                out.stdout
            };
            String::from_utf8_lossy(&text)
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned()
        },
    )
}

fn load() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|l| l.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

/// The machine, the commit and the tools, for the scoreboard's head.
fn machine() -> String {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|c| {
            c.lines()
                .find_map(|l| l.strip_prefix("model name"))
                .map(|m| m.trim_start_matches([' ', '\t', ':']).to_owned())
        })
        .unwrap_or_default();
    let cores = std::thread::available_parallelism().map_or(0, std::num::NonZero::get);
    let commit = first_line("git", &["log", "-1", "--format=%h %s"]);
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .is_ok_and(|o| !o.stdout.is_empty());
    format!(
        "- **Commit:** {commit}{}\n- **Machine:** {cpu}, {cores} threads; {}\n- **Date:** {}\n\
         - **Tools:** {}; {}; {}\n",
        if dirty {
            " (with uncommitted changes)"
        } else {
            ""
        },
        first_line("uname", &["-srm"]),
        first_line("date", &["-u", "+%Y-%m-%d %H:%M UTC"]),
        first_line("mosh-server", &["--version"]),
        first_line("ssh", &["-V"]),
        first_line("perf", &["--version"]),
    )
}

fn kib(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / 1024.0)
}

fn ms(d: Option<Duration>) -> String {
    d.map_or_else(
        || "-".to_owned(),
        |d| format!("{:.1}", d.as_secs_f64() * 1000.0),
    )
}

/// One workload's wire, for each system.
struct WireRow {
    name: String,
    about: String,
    output: usize,
    by: Vec<(System, Result<Wire, String>)>,
}

fn wire_cell(result: &Result<Wire, String>) -> String {
    match result {
        Ok(w) => format!(
            "{} / {}",
            kib(w.counts.to_client.bytes),
            kib(w.counts.to_server.bytes)
        ),
        Err(_) => "failed".to_owned(),
    }
}

/// The link profiles latency and settling are measured on.
fn profiles() -> [(&'static str, Profile); 5] {
    let rtt50 = Duration::from_millis(25);
    [
        ("clean", Profile::default()),
        (
            "50 ms RTT",
            Profile {
                delay: rtt50,
                ..Profile::default()
            },
        ),
        (
            "50 ms RTT, 5% loss",
            Profile {
                delay: rtt50,
                loss: 0.05,
                ..Profile::default()
            },
        ),
        (
            "1 Mbit/s, 50 ms RTT",
            Profile {
                delay: rtt50,
                rate: Some(1_000_000),
                ..Profile::default()
            },
        ),
        (
            "256 kbit/s, 50 ms RTT",
            Profile {
                delay: rtt50,
                rate: Some(256_000),
                ..Profile::default()
            },
        ),
    ]
}

/// A measure taken on a link: keystroke latency beside a flood, or the time an action takes to
/// settle.
#[derive(Clone, Copy)]
enum Kind {
    Latency { samples: usize },
    Settle { action: Action, repeats: usize },
}

/// What a measure found.
enum Got {
    Latency(Latency),
    Settle(Vec<Duration>),
}

/// Take `kind` through `system` over `profile`: for mosh and ssh in a namespace with netem when
/// `namespaces` (one method for UDP and TCP alike, ssh's server reached through a Unix socket);
/// for koh over its fault link.
async fn measure_one(
    kind: Kind,
    system: System,
    profile: Profile,
    setup: &Setup,
    scratch: &Path,
    seed: u64,
    namespaces: bool,
) -> Result<Got, String> {
    if system != System::Koh && namespaces {
        let mut child = match kind {
            Kind::Latency { samples } => vec![
                "latency".to_owned(),
                system.name().to_owned(),
                samples.to_string(),
            ],
            Kind::Settle { action, repeats } => vec![
                "settle".to_owned(),
                system.name().to_owned(),
                action.key().to_owned(),
                repeats.to_string(),
            ],
        };
        child.push(setup.koh.display().to_string());
        child.push(seed.to_string());
        let mut bridge = None;
        if let (System::Ssh, Some(sshd)) = (system, setup.sshd.as_ref()) {
            let socket = scratch.join(format!("ssh-{seed}-{}.sock", std::process::id()));
            bridge = netns::unix_to_tcp(&socket, ([127, 0, 0, 1], sshd.port).into()).ok();
            child.push(socket.display().to_string());
            child.push(sshd.key.display().to_string());
        }
        let measure = child.remove(0);
        let lines = tokio::task::spawn_blocking(move || netns::run(profile, &measure, &child))
            .await
            .map_err(|e| anyhow!("{e}"))
            .and_then(|r| r);
        if let Some(bridge) = bridge {
            bridge.abort();
        }
        let lines = lines.map_err(|e| format!("{e:#}"))?;
        return Ok(match kind {
            Kind::Latency { .. } => Got::Latency(Latency {
                shown: netns::durations(&lines, "shown "),
                echoed: netns::durations(&lines, "echoed "),
                missed: netns::count(&lines, "missed "),
            }),
            Kind::Settle { .. } => Got::Settle(netns::durations(&lines, "settle ")),
        });
    }
    if system == System::Ssh && profile.loss > 0.0 {
        return Err("not measured".to_owned());
    }
    let dir = scratch.join(format!("{}-{seed}", system.name()));
    match kind {
        Kind::Latency { samples } => measure::latency(system, setup, profile, samples, &dir, seed)
            .await
            .map(Got::Latency),
        Kind::Settle { action, repeats } => {
            measure::settle(system, setup, profile, action, repeats, &dir, seed)
                .await
                .map(Got::Settle)
        }
    }
    .map_err(|e| format!("{e:#}"))
}

/// The median of `values`, and their least and greatest.
fn spread(values: &[Duration]) -> Option<(Duration, Duration, Duration)> {
    let mut sorted = values.to_vec();
    sorted.sort();
    let mid = sorted.len().checked_div(2)?;
    Some((*sorted.get(mid)?, *sorted.first()?, *sorted.last()?))
}

/// A median with its range, in milliseconds.
fn ranged(values: &[Duration]) -> String {
    spread(values).map_or_else(
        || "-".to_owned(),
        |(median, low, high)| {
            if values.len() > 1 {
                format!(
                    "{} <sub>{}–{}</sub>",
                    ms(Some(median)),
                    ms(Some(low)),
                    ms(Some(high))
                )
            } else {
                ms(Some(median))
            }
        },
    )
}

/// One system's latency over runs: each run's p50 and p99, shown and echoed.
#[derive(Default)]
struct LatencyRuns {
    shown_p50: Vec<Duration>,
    shown_p99: Vec<Duration>,
    echoed_p50: Vec<Duration>,
    echoed_p99: Vec<Duration>,
    missed: usize,
    error: Option<String>,
}

/// One action's settling on one link: by system, each run's p50, and what went wrong if anything.
type SettleProfile = (&'static str, Vec<(System, Vec<Duration>, Option<String>)>);

/// What every measure found.
#[derive(Default)]
struct Results {
    wire: Vec<WireRow>,
    synthetic: usize,
    /// By profile, by system.
    latency: Vec<(&'static str, Vec<(System, LatencyRuns)>)>,
    /// By action, by profile, by system: each run's p50.
    settle: Vec<(Action, Vec<SettleProfile>)>,
    /// Each workload's history, and what fetching it all costs koh.
    scrollback: Vec<(String, usize, scrollback::History)>,
}

async fn run(args: &Args) -> anyhow::Result<String> {
    let scratch = std::env::temp_dir().join(format!("koh-bench-{}", std::process::id()));
    std::fs::create_dir_all(&scratch)?;
    let mut systems = Vec::new();
    let mut missing = Vec::new();
    for &system in &args.systems {
        let needs: &[&str] = match system {
            System::Koh => &[],
            System::Mosh => &["mosh-server", "mosh-client"],
            System::Ssh => &["ssh", "sshd", "ssh-keygen"],
        };
        let absent: Vec<&str> = needs
            .iter()
            .copied()
            .filter(|n| which(n).is_none())
            .collect();
        if absent.is_empty() {
            systems.push(system);
        } else {
            missing.push(format!("{} (no {})", system.name(), absent.join(", ")));
        }
    }
    let sshd = if systems.contains(&System::Ssh) {
        Some(Sshd::start(&scratch.join("sshd"))?)
    } else {
        None
    };
    let setup = Setup {
        koh: std::fs::canonicalize(&args.koh)?,
        sshd,
        direct: false,
    };
    let namespaces = netns::available();
    let load_before = load();
    let mut results = Results::default();

    if args.wire {
        let mut list: Vec<Workload> = workloads::synthetic();
        let corpus =
            recording::Recording::load_all(Path::new("testing/corpus")).map_err(|e| anyhow!(e))?;
        let recorded: Vec<Workload> = corpus
            .iter()
            .filter(|r| {
                args.recordings
                    .as_ref()
                    .is_none_or(|names| names.contains(&r.name))
            })
            .map(Workload::recorded)
            .collect();
        results.synthetic = list.len();
        list.extend(recorded);
        for workload in &list {
            match scrollback::measure(workload) {
                Ok(history) => {
                    results
                        .scrollback
                        .push((workload.name.clone(), workload.bytes(), history));
                }
                Err(e) => eprintln!("scrollback {}: {e:#}", workload.name),
            }
        }
        for (seed, workload) in (1u64..).zip(&list) {
            let mut by = Vec::new();
            for &system in &systems {
                let dir = scratch.join(format!("{}-{}", system.name(), workload.name));
                let result = measure::wire(system, &setup, workload, &dir, seed)
                    .await
                    .map_err(|e| format!("{e:#}"));
                eprintln!(
                    "wire {} {}: {}",
                    workload.name,
                    system.name(),
                    result.as_ref().map_or_else(Clone::clone, |w| format!(
                        "{} (packets {} / {})",
                        wire_cell(&Ok(*w)),
                        w.counts.to_client.packets,
                        w.counts.to_server.packets
                    ))
                );
                by.push((system, result));
            }
            results.wire.push(WireRow {
                name: workload.name.clone(),
                about: workload.about.clone(),
                output: workload.bytes(),
                by,
            });
        }
    }

    if args.latency {
        for (seed, (name, profile)) in (1u64..).zip(profiles()) {
            let mut by = Vec::new();
            for &system in &systems {
                let mut runs = LatencyRuns::default();
                for run in 0..args.runs {
                    let seed = seed
                        .saturating_mul(100)
                        .saturating_add(u64::try_from(run).unwrap_or(0));
                    let kind = Kind::Latency {
                        samples: args.samples,
                    };
                    match measure_one(kind, system, profile, &setup, &scratch, seed, namespaces)
                        .await
                    {
                        Ok(Got::Latency(l)) => {
                            let p = |v: &[Duration], q| percentile(v, q);
                            runs.shown_p50.extend(p(&l.shown, 50));
                            runs.shown_p99.extend(p(&l.shown, 99));
                            runs.echoed_p50.extend(p(&l.echoed, 50));
                            runs.echoed_p99.extend(p(&l.echoed, 99));
                            runs.missed = runs.missed.saturating_add(l.missed);
                        }
                        Ok(Got::Settle(_)) => {}
                        Err(e) => runs.error = Some(e),
                    }
                }
                eprintln!(
                    "latency {name} {}: {} / {}",
                    system.name(),
                    ranged(&runs.shown_p50),
                    ranged(&runs.shown_p99)
                );
                by.push((system, runs));
            }
            results.latency.push((name, by));
        }
    }

    if args.settle {
        for action in Action::ALL {
            let mut by_profile = Vec::new();
            for (seed, (name, profile)) in (1u64..).zip(profiles()) {
                let mut by = Vec::new();
                for &system in &systems {
                    let mut p50s = Vec::new();
                    let mut error = None;
                    for run in 0..args.runs {
                        let seed = seed
                            .saturating_mul(100)
                            .saturating_add(u64::try_from(run).unwrap_or(0));
                        let kind = Kind::Settle {
                            action,
                            repeats: args.repeats,
                        };
                        match measure_one(kind, system, profile, &setup, &scratch, seed, namespaces)
                            .await
                        {
                            Ok(Got::Settle(times)) => p50s.extend(percentile(&times, 50)),
                            Ok(Got::Latency(_)) => {}
                            Err(e) => error = Some(e),
                        }
                    }
                    eprintln!(
                        "settle {} {name} {}: {}",
                        action.key(),
                        system.name(),
                        ranged(&p50s)
                    );
                    by.push((system, p50s, error));
                }
                by_profile.push((name, by));
            }
            results.settle.push((action, by_profile));
        }
    }

    let mut out = String::from("# koh's scoreboard\n\n");
    out.push_str(
        "koh beside mosh and plain ssh, made by `testing/scoreboard.sh` (see \
         `testing/bench/README.md` for how each number is taken).\n\n",
    );
    out.push_str(&machine());
    if !missing.is_empty() {
        let _ = writeln!(out, "- **Not measured:** {}", missing.join("; "));
    }
    let _ = writeln!(
        out,
        "- **Runs:** latency and settling {} times each, given as the median with its range \
         (<sub>least–greatest</sub>); bytes, memory and instructions once, as they hardly vary.",
        args.runs
    );
    summary(&mut out, &systems, &results);
    wire_section(&mut out, &systems, &results);
    scrollback_section(&mut out, &systems, &results);
    latency_section(&mut out, &systems, &results, args, namespaces);
    settle_section(&mut out, &systems, &results, args, namespaces);

    if args.memory {
        out.push_str("\n## Server memory per session\n\n");
        out.push_str(
            "What a session's terminal costs the server: a child process makes server emulators \
             at 40x120 with the scrollback given, fills them (or not) with enough lines of text \
             to fill the scrollback and the screen, takes a snapshot of each as a session holds \
             one, and reports how much its resident memory grew, per session. A session also \
             holds a PTY, two threads and its connection, which this does not count.\n\n\
             | Scrollback | Sessions | Idle | Full |\n| ---: | ---: | ---: | ---: |\n",
        );
        for (scrollback, sessions) in [(1000usize, 16usize), (65_000, 2)] {
            let idle = children::footprint(scrollback, false, sessions);
            let full = children::footprint(scrollback, true, sessions);
            let show = |r: &anyhow::Result<u64>| {
                r.as_ref()
                    .map_or_else(|e| format!("failed: {e}"), |b| format!("{} KiB", kib(*b)))
            };
            let _ = writeln!(
                out,
                "| {scrollback} | {sessions} | {} | {} |",
                show(&idle),
                show(&full)
            );
        }
    }

    if args.instructions {
        instructions_section(&mut out);
    }
    let _ = write!(
        out,
        "\nLoad average at the start: {load_before}; at the end: {}.\n",
        load()
    );
    drop(setup);
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(out)
}

/// The least of `values` by system, and which system has it: the axis's best.
fn best(values: &[(System, Option<f64>)]) -> String {
    values
        .iter()
        .filter_map(|(s, v)| Some((*s, (*v)?)))
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .map_or_else(|| "-".to_owned(), |(s, _)| format!("**{}**", s.name()))
}

/// The plain summary at the top: who is best on each axis, lower being better.
fn summary(out: &mut String, systems: &[System], results: &Results) {
    out.push_str("\n## Who wins\n\n");
    out.push_str(
        "Lower is better on every row. The detailed tables below say how each number is taken.\n\n",
    );
    out.push_str("| Axis |");
    for s in systems {
        let _ = write!(out, " {} |", s.name());
    }
    out.push_str(" Best |\n| --- |");
    for _ in systems {
        out.push_str(" ---: |");
    }
    out.push_str(" --- |\n");
    let row = |out: &mut String, axis: &str, values: Vec<(System, Option<f64>)>, unit: &str| {
        let _ = write!(out, "| {axis} |");
        for (_, v) in &values {
            let _ = write!(
                out,
                " {} |",
                v.map_or_else(|| "-".to_owned(), |v| format!("{v:.1}{unit}"))
            );
        }
        let _ = writeln!(out, " {} |", best(&values));
    };
    // Bytes to the client.
    let (synthetic, recorded) = results
        .wire
        .split_at(results.synthetic.min(results.wire.len()));
    let bytes = |rows: &[WireRow], i: usize| -> Option<f64> {
        let mut total = 0u64;
        for r in rows {
            match r.by.get(i) {
                Some((_, Ok(w))) => total = total.saturating_add(w.counts.to_client.bytes),
                Some((_, Err(_))) | None => return None,
            }
        }
        (!rows.is_empty()).then_some(total as f64 / 1024.0)
    };
    if !recorded.is_empty() {
        let values = systems
            .iter()
            .enumerate()
            .map(|(i, s)| (*s, bytes(recorded, i)))
            .collect();
        row(out, "Bytes to the client, the recordings (KiB)", values, "");
    }
    for name in ["redraw-30fps", "ascii-flood"] {
        if let Some(r) = synthetic.iter().find(|r| r.name == name) {
            let values = systems
                .iter()
                .enumerate()
                .map(|(i, s)| (*s, bytes(std::slice::from_ref(r), i)))
                .collect();
            row(
                out,
                &format!("Bytes to the client, {name} (KiB)"),
                values,
                "",
            );
        }
    }
    let msf =
        |d: Option<(Duration, Duration, Duration)>| d.map(|(m, _, _)| m.as_secs_f64() * 1000.0);
    for (name, by) in &results.latency {
        let values = by
            .iter()
            .map(|(s, r)| (*s, msf(spread(&r.shown_p99))))
            .collect();
        row(
            out,
            &format!("Typing, worst case shown (p99 ms), {name}"),
            values,
            "",
        );
    }
    if let Some((_, by)) = results.latency.first() {
        let values = by
            .iter()
            .map(|(s, r)| {
                // koh's echoed is the server's own; mosh's and ssh's shown is all they report.
                let v = if *s == System::Koh {
                    &r.echoed_p50
                } else {
                    &r.shown_p50
                };
                (*s, msf(spread(v)))
            })
            .collect();
        row(
            out,
            "Typing, the server's echo (p50 ms), clean link, beside a flood",
            values,
            "",
        );
    }
    for (action, by_profile) in &results.settle {
        if let Some((name, by)) = by_profile.last() {
            let values = by.iter().map(|(s, p, _)| (*s, msf(spread(p)))).collect();
            row(
                out,
                &format!("Settled after {} (ms), {name}", action.name()),
                values,
                "",
            );
        }
    }
    let _ = write!(out, "| Scrollback |");
    let (rows, bytes) = results
        .scrollback
        .iter()
        .fold((0_usize, 0_u64), |(rows, bytes), (_, _, h)| {
            (rows.saturating_add(h.rows), bytes.saturating_add(h.bytes))
        });
    for s in systems {
        let v = match s {
            System::Koh if rows > 0 => format!(
                "the server's, in full colour, kept across reconnects ({rows} rows of the \
                 workloads in {} KiB)",
                kib(bytes)
            ),
            System::Koh => "the server's, in full colour, kept across reconnects".to_owned(),
            System::Mosh => "none".to_owned(),
            System::Ssh => "the terminal's own, lost on a reconnect".to_owned(),
        };
        let _ = write!(out, " {v} |");
    }
    out.push_str(" **koh** |\n");
}

fn scrollback_section(out: &mut String, systems: &[System], results: &Results) {
    let kept: Vec<_> = results
        .scrollback
        .iter()
        .filter(|(_, _, h)| h.rows > 0)
        .collect();
    if kept.is_empty() {
        return;
    }
    out.push_str("\n## Scrollback\n\n");
    out.push_str(
        "Each workload played into a server emulator keeping the default 1,000 lines, then \
         every row of its history fetched as koh's scrollback view (`Ctrl-^ [`) fetches them: \
         the bytes of the compressed history streams, in KiB. koh fetches a row only when the \
         user scrolls to it (and the newest screenful when idle), and never twice. mosh keeps \
         no history; ssh's is the user's terminal's, which every byte of output already paid \
         for, and which a reconnect loses. Workloads that leave no history (those on the \
         alternate screen) are left out.\n\n",
    );
    out.push_str("| Workload | Output KiB | History rows |");
    for system in systems {
        let _ = write!(out, " {} |", system.name());
    }
    out.push_str("\n| --- | ---: | ---: |");
    for _ in systems {
        out.push_str(" ---: |");
    }
    out.push('\n');
    for (name, output, history) in kept {
        let output = kib(u64::try_from(*output).unwrap_or(0));
        let _ = write!(out, "| {name} | {output} | {} |", history.rows);
        for system in systems {
            let v = match system {
                System::Koh => kib(history.bytes),
                System::Mosh => "none".to_owned(),
                System::Ssh => format!("({output})"),
            };
            let _ = write!(out, " {v} |");
        }
        out.push('\n');
    }
}

fn wire_section(out: &mut String, systems: &[System], results: &Results) {
    if results.wire.is_empty() {
        return;
    }
    out.push_str("\n## Bytes on the wire\n\n");
    out.push_str(
        "Each workload played as the program, on a clean link, one step at a time: the \
         harness types for a step, the program writes it, and the step ends when the link has \
         carried nothing for 300 ms. Payload bytes delivered (UDP payloads for koh and mosh, \
         TCP payloads for ssh; no IP, UDP or TCP headers), after the connection's setup, in \
         KiB: to the client / to the server. koh is counted on the fault link of its own \
         tests, which is its only path; mosh and ssh through a proxy on loopback. ssh is as \
         it ships: OpenSSH 9.5 and later obscure keystroke timing by default, sending chaff \
         packets for a while after each key typed, which the harness's key for each step \
         sets off as a user's typing would.\n\n",
    );
    let header = |out: &mut String| {
        out.push_str("| Workload | Output KiB |");
        for system in systems {
            let _ = write!(out, " {} |", system.name());
        }
        out.push_str("\n| --- | ---: |");
        for _ in systems {
            out.push_str(" ---: |");
        }
        out.push('\n');
    };
    header(out);
    let (synthetic, recorded) = results
        .wire
        .split_at(results.synthetic.min(results.wire.len()));
    for row in synthetic {
        let _ = write!(
            out,
            "| {} ({}) | {} |",
            row.name,
            row.about,
            kib(u64::try_from(row.output).unwrap_or(0))
        );
        for (_, result) in &row.by {
            let _ = write!(out, " {} |", wire_cell(result));
        }
        out.push('\n');
    }
    if !recorded.is_empty() {
        let output: usize = recorded.iter().map(|r| r.output).sum();
        let _ = write!(
            out,
            "| **the corpus**, {} recordings | {} |",
            recorded.len(),
            kib(u64::try_from(output).unwrap_or(0))
        );
        for i in 0..systems.len() {
            let (mut down, mut up, mut failed) = (0u64, 0u64, 0usize);
            for row in recorded {
                match row.by.get(i) {
                    Some((_, Ok(w))) => {
                        down = down.saturating_add(w.counts.to_client.bytes);
                        up = up.saturating_add(w.counts.to_server.bytes);
                    }
                    Some((_, Err(_))) | None => failed = failed.saturating_add(1),
                }
            }
            let _ = write!(out, " {} / {}", kib(down), kib(up));
            if failed > 0 {
                let _ = write!(out, " ({failed} failed)");
            }
            out.push_str(" |");
        }
        out.push('\n');
    }
    // What each client made the user's terminal parse, and koh's paints a second.
    out.push_str(
        "\n**What the user's terminal is given:** the bytes each client wrote to it, in KiB; for \
         koh also how many times it painted a second.\n\n",
    );
    header(out);
    let terminal = |out: &mut String, name: &str, rows: &[&WireRow]| {
        let output: usize = rows.iter().map(|r| r.output).sum();
        let _ = write!(
            out,
            "| {name} | {} |",
            kib(u64::try_from(output).unwrap_or(0))
        );
        for (i, system) in systems.iter().enumerate() {
            let (mut written, mut paints, mut seconds, mut ok) = (0u64, 0u64, 0f64, true);
            for row in rows {
                match row.by.get(i) {
                    Some((_, Ok(w))) => {
                        written = written.saturating_add(w.written);
                        paints = paints.saturating_add(w.paints);
                        seconds += w.seconds;
                    }
                    Some((_, Err(_))) | None => ok = false,
                }
            }
            if !ok {
                out.push_str(" failed |");
            } else if *system == System::Koh && seconds > 0.0 {
                let _ = write!(
                    out,
                    " {} ({:.0} a s) |",
                    kib(written),
                    paints as f64 / seconds
                );
            } else {
                let _ = write!(out, " {} |", kib(written));
            }
        }
        out.push('\n');
    };
    for row in synthetic {
        terminal(out, &row.name, &[row]);
    }
    if !recorded.is_empty() {
        let rows: Vec<&WireRow> = recorded.iter().collect();
        terminal(out, "**the corpus**", &rows);
        out.push_str("\n<details><summary>Each recording, bytes on the wire</summary>\n\n");
        header(out);
        for row in recorded {
            let _ = write!(
                out,
                "| {} | {} |",
                row.name,
                kib(u64::try_from(row.output).unwrap_or(0))
            );
            for (_, result) in &row.by {
                let _ = write!(out, " {} |", wire_cell(result));
            }
            out.push('\n');
        }
        out.push_str("\n</details>\n");
    }
}

fn method_of_links(namespaces: bool) -> &'static str {
    if namespaces {
        "koh runs over the fault link of its own tests with the profile; mosh and ssh run in a \
         network namespace of this user's whose loopback a kernel queueing discipline (`tc \
         netem`) delays and drops on with the same profile, each packet once each way, so TCP \
         cannot hide a drop and ssh is measured under loss too. ssh's server stays outside the \
         namespace, reached through a Unix socket, so that it can give its sessions a terminal."
    } else {
        "koh runs over the fault link of its own tests with the profile; mosh and ssh through a \
         proxy on loopback that delays (and, for UDP, drops). A TCP proxy cannot drop without \
         TCP hiding it, so ssh has no figure with loss: user namespaces were not available."
    }
}

fn latency_section(
    out: &mut String,
    systems: &[System],
    results: &Results,
    args: &Args,
    namespaces: bool,
) {
    if results.latency.is_empty() {
        return;
    }
    out.push_str("\n## Keystroke latency beside a flood\n\n");
    let _ = writeln!(
        out,
        "A program floods the top row as fast as `awk` can write (its cursor saved and restored \
         around each write) while `cat` echoes what is typed below it; {} keys are typed 150–250 \
         ms apart, and each is timed from being typed to showing in the user's terminal (a \
         fux-vt parser reading what the client painted): with prediction, as the user sees it. \
         For koh, *echoed* is the time to show on the screen the server sent, prediction aside. \
         Milliseconds, p50 / p99, each the median of {} runs with its range. The delay is one \
         way, each way; loss is each way, per packet. {}\n",
        args.samples,
        args.runs,
        method_of_links(namespaces)
    );
    out.push_str("| Link |");
    for system in systems {
        let _ = write!(out, " {} |", system.name());
        if *system == System::Koh {
            out.push_str(" koh, echoed |");
        }
    }
    out.push_str("\n| --- |");
    for system in systems {
        out.push_str(" ---: |");
        if *system == System::Koh {
            out.push_str(" ---: |");
        }
    }
    out.push('\n');
    for (name, by) in &results.latency {
        let _ = write!(out, "| {name} |");
        for (system, runs) in by {
            let cell = |p50: &[Duration], p99: &[Duration]| {
                if p50.is_empty() {
                    return match &runs.error {
                        Some(e) if e == "not measured" => "-".to_owned(),
                        Some(_) => "failed".to_owned(),
                        None => "-".to_owned(),
                    };
                }
                let mut c = format!("{} / {}", ranged(p50), ranged(p99));
                if runs.missed > 0 {
                    let _ = write!(c, " ({} missed)", runs.missed);
                }
                c
            };
            let _ = write!(out, " {} |", cell(&runs.shown_p50, &runs.shown_p99));
            if *system == System::Koh {
                let _ = write!(out, " {} |", cell(&runs.echoed_p50, &runs.echoed_p99));
            }
        }
        out.push('\n');
    }
}

fn settle_section(
    out: &mut String,
    systems: &[System],
    results: &Results,
    args: &Args,
    namespaces: bool,
) {
    if results.settle.is_empty() {
        return;
    }
    out.push_str("\n## Time until the screen settles\n\n");
    let _ = writeln!(
        out,
        "What users notice beyond a keystroke's echo: from an action to the moment the user's \
         terminal (a fux-vt parser reading what the client wrote) last changed before it stayed \
         unchanged for 500 ms. The same for every system, with no need to know its server's \
         screen. Each action is repeated {} times in a session at 40x120; the figure is the \
         median of those, and the median of {} runs with its range, in milliseconds. nvim runs \
         with `--clean` on a 5,000-line source file; `ls -l` lists 2,000 files after a `clear`; \
         the resize alternates between 30x100 and 40x120. {}\n",
        args.repeats,
        args.runs,
        method_of_links(namespaces)
    );
    out.push_str("| Action | Link |");
    for system in systems {
        let _ = write!(out, " {} |", system.name());
    }
    out.push_str("\n| --- | --- |");
    for _ in systems {
        out.push_str(" ---: |");
    }
    out.push('\n');
    for (action, by_profile) in &results.settle {
        for (name, by) in by_profile {
            let _ = write!(out, "| {} | {name} |", action.name());
            for (_, p50s, error) in by {
                let cell = if p50s.is_empty() {
                    match error {
                        Some(e) if e == "not measured" => "-".to_owned(),
                        Some(_) => "failed".to_owned(),
                        None => "-".to_owned(),
                    }
                } else {
                    ranged(p50s)
                };
                let _ = write!(out, " {cell} |");
            }
            out.push('\n');
        }
    }
}

fn instructions_section(out: &mut String) {
    out.push_str("\n## Instructions\n\n");
    match children::Counter::detect() {
        None => out.push_str(
            "Not measured: nothing here counts instructions (perf with \
             `kernel.perf_event_paranoid` at 2 or less, or valgrind).\n",
        ),
        Some(counter) => {
            let _ = writeln!(
                out,
                "Counted with `{}`, which does not change with the machine's load: each in a \
                 child process of its own, the fewest of three runs less the fewest of three \
                 baseline runs (making the same inputs, doing nothing with them). *Emulator*: \
                 the output fed to the server's emulator in 4 KiB reads, per byte. *Server*: \
                 the same, with the snapshot, diff and encoded frame a session's burst takes \
                 after every read, per byte: an interactive program's pace, and more than a \
                 flood costs, since a session takes one snapshot per burst of up to 65 reads \
                 and sends frames at most once per frame interval. *Client*: those frames \
                 decoded, applied and painted, per frame.\n\n\
                 | Workload | Emulator, per byte | Server, per byte | Client, per frame |\n\
                 | --- | ---: | ---: | ---: |",
                counter.name()
            );
            for workload in children::COUNTED {
                let emulator = children::instructions(counter, "emulator", workload, 3);
                let server = children::instructions(counter, "server", workload, 3);
                let client = children::instructions(counter, "client", workload, 3);
                let show = |r: &anyhow::Result<f64>| {
                    r.as_ref()
                        .map_or_else(|e| format!("failed: {e}"), |n| format!("{n:.1}"))
                };
                eprintln!(
                    "instructions {workload}: {} {} {}",
                    show(&emulator),
                    show(&server),
                    show(&client)
                );
                let _ = writeln!(
                    out,
                    "| {workload} | {} | {} | {} |",
                    show(&emulator),
                    show(&server),
                    show(&client)
                );
            }
        }
    }
}

/// A measure in a namespace of its own (see [`netns`]): `MEASURE ARGS…`.
///
/// - `latency SYSTEM SAMPLES KOH SEED [SOCKET KEY]` prints `shown MS` and `echoed MS` a key, and
///   `missed N`;
/// - `settle SYSTEM ACTION REPEATS KOH SEED [SOCKET KEY]` prints `settle MS` a repeat.
///
/// For ssh, SOCKET is the Unix socket the parent carries on to its sshd, and KEY the key it
/// accepts.
fn netns_child(args: &[String]) -> anyhow::Result<()> {
    let arg = |i: usize| {
        args.get(i)
            .cloned()
            .ok_or_else(|| anyhow!("too few arguments"))
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let scratch = std::env::temp_dir().join(format!("koh-bench-ns-{}", std::process::id()));
    let measure = arg(0)?;
    let system = system(&arg(1)?)?;
    // Where the arguments after the measure's own begin.
    let rest: usize = if measure == "settle" { 4 } else { 3 };
    // sshd stays outside, where it can give its sessions a terminal: the client reaches it
    // through the namespace's loopback and a Unix socket.
    let sshd = if system == System::Ssh {
        let socket = PathBuf::from(arg(rest.saturating_add(2))?);
        let port = runtime.block_on(netns::tcp_to_unix(socket))?;
        Some(Sshd::at(port, PathBuf::from(arg(rest.saturating_add(3))?)))
    } else {
        None
    };
    let setup = Setup {
        koh: PathBuf::from(arg(rest)?),
        sshd,
        direct: true,
    };
    let seed: u64 = arg(rest.saturating_add(1))?.parse()?;
    let result = match measure.as_str() {
        "latency" => {
            let samples: usize = arg(2)?.parse()?;
            runtime
                .block_on(measure::latency(
                    system,
                    &setup,
                    Profile::default(),
                    samples,
                    &scratch.join("latency"),
                    seed,
                ))
                .map(|latency| {
                    for d in &latency.shown {
                        println!("shown {}", d.as_secs_f64() * 1000.0);
                    }
                    for d in &latency.echoed {
                        println!("echoed {}", d.as_secs_f64() * 1000.0);
                    }
                    println!("missed {}", latency.missed);
                })
        }
        "settle" => {
            let action = Action::from_key(&arg(2)?).ok_or_else(|| anyhow!("no such action"))?;
            let repeats: usize = arg(3)?.parse()?;
            runtime
                .block_on(measure::settle(
                    system,
                    &setup,
                    Profile::default(),
                    action,
                    repeats,
                    &scratch.join("settle"),
                    seed,
                ))
                .map(|times| {
                    for d in &times {
                        println!("settle {}", d.as_secs_f64() * 1000.0);
                    }
                })
        }
        other => Err(anyhow!("no namespaced measure {other}")),
    };
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

fn system(name: &str) -> anyhow::Result<System> {
    match name {
        "koh" => Ok(System::Koh),
        "mosh" => Ok(System::Mosh),
        "ssh" => Ok(System::Ssh),
        other => Err(anyhow!("no system {other}")),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some(netns::CHILD) {
        return match netns_child(argv.get(2..).unwrap_or_default()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{e:#}");
                ExitCode::FAILURE
            }
        };
    }
    let child = match argv.get(1).map(String::as_str) {
        Some(children::FOOTPRINT) => {
            Some(children::footprint_child(argv.get(2..).unwrap_or_default()))
        }
        Some(children::INSTRUCTIONS) => Some(children::instructions_child(
            argv.get(2..).unwrap_or_default(),
        )),
        _ => None,
    };
    if let Some(result) = child {
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{e:#}");
                ExitCode::FAILURE
            }
        };
    }
    let result = args().and_then(|args| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()?;
        let out = runtime.block_on(run(&args))?;
        std::fs::write(&args.out, out)?;
        eprintln!("wrote {}", args.out.display());
        Ok(())
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("koh-bench: {e:#}");
            ExitCode::FAILURE
        }
    }
}
