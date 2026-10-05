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
mod proxy;
#[expect(
    dead_code,
    reason = "the scoreboard measures, and has no use for the recordings the user's terminal is \
              known to show otherwise than the server"
)]
#[path = "../../corpus/recording.rs"]
mod recording;
mod remote;
mod workloads;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

use anyhow::anyhow;

use crate::measure::{percentile, Latency, Wire};
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
    wire: bool,
    latency: bool,
    memory: bool,
    instructions: bool,
}

const USAGE: &str = "koh-bench --koh BIN [--out FILE] [--recordings all|none|a,b] \
                     [--systems koh,mosh,ssh] [--samples N] [--skip wire,latency,memory,instructions]";

fn args() -> anyhow::Result<Args> {
    let mut args = Args {
        koh: PathBuf::from("target/release/koh"),
        out: PathBuf::from("docs/SCOREBOARD.md"),
        recordings: None,
        systems: vec![System::Koh, System::Mosh, System::Ssh],
        samples: 100,
        wire: true,
        latency: true,
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
            "--skip" => {
                for skip in value()?.split(',') {
                    match skip {
                        "wire" => args.wire = false,
                        "latency" => args.latency = false,
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

async fn run(args: &Args) -> anyhow::Result<String> {
    let scratch = std::env::temp_dir().join(format!("koh-bench-{}", std::process::id()));
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
    };
    let load_before = load();
    let mut out = String::from("# koh's scoreboard\n\n");
    out.push_str(
        "koh beside mosh and plain ssh, made by `testing/scoreboard.sh` (see \
         `testing/bench/README.md` for how each number is taken). Every number is from one run on \
         the machine below; run it again to compare on yours.\n\n",
    );
    out.push_str(&machine());
    if !missing.is_empty() {
        let _ = writeln!(out, "- **Not measured:** {}", missing.join("; "));
    }

    if args.wire {
        let mut rows = Vec::new();
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
        let synthetic_count = list.len();
        list.extend(recorded);
        for (seed, workload) in (1u64..).zip(&list) {
            let mut by = Vec::new();
            for &system in &systems {
                let dir = scratch.join(format!("{}-{}", system.name(), workload.name));
                let result = measure::wire(system, &setup, workload, &dir, seed)
                    .await
                    .map_err(|e| format!("{e:#}"));
                if let Err(e) = &result {
                    eprintln!("{}: {}: {e}", workload.name, system.name());
                }
                eprintln!(
                    "wire {} {}: {}",
                    workload.name,
                    system.name(),
                    wire_cell(&result)
                );
                by.push((system, result));
            }
            rows.push(WireRow {
                name: workload.name.clone(),
                about: workload.about.clone(),
                output: workload.bytes(),
                by,
            });
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
            for system in &systems {
                let _ = write!(out, " {} |", system.name());
            }
            out.push_str("\n| --- | ---: |");
            for _ in &systems {
                out.push_str(" ---: |");
            }
            out.push('\n');
        };
        header(&mut out);
        let (synthetic_rows, recorded_rows) = rows.split_at(synthetic_count.min(rows.len()));
        for row in synthetic_rows {
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
        if !recorded_rows.is_empty() {
            let output: usize = recorded_rows.iter().map(|r| r.output).sum();
            let _ = write!(
                out,
                "| **the corpus**, {} recordings | {} |",
                recorded_rows.len(),
                kib(u64::try_from(output).unwrap_or(0))
            );
            for (i, system) in systems.iter().enumerate() {
                let (mut down, mut up, mut failed) = (0u64, 0u64, 0usize);
                for row in recorded_rows {
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
                let _ = system;
                out.push_str(" |");
            }
            out.push_str("\n\n<details><summary>Each recording</summary>\n\n");
            header(&mut out);
            for row in recorded_rows {
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

    if args.latency {
        let profiles = [
            ("clean", Profile::default()),
            (
                "50 ms RTT",
                Profile {
                    delay: Duration::from_millis(25),
                    loss: 0.0,
                },
            ),
            (
                "50 ms RTT, 5% loss",
                Profile {
                    delay: Duration::from_millis(25),
                    loss: 0.05,
                },
            ),
        ];
        out.push_str("\n## Keystroke latency beside a flood\n\n");
        let _ = writeln!(
            out,
            "A program floods the top row as fast as `awk` can write (its cursor saved and \
             restored around each write) while `cat` echoes what is typed below it; {} keys are \
             typed 150–250 ms apart, and each is timed from being typed to showing in the user's \
             terminal (a fux-vt parser reading what the client painted): with prediction, as the \
             user sees it. For koh, *echoed* is the time to show on the screen the server sent, \
             prediction aside. Milliseconds, p50 / p99. The delay is one way, each way; loss is \
             each way, per packet. ssh has no figure with loss: a TCP proxy cannot drop without \
             TCP hiding it, which needs a kernel queueing discipline this harness does not use.\n",
            args.samples
        );
        out.push_str("| Link |");
        for system in &systems {
            let _ = write!(out, " {} |", system.name());
            if *system == System::Koh {
                out.push_str(" koh, echoed |");
            }
        }
        out.push_str("\n| --- |");
        for system in &systems {
            out.push_str(" ---: |");
            if *system == System::Koh {
                out.push_str(" ---: |");
            }
        }
        out.push('\n');
        for (seed, (name, profile)) in (1u64..).zip(profiles) {
            let _ = write!(out, "| {name} |");
            for &system in &systems {
                let result = if system == System::Ssh && profile.loss > 0.0 {
                    Err("not measured".to_owned())
                } else {
                    let dir = scratch.join(format!("latency-{}-{seed}", system.name()));
                    measure::latency(system, &setup, profile, args.samples, &dir, seed)
                        .await
                        .map_err(|e| format!("{e:#}"))
                };
                let cell = |l: &Latency, v: &[Duration]| {
                    let mut c = format!("{} / {}", ms(percentile(v, 50)), ms(percentile(v, 99)));
                    if l.missed > 0 {
                        let _ = write!(c, " ({} missed)", l.missed);
                    }
                    c
                };
                match &result {
                    Ok(l) => {
                        eprintln!("latency {name} {}: {}", system.name(), cell(l, &l.shown));
                        let _ = write!(out, " {} |", cell(l, &l.shown));
                        if system == System::Koh {
                            let _ = write!(out, " {} |", cell(l, &l.echoed));
                        }
                    }
                    Err(e) => {
                        eprintln!("latency {name} {}: {e}", system.name());
                        let shown = if e == "not measured" { "-" } else { "failed" };
                        let _ = write!(out, " {shown} |");
                        if system == System::Koh {
                            let _ = write!(out, " {shown} |");
                        }
                    }
                }
            }
            out.push('\n');
        }
    }

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
    let _ = write!(
        out,
        "\nLoad average at the start: {load_before}; at the end: {}.\n",
        load()
    );
    drop(setup);
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(out)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
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
