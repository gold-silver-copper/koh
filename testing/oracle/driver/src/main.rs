//! koh's oracle: koh at the working tree beside koh at a commit, given the same sessions (the
//! corpus's recordings and random ones: output, resizes, keystrokes, lost frames, time) and
//! compared on what the user's terminal would show, read back from what each painted, and on
//! what each answered the program and sent the server. A difference fails, shrunk to the
//! smallest case that shows it and saved to replay. Frame bytes are reported for each side, not
//! compared, so a change in what koh sends is a number, not a failure.
//!
//! `testing/oracle.sh` builds both sides and runs this; see `testing/oracle/README.md`.

mod case;
mod compare;
mod inputs;
#[expect(
    dead_code,
    reason = "the oracle compares koh with koh, so it has no use for the recordings the user's \
              terminal is known to show otherwise than the server"
)]
#[path = "../../../corpus/recording.rs"]
mod recording;
mod shrink;
mod side;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use case::Case;
use compare::Run;
use side::Side;

/// What to run, from the command line.
struct Args {
    side: PathBuf,
    base: PathBuf,
    cases: u64,
    seed: u64,
    recordings: bool,
    replay: Option<PathBuf>,
    save: PathBuf,
}

const USAGE: &str = "koh-oracle --side BIN --base BIN [--cases N] [--seed S] [--no-recordings] \
                     [--replay FILE] [--save DIR]";

fn args() -> Result<Args, String> {
    let mut args = Args {
        side: PathBuf::new(),
        base: PathBuf::new(),
        cases: 2_000,
        seed: 1,
        recordings: true,
        replay: None,
        save: PathBuf::from("testing/oracle/target/cases"),
    };
    let mut words = std::env::args().skip(1);
    while let Some(word) = words.next() {
        let mut value = || {
            words
                .next()
                .ok_or_else(|| format!("{word} needs a value\n{USAGE}"))
        };
        match word.as_str() {
            "--side" => args.side = PathBuf::from(value()?),
            "--base" => args.base = PathBuf::from(value()?),
            "--cases" => args.cases = value()?.parse().map_err(|e| format!("--cases: {e}"))?,
            "--seed" => args.seed = value()?.parse().map_err(|e| format!("--seed: {e}"))?,
            "--no-recordings" => args.recordings = false,
            "--replay" => args.replay = Some(PathBuf::from(value()?)),
            "--save" => args.save = PathBuf::from(value()?),
            "--help" | "-h" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    if args.side.as_os_str().is_empty() || args.base.as_os_str().is_empty() {
        return Err(USAGE.to_owned());
    }
    Ok(args)
}

/// The two sides, and what they have sent.
struct Oracle {
    side: Side,
    base: Side,
    bytes: (u64, u64),
}

impl Oracle {
    /// The difference the sides show on `case`, if any.
    fn check(&mut self, case: &Case) -> Result<Option<String>, String> {
        let (a, b) = match (self.base.run(case), self.side.run(case)) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(e), Ok(_)) | (Ok(_), Err(e)) => return Ok(Some(e)),
            (Err(e), Err(_)) => return Err(e),
        };
        let (a, b) = (Run::parse(&a)?, Run::parse(&b)?);
        self.bytes.0 = self.bytes.0.saturating_add(a.frame_bytes());
        self.bytes.1 = self.bytes.1.saturating_add(b.frame_bytes());
        compare::difference(case, &a, &b, ("base", "tree"))
    }
}

/// Report a difference on `case`: shrink it, save it, and say how to replay it.
fn report(oracle: &mut Oracle, case: &Case, difference: &str, save: &Path, started: Instant) {
    eprintln!(
        "DIFFERENCE in {} after {:.1}s: {difference}",
        case.name,
        started.elapsed().as_secs_f64()
    );
    eprintln!("shrinking {} steps...", case.steps.len());
    let small = shrink::shrink(case, |c| oracle.check(c).is_ok_and(|d| d.is_some()));
    let what = oracle
        .check(&small)
        .ok()
        .flatten()
        .unwrap_or_else(|| difference.to_owned());
    let path = save.join(format!("{}.case", case.name));
    let saved = std::fs::create_dir_all(save).and_then(|()| std::fs::write(&path, small.text()));
    eprintln!("shrunk to {} steps: {what}", small.steps.len());
    eprintln!("{}", small.text().trim_end());
    match saved {
        Ok(()) => eprintln!(
            "saved: replay with `testing/oracle.sh --replay {}`",
            path.display()
        ),
        Err(e) => eprintln!("could not save {}: {e}", path.display()),
    }
}

fn percent(base: u64, tree: u64) -> String {
    if base == 0 {
        return "-".to_owned();
    }
    let change = (tree as f64 - base as f64) * 100.0 / base as f64;
    format!("{change:+.2}%")
}

fn run() -> Result<bool, String> {
    let args = args()?;
    let mut oracle = Oracle {
        side: Side::new("tree", args.side.clone()),
        base: Side::new("base", args.base.clone()),
        bytes: (0, 0),
    };
    let started = Instant::now();
    if let Some(path) = &args.replay {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let case = Case::parse(&path.display().to_string(), &text)?;
        if let Some(d) = oracle.check(&case)? {
            eprintln!("DIFFERENCE: {d}");
            return Ok(false);
        }
        println!("alike on {}", path.display());
        return Ok(true);
    }
    let mut cases = 0u64;
    if args.recordings {
        let dir = Path::new("testing/corpus");
        let corpus = recording::Recording::load_all(dir)?;
        for (seed, recording) in (args.seed..).zip(&corpus) {
            // Every other recording over a link that loses a fifth of its frames.
            let loss = if seed % 2 == 0 { 20 } else { 0 };
            let case = inputs::recorded(recording, seed, loss);
            cases = cases.saturating_add(1);
            if let Some(d) = oracle.check(&case)? {
                report(&mut oracle, &case, &d, &args.save, started);
                return Ok(false);
            }
        }
        println!(
            "recordings: {} alike, frame bytes base {} tree {} ({})",
            corpus.len(),
            oracle.bytes.0,
            oracle.bytes.1,
            percent(oracle.bytes.0, oracle.bytes.1)
        );
    }
    let recorded = oracle.bytes;
    for seed in args.seed..args.seed.saturating_add(args.cases) {
        let case = inputs::random(seed);
        cases = cases.saturating_add(1);
        if let Some(d) = oracle.check(&case)? {
            report(&mut oracle, &case, &d, &args.save, started);
            return Ok(false);
        }
    }
    println!(
        "random: {} alike, frame bytes base {} tree {} ({})",
        args.cases,
        oracle.bytes.0.saturating_sub(recorded.0),
        oracle.bytes.1.saturating_sub(recorded.1),
        percent(
            oracle.bytes.0.saturating_sub(recorded.0),
            oracle.bytes.1.saturating_sub(recorded.1)
        )
    );
    println!(
        "alike: {cases} cases in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    Ok(true)
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("koh-oracle: {e}");
            ExitCode::from(2)
        }
    }
}
