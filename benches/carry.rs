//! What following a pane costs a server: `cargo bench --bench carry`. Not a test: it prints, and
//! asserts nothing but that the mirror is the pane after each part.
//!
//! A pane after a flood (`history` and `history.styled` of 4 MiB each) whose program prints on:
//! a holder's round adds a line to both files in place and replaces a screen, and the reader
//! must prove all that is before the added bytes before it sends them. The holder writes as
//! fux's does, on its own time, while the reader reads; the reader looks when `generation` is
//! another file, as a server does. Printed, for a holder that waits to be read, one that
//! writes every 5 ms and one every 25 ms: the rounds a second the mirror got, the reads thrown
//! away (the folder's number moved under them), what a round took to read, and the share of
//! the time the reader worked. Then how long a change that needs no proof (a key's echo on the
//! screen, 10 ms after a line scrolled) waits for its round. First, for the list a client
//! sends: blake3 over the two files, one time after the other and each time after a rest.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

use koh::carry::{Look, Mirror, Reader};
use koh::proto::ToMirror;

const HISTORY: usize = 4 << 20;
const FILES: [&str; 2] = ["history", "history.styled"];
const LINE: &[u8] = b"a line of a build's output, as long as such lines mostly are, more or less\n";
/// How long each part runs.
const PART: Duration = Duration::from_secs(4);

fn wrong(what: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{what:?}"))
}

/// A pane's folder written as fux's holder writes one.
struct Holder {
    pane: PathBuf,
    number: u64,
}

impl Holder {
    /// One round: `generation` odd, a line added to the history files if the round scrolls, a
    /// screen replaced, `generation` even.
    fn round(&mut self, scrolls: bool) -> io::Result<()> {
        let number = |number: u64| {
            fux::replace(
                self.pane.join("generation"),
                format!("{number}\n").as_bytes(),
            )
        };
        number(self.number + 1)?;
        for name in FILES.iter().filter(|_| scrolls) {
            OpenOptions::new()
                .append(true)
                .open(self.pane.join(name))?
                .write_all(LINE)?;
        }
        let screen = [LINE.repeat(59), format!("{}\n", self.number).into_bytes()].concat();
        fux::replace(self.pane.join("main/screen"), &screen)?;
        self.number += 2;
        number(self.number)
    }
}

/// What a reader made of a holder's rounds.
#[derive(Default)]
struct Seen {
    rounds: usize,
    reads: usize,
    thrown: usize,
    busy: Duration,
    took: Vec<Duration>,
    waits: Vec<Duration>,
}

/// Rounds a holder writes, each with its number and the moment before it was written: how
/// long until the mirror has it.
type Awaited = Mutex<VecDeque<(u64, Instant)>>;

struct Line {
    pane: PathBuf,
    reader: Reader,
    mirror: Mirror,
    /// The `generation` that was there before the last look that read a round.
    seen: Option<(u64, i64, i64)>,
}

impl Line {
    /// Looks at the pane as a server does until `ends` says so: when `generation` is another
    /// file, and not while the reader rests. What it reads goes into the mirror.
    fn follow(
        &mut self,
        awaited: &Awaited,
        mut ends: impl FnMut(&Seen) -> bool,
    ) -> io::Result<Seen> {
        let mut seen = Seen::default();
        while !ends(&seen) {
            let generation = fs::metadata(self.pane.join("generation")).ok();
            let stamp = generation.map(|file| (file.ino(), file.mtime(), file.mtime_nsec()));
            if stamp == self.seen {
                sleep(Duration::from_micros(500));
                continue;
            }
            let began = Instant::now();
            let look = self.reader.look(false, began);
            let took = began.elapsed();
            seen.busy += took;
            match look {
                Look::Round(round) => {
                    (seen.reads, self.seen) = (seen.reads + 1, stamp);
                    let Some(ToMirror::Round(number)) = round.first() else {
                        continue;
                    };
                    let number = *number;
                    seen.rounds += 1;
                    seen.took.push(took);
                    for message in round {
                        self.mirror.take(message, Instant::now()).map_err(wrong)?;
                    }
                    let mut awaited = awaited.lock().map_err(wrong)?;
                    while let Some((_, whole)) = awaited.pop_front_if(|(round, _)| *round <= number)
                    {
                        seen.waits.push(whole.elapsed());
                    }
                }
                Look::Moved => (seen.reads, seen.thrown) = (seen.reads + 1, seen.thrown + 1),
                Look::Odd => sleep(Duration::from_micros(100)),
                Look::Rests(until) => sleep(until.saturating_duration_since(Instant::now())),
            }
        }
        Ok(seen)
    }

    /// The pane is still: the mirror is given what it lacks, and must then be the pane.
    fn settle(&mut self) -> io::Result<()> {
        let until = Instant::now() + Duration::from_secs(2);
        self.seen = None;
        self.follow(&Awaited::default(), |seen| {
            seen.reads > seen.thrown || Instant::now() > until
        })?;
        for name in FILES.iter().chain(&["main/screen"]) {
            if fs::read(self.pane.join(name))?
                != fs::read(self.pane.with_file_name("mirror").join(name))?
            {
                return Err(wrong(format!("the mirror's {name} is not the pane's")));
            }
        }
        Ok(())
    }

    /// A part of the bench: the holder writes as `holder` says, on a thread of its own, until
    /// it is told to stop, while the pane is followed for as long as a part runs. With
    /// `waits`, how long the rounds the holder names waited is printed too.
    fn part(
        &mut self,
        what: &str,
        waits: bool,
        holder: impl FnOnce(&AtomicBool, &Awaited) -> io::Result<()> + Send,
    ) -> io::Result<()> {
        let (stop, awaited, began) = (AtomicBool::new(false), Awaited::default(), Instant::now());
        let seen = std::thread::scope(|scope| {
            let writer = scope.spawn(|| holder(&stop, &awaited));
            let seen = self.follow(&awaited, |_| began.elapsed() > PART);
            stop.store(true, Ordering::Relaxed);
            writer.join().map_err(wrong)??;
            seen
        })?;
        let wall = began.elapsed().as_secs_f64();
        self.settle()?;
        let (mut took, mut waited) = (seen.took, seen.waits);
        println!(
            "{what}: {:.1} rounds a second; {} of {} reads thrown away; a round {:.2} ms to read; the reader works {:.1}% of the time",
            seen.rounds as f64 / wall,
            seen.thrown,
            seen.reads,
            ms(&mut took, 50),
            100.0 * seen.busy.as_secs_f64() / wall
        );
        if waits {
            let (median, most) = (ms(&mut waited, 50), ms(&mut waited, 100));
            println!(
                "    the echo waited {median:.2} ms for its round (median of {}; most {most:.2})",
                waited.len()
            );
        }
        Ok(())
    }
}

/// The time so many in a hundred of them are within, in milliseconds.
fn ms(all: &mut [Duration], of_100: usize) -> f64 {
    all.sort();
    let at = (all.len() * of_100 / 100).min(all.len().saturating_sub(1));
    all.get(at).map_or(0.0, |time| time.as_secs_f64() * 1000.0)
}

fn main() -> io::Result<()> {
    let dir = std::env::temp_dir().join(format!("koh-carry-bench-{}", std::process::id()));
    let pane = dir.join("pane");
    fs::create_dir_all(pane.join("main"))?;
    for name in FILES {
        fs::write(pane.join(name), LINE.repeat(HISTORY / LINE.len()))?;
    }
    let mut holder = Holder {
        pane: pane.clone(),
        number: 0,
    };
    holder.round(false)?;

    // blake3 alone, over the two files as they are read from the page cache: one time after
    // the other, and each time after a rest (a machine gives a thread that rests a slower
    // clock, and takes some rests to get there: the first ten are not counted).
    let (mut alone, mut rested) = (Vec::new(), Vec::new());
    for n in 0..80 {
        if n >= 50 {
            sleep(Duration::from_millis(100));
        }
        let began = Instant::now();
        for name in FILES {
            blake3::Hasher::new().update_reader(File::open(pane.join(name))?)?;
        }
        match n {
            0..50 => alone.push(began.elapsed()),
            50..60 => {}
            _ => rested.push(began.elapsed()),
        }
    }
    let (alone, rested) = (ms(&mut alone, 50), ms(&mut rested, 50));
    println!(
        "blake3 over two files of 4 MiB: {alone:.2} ms one time after the other, {rested:.2} ms each time after a rest of 100 ms"
    );

    let (mut reader, mut mirror) = (Reader::new(&pane), Mirror::make(&dir.join("mirror"))?);
    reader.has(&mirror.has()?, false).map_err(wrong)?;
    let mut line = Line {
        pane,
        reader,
        mirror,
        seen: None,
    };
    line.settle()?;

    // (Each round is written when the one before it is in the mirror.)
    line.part("a holder that waits to be read", false, |stop, awaited| {
        while !stop.load(Ordering::Relaxed) {
            // (Said before it is written: the reader may have the round before the next line.)
            awaited
                .lock()
                .map_err(wrong)?
                .push_back((holder.number + 2, Instant::now()));
            holder.round(true)?;
            while !stop.load(Ordering::Relaxed) && !awaited.lock().map_err(wrong)?.is_empty() {
                sleep(Duration::from_micros(200));
            }
        }
        Ok(())
    })?;
    for every in [5, 25] {
        line.part(
            &format!("a holder that writes every {every} ms"),
            false,
            |stop, _| {
                while !stop.load(Ordering::Relaxed) {
                    let began = Instant::now();
                    holder.round(true)?;
                    sleep(Duration::from_millis(every).saturating_sub(began.elapsed()));
                }
                Ok(())
            },
        )?;
    }
    line.part(
        "a line every 100 ms, and a key's echo 10 ms after it",
        true,
        |stop, awaited| {
            while !stop.load(Ordering::Relaxed) {
                holder.round(true)?;
                sleep(Duration::from_millis(10));
                awaited
                    .lock()
                    .map_err(wrong)?
                    .push_back((holder.number + 2, Instant::now()));
                holder.round(false)?;
                sleep(Duration::from_millis(90));
            }
            Ok(())
        },
    )?;
    fs::remove_dir_all(&dir)
}
