//! What proving costs: `cargo bench --bench carry`. Not a test: it prints, and asserts nothing
//! but that the mirror is the pane.
//!
//! A pane after a flood (`history` and `history.styled` of 4 MiB each) whose program prints on.
//! Each round the holder adds a line to both files in place and replaces a screen; the reader
//! proves all that is before the added bytes, by blake3 over both files, and sends what was
//! added. Printed: what blake3 alone takes over the two files, one time after the other and
//! each time after a rest; what a round takes to read and put together; how many rounds a
//! second that gives with the rest after each (nine times as long as the look took); and the
//! share of the time the reader then works.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use koh::carry::{Mirror, Reader};

const HISTORY: usize = 4 << 20;
const SECONDS: u64 = 10;

fn wrong(what: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{what:?}"))
}

/// One round of a holder: `generation` odd, what `change` does, `generation` even.
fn round(pane: &Path, number: &mut u64, change: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    fux::replace(
        pane.join("generation"),
        format!("{}\n", *number + 1).as_bytes(),
    )?;
    change()?;
    *number += 2;
    fux::replace(pane.join("generation"), format!("{number}\n").as_bytes())
}

fn main() -> io::Result<()> {
    let dir = std::env::temp_dir().join(format!("koh-carry-bench-{}", std::process::id()));
    let (pane, files) = (dir.join("pane"), ["history", "history.styled"]);
    fs::create_dir_all(pane.join("main"))?;
    let line = b"a line of a build's output, as long as such lines mostly are, more or less\n";
    let (screen, mut number) = (line.repeat(60), 0);
    round(&pane, &mut number, || {
        files
            .iter()
            .try_for_each(|name| fs::write(pane.join(name), line.repeat(HISTORY / line.len())))?;
        fux::replace(pane.join("main/screen"), &screen)
    })?;
    let add = |name: &&str| {
        OpenOptions::new()
            .append(true)
            .open(pane.join(name))?
            .write_all(line)
    };

    // blake3 alone, over the two files as they are read from the page cache: one time after
    // the other, and each time after a rest, as the reader has it (a machine may give a thread
    // that rests a slower core, or a slower clock).
    let (mut alone, mut rested) = (Vec::new(), Vec::new());
    for n in 0..70 {
        if n >= 50 {
            std::thread::sleep(Duration::from_millis(100));
        }
        let began = Instant::now();
        for name in files {
            blake3::Hasher::new().update_reader(File::open(pane.join(name))?)?;
        }
        if n < 50 { &mut alone } else { &mut rested }.push(began.elapsed());
    }

    let (mut reader, mut mirror) = (Reader::new(&pane), Mirror::make(&dir.join("mirror"))?);
    reader.has(&mirror.has()?, false).map_err(wrong)?;
    let (mut took, mut busy, began) = (Vec::new(), Duration::ZERO, Instant::now());
    while began.elapsed() < Duration::from_secs(SECONDS) {
        // The holder writes as fast as it is read: the next round is there when the reader looks.
        round(&pane, &mut number, || {
            files.iter().try_for_each(add)?;
            fux::replace(pane.join("main/screen"), &screen)
        })?;
        let sent = loop {
            let look = Instant::now();
            let sent = reader.round(false, look);
            busy += look.elapsed();
            match sent {
                Some(sent) => break (sent, look.elapsed()),
                None => std::thread::sleep(Duration::from_micros(50)),
            }
        };
        took.push(sent.1);
        for message in sent.0 {
            mirror.take(message, Instant::now()).map_err(wrong)?;
        }
    }
    let wall = began.elapsed();
    for name in files {
        if fs::read(pane.join(name))? != fs::read(dir.join("mirror").join(name))? {
            return Err(wrong(format!("the mirror's {name} is not the pane's")));
        }
    }
    fs::remove_dir_all(&dir)?;

    let ms = |all: &mut Vec<Duration>, at: usize| {
        all.sort();
        all.get(all.len() * at / 100)
            .map_or(0.0, |d| d.as_secs_f64() * 1000.0)
    };
    println!(
        "blake3 over two files of 4 MiB: {:.2} ms (median of 50; most {:.2})",
        ms(&mut alone, 50),
        ms(&mut alone, 99)
    );
    println!(
        "the same after a rest of 100 ms: {:.2} ms (median of 20; most {:.2})",
        ms(&mut rested, 50),
        ms(&mut rested, 99)
    );
    // (The first round is the whole folder: left out of the round's figures.)
    let mut rounds = took.split_off(1.min(took.len()));
    println!(
        "a round read and put together: {:.2} ms (median of {}; 99 in 100 under {:.2})",
        ms(&mut rounds, 50),
        rounds.len(),
        ms(&mut rounds, 99)
    );
    println!(
        "with the rest after each: {:.1} rounds a second",
        rounds.len() as f64 / wall.as_secs_f64()
    );
    println!(
        "the reader works {:.1}% of the time",
        100.0 * busy.as_secs_f64() / wall.as_secs_f64()
    );
    Ok(())
}
