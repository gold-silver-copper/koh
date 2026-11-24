//! What a session costs on each link, measured with the link's own counters: no test, and run
//! by hand (`cargo test --test link measure -- --ignored --nocapture`). It prints a table.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::time::{Duration, Instant};

use crate::net::Profile;
use crate::rig::{self, Rig};

/// Counts a folder's rounds (each new even number in its `generation`) until it is dropped.
struct Rounds(Arc<AtomicU64>, Arc<AtomicBool>);

impl Rounds {
    fn of(dir: &Path) -> Rounds {
        let (rounds, stop) = (
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicBool::new(false)),
        );
        let (count, stopped, file) = (rounds.clone(), stop.clone(), dir.join("generation"));
        std::thread::spawn(move || {
            // (A number is odd while its round is written: a round is the next even one.)
            let even = || {
                let number = fs::read_to_string(&file).unwrap_or_default();
                number.trim().parse::<u64>().ok().filter(|n| n % 2 == 0)
            };
            let mut last = even();
            while !stopped.load(SeqCst) {
                let number = even();
                if number.is_some() && number != last {
                    count.fetch_add(1, SeqCst);
                    last = number;
                }
                std::thread::sleep(Duration::from_micros(300));
            }
        });
        Rounds(rounds, stop)
    }

    fn so_far(&self) -> u64 {
        self.0.load(SeqCst)
    }
}

impl Drop for Rounds {
    fn drop(&mut self) {
        self.1.store(true, SeqCst);
    }
}

fn ms(time: Duration) -> String {
    format!("{:.1}", time.as_secs_f64() * 1000.0)
}

/// Typing and a build on a link of `name`: a row of each table.
async fn measured(name: &str) -> [String; 2] {
    let rig = Rig::start("measure", Profile::named(name), 1).await;
    let pane = rig.pane("s", &["cat"]);
    let mount = rig.mount("s", "a").await;
    rig::agrees(&pane, &mount.dir);
    let counts = || (rig.net.counts(mount.id), rig.net.counts(rig.server_id));

    // Sixty keys, one every 100 ms, each echoed by the terminal's own line: from the key's
    // write into the mirror until the mirror's screen has it.
    let (rounds, began, (down, up)) = (Rounds::of(&mount.dir), Instant::now(), counts());
    let (mut typed, mut echo) = (String::new(), Vec::new());
    for key in (b'a'..=b'z').cycle().take(60) {
        let at = Instant::now();
        mount.types(&[key]);
        typed.push(key as char);
        while !rig::screen(&mount.dir).contains(&typed) && at.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_micros(200));
        }
        echo.push(at.elapsed());
        tokio::time::sleep(Duration::from_millis(100).saturating_sub(at.elapsed())).await;
    }
    let (took, rounds) = (began.elapsed().as_secs_f64(), rounds.so_far().max(1));
    let (down, up) = (counts().0.bytes - down.bytes, counts().1.bytes - up.bytes);
    echo.sort();
    let typing = format!(
        "| {name} | {} | {} | {} | {} | {:.0} | {:.0} | {:.0} |",
        ms(echo[30]),
        ms(echo[53]),
        ms(echo[59]),
        rounds,
        down as f64 / rounds as f64,
        down as f64 / took,
        up as f64 / took,
    );

    // A build: a line every 20 ms for five seconds, written by a program of the session.
    let build = "i=0; while [ $i -lt 250 ]; do echo \"   Compiling crate-$i v0.1.$i (/src/crate-$i)\"; i=$((i+1)); sleep 0.02; done; echo build-is-d''one";
    let built = rig.pane("b", &["sh", "-c", &format!("read go; {build}; read stay")]);
    let mirror = rig.mount("b", "b").await;
    rig::agrees(&built, &mirror.dir);
    let counts = || (rig.net.counts(mirror.id), rig.net.counts(rig.server_id));
    let (rounds, held, began, (down, up)) = (
        Rounds::of(&mirror.dir),
        Rounds::of(&built),
        Instant::now(),
        counts(),
    );
    mirror.types(b"\n");
    rig::until("the build ends", Duration::from_secs(60), || {
        rig::screen(&built).contains("build-is-done")
    });
    let ended = Instant::now();
    rig::until(
        "the mirror shows the build's end",
        Duration::from_secs(60),
        || rig::screen(&mirror.dir).contains("build-is-done"),
    );
    let (behind, took) = (ended.elapsed(), began.elapsed().as_secs_f64());
    let (rounds, held) = (rounds.so_far().max(1), held.so_far());
    let (down, up) = (counts().0.bytes - down.bytes, counts().1.bytes - up.bytes);
    let build = format!(
        "| {name} | {:.1} | {:.1} | {:.0} | {:.0} | {:.0} | {} |",
        held as f64 / took,
        rounds as f64 / took,
        down as f64 / rounds as f64,
        down as f64 / took,
        up as f64 / took,
        ms(behind),
    );
    [typing, build]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement: it prints a table, and asserts nothing"]
async fn measure() {
    let mut rows = Vec::new();
    for name in [
        "clean",
        "25ms",
        "25ms-5%",
        "1Mbit",
        "256kbit",
        "dup-reorder",
    ] {
        rows.push(measured(name).await);
    }
    println!("Typing, a key every 100 ms, sixty keys.");
    println!(
        "| link | echo ms, median | p90 | most | rounds | bytes a round, to the client | bytes a second, to the client | to the server |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    rows.iter().for_each(|row| println!("{}", row[0]));
    println!("\nA build, a line every 20 ms for five seconds.");
    println!(
        "| link | rounds a second, the holder | the mirror | bytes a round, to the client | bytes a second, to the client | to the server | its end shown after, ms |"
    );
    println!("|---|---|---|---|---|---|---|");
    rows.iter().for_each(|row| println!("{}", row[1]));
}
