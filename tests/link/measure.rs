//! What a session costs on each link, measured with the link's own counters and at the
//! client's terminal: no test, and run by hand (`cargo test --release --test link measure --
//! --ignored --nocapture`).

use std::time::{Duration, Instant};

use crate::net::Profile;
use crate::rig::{self, Rig};

fn ms(time: Duration) -> String {
    format!("{:.1}", time.as_secs_f64() * 1000.0)
}

/// Typing and a build on a link of `name`: a row of each table.
async fn measured(name: &str) -> [String; 2] {
    let rig = Rig::start("measure", profile(name), 1).await;
    let pane = rig.pane("s", &["cat"]);
    let client = rig.connect("s", "a").await;
    rig::screen_agrees(&pane, &client);
    let counts = || (rig.net.counts(client.id), rig.net.counts(rig.server_id));

    // Sixty keys, one every 100 ms, each echoed by the terminal's own line: from the key's
    // write into the client's terminal until koh has written its echo there.
    let (began, (down, up)) = (Instant::now(), counts());
    let mut echo = Vec::new();
    for key in (b'a'..=b'z').cycle().take(60) {
        let (at, before) = (Instant::now(), client.raw().len());
        client.types(&[key]);
        while !client.raw()[before..].contains(&key) && at.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_micros(200));
        }
        echo.push(at.elapsed());
        tokio::time::sleep(Duration::from_millis(100).saturating_sub(at.elapsed())).await;
    }
    let took = began.elapsed().as_secs_f64();
    let (down, up) = (counts().0.bytes - down.bytes, counts().1.bytes - up.bytes);
    echo.sort();
    let typing = format!(
        "| {name} | {} | {} | {} | {:.0} | {:.0} |",
        ms(echo[30]),
        ms(echo[53]),
        ms(echo[59]),
        down as f64 / took,
        up as f64 / took,
    );

    // A build: a line every 20 ms for five seconds, written by a program of the session.
    let build = "i=0; while [ $i -lt 250 ]; do echo \"   Compiling crate-$i v0.1.$i (/src/crate-$i)\"; i=$((i+1)); sleep 0.02; done; echo build-is-d''one";
    let built = rig.pane("b", &["sh", "-c", &format!("read go; {build}; read stay")]);
    let client_b = rig.connect("b", "b").await;
    rig::screen_agrees(&built, &client_b);
    let counts = || (rig.net.counts(client_b.id), rig.net.counts(rig.server_id));
    let (began, (down, up)) = (Instant::now(), counts());
    client_b.types(b"\n");
    rig::until("the build ends", Duration::from_secs(60), || {
        rig::screen(&built).contains("build-is-done")
    });
    let ended = Instant::now();
    rig::until(
        "the client shows the build's end",
        Duration::from_secs(60),
        || client_b.raw().windows(13).any(|at| at == b"build-is-done"),
    );
    let (behind, took) = (ended.elapsed(), began.elapsed().as_secs_f64());
    let (down, up) = (counts().0.bytes - down.bytes, counts().1.bytes - up.bytes);
    let build = format!(
        "| {name} | {:.0} | {:.0} | {} |",
        down as f64 / took,
        up as f64 / took,
        ms(behind),
    );
    [typing, build]
}

/// The six links of the tests, and the slowest a session is used on: 64 kbit/s, 25 ms each way.
fn profile(name: &str) -> Profile {
    match name {
        "64kbit" => Profile {
            rate: Some(64_000),
            queue: Duration::from_secs(1),
            ..Profile::named("25ms")
        },
        name => Profile::named(name),
    }
}

/// A flood on a link of `name`: `seq 1 400000`, and how long after the session's pane showed
/// its end the client's terminal did; and a key's echo while it floods, on a row of its own.
async fn flooded(name: &str) -> String {
    let rig = Rig::start("flood", profile(name), 1).await;
    let floods = "read go; seq 1 400000; echo the-flood-is-o''ver; exec sleep 600";
    let pane = rig.pane("s", &["sh", "-c", floods]);
    let client = rig.connect("s", "a").await;
    rig::screen_agrees(&pane, &client);
    client.types(b"\n");
    rig::until("the pane shows the end", Duration::from_secs(120), || {
        rig::screen(&pane).contains("the-flood-is-over")
    });
    let ended = Instant::now();
    rig::until("the client shows the end", Duration::from_secs(120), || {
        client
            .raw()
            .windows(17)
            .any(|at| at == b"the-flood-is-over")
    });
    let late = ended.elapsed();
    // (One writer for the flood and the echo, so that no sequence is cut by another.)
    let echoes = r#"
import os, select, sys, tty
tty.setraw(0)
out = sys.stdout.buffer
out.write(b'\x1b[2;24r\x1b[2;1H'); out.flush()
n = 1
while True:
    if select.select([0], [], [], 0)[0]:
        k = os.read(0, 1)
        if not k: break
        out.write(b'\x1b7\x1b[1;1H===ECHO-' + k + b'===\x1b8')
        out.flush()
    out.write(''.join(f'{i}\r\n' for i in range(n, n + 200)).encode()); out.flush()
    n = (n + 200) % 2000000 + 1
"#;
    rig.pane("e", &["python3", "-c", echoes]);
    let client = rig.connect("e", "b").await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut echo = Vec::new();
    for key in b'A'..=b'P' {
        let want = format!("===ECHO-{}===", key as char);
        let at = Instant::now();
        client.types(&[key]);
        // (On the terminal's screen: of a key's echo the viewer draws the one cell that changed.)
        rig::until(&want, Duration::from_secs(30), || {
            client.screen().contains(&want)
        });
        echo.push(at.elapsed());
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    echo.sort();
    // A whole screen of cells that each have a colour of their own, as a picture drawn in text
    // has: some 40 KB for the viewer to send, at once.
    let paints = r#"read go; python3 -c "
import sys
for r in range(23):
    sys.stdout.write(''.join(f'\x1b[38;2;{r * 11};{c * 3};{(r * c) % 256}m#' for c in range(80)) + '\r\n')
sys.stdout.write('\x1b[mPAINTED-'); sys.stdout.write('ALL')
"; exec sleep 600"#;
    let painted = rig.pane("p", &["sh", "-c", paints]);
    let client = rig.connect("p", "a").await;
    rig::screen_agrees(&painted, &client);
    let at = Instant::now();
    client.types(b"\n");
    rig::until("the screen is painted", Duration::from_secs(60), || {
        client.screen().contains("PAINTED-ALL")
    });
    format!(
        "| {name} | {} | {} | {} | {} | {} |",
        ms(late),
        ms(echo[8]),
        ms(echo[14]),
        ms(echo[15]),
        ms(at.elapsed())
    )
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
        "64kbit",
        "dup-reorder",
    ] {
        rows.push(measured(name).await);
    }
    println!("Typing, a key every 100 ms, sixty keys.");
    println!(
        "| link | echo ms, median | p90 | most | bytes a second, to the client | to the server |"
    );
    println!("|---|---|---|---|---|---|");
    rows.iter().for_each(|row| println!("{}", row[0]));
    println!("\nA build, a line every 20 ms for five seconds.");
    println!("| link | bytes a second, to the client | to the server | its end shown after, ms |");
    println!("|---|---|---|---|");
    rows.iter().for_each(|row| println!("{}", row[1]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement: it prints a table, and asserts nothing"]
async fn measure_a_flood() {
    let mut rows = Vec::new();
    for name in ["25ms", "256kbit", "64kbit"] {
        rows.push(flooded(name).await);
    }
    println!(
        "A flood: `seq 1 400000`; a key's echo during one that does not end; a whole screen painted."
    );
    println!(
        "| link | the flood's end shown after, ms | a key's echo, ms, median | p90 | most | a screen of 1,840 coloured cells drawn after, ms |"
    );
    println!("|---|---|---|---|---|---|");
    rows.iter().for_each(|row| println!("{row}"));
}
