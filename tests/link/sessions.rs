//! Sessions on the fault link: what a user would notice.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::time::{Duration, Instant};

use crate::net::Profile;
use crate::rig::{self, Rig};

/// (What each of these prints at its end is not in its text as it is typed: a test waits for
/// the output, which the command's echo does not have.)
///
/// A program that takes the whole screen, as an editor or a pager does: the alternate screen,
/// twelve frames drawn by the cursor's address, a last line, and it waits for a key to leave.
const FULL_SCREEN: &str = r"printf '\033[?1049h'; f=0; while [ $f -lt 12 ]; do printf '\033[H\033[2J'; r=1; while [ $r -le 23 ]; do printf '\033[%d;1Hframe %d row %d of a full screen' $r $f $r; r=$((r+1)); done; f=$((f+1)); sleep 0.05; done; printf '\033[24;1HFULL-%s' SCREEN; read key; printf '\033[?1049l'; echo left''-it";

/// A build that scrolls: six hundred lines, a pause after every tenth, as a compiler prints.
const BUILD: &str = "i=0; while [ $i -lt 600 ]; do echo \"   Compiling crate-$i v0.1.$i (/src/crate-$i)\"; i=$((i+1)); [ $((i % 10)) -eq 0 ] && sleep 0.02; done; echo build-is-d''one";

/// A shell session, a build that scrolls and a full-screen program on a link of `profile`: at
/// the end of each the mirror is the pane, every file of it.
async fn the_mirror_is_the_pane_on(name: &str, seed: u64) {
    let rig = Rig::start(name, Profile::named(name), seed).await;
    let pane = rig.pane("s", &["sh"]);
    let mount = rig.mount("s", "a").await;
    rig::agrees(&pane, &mount.dir);
    let shows = |what: &str| {
        let said = format!("{name}, seed {seed}: the mirror shows {what:?}");
        rig::until(&said, Duration::from_secs(25), || {
            rig::screen(&mount.dir).contains(what)
        });
    };
    // A shell session.
    mount.types(b"cd /; echo in-$(pwd)-$((6 * 7))\n");
    shows("in-/-42");
    mount.types(b"ls -d /dev/nul?; echo status-$?\n");
    shows("status-0");
    rig::agrees(&pane, &mount.dir);
    // A build that scrolls into history.
    mount.types(format!("{BUILD}\n").as_bytes());
    shows("build-is-done");
    rig::agrees(&pane, &mount.dir);
    let history = fs::read_to_string(mount.dir.join("history")).unwrap();
    assert!(history.contains("Compiling crate-0 v0.1.0") && history.contains("crate-500 "));
    // A full-screen program, and back from it.
    mount.types(format!("{FULL_SCREEN}\n").as_bytes());
    shows("FULL-SCREEN");
    rig::agrees(&pane, &mount.dir);
    let shown = || fs::read_link(mount.dir.join("shown")).unwrap();
    assert_eq!(shown(), Path::new("alt"));
    assert!(rig::screen(&mount.dir).contains("frame 11 row 23 of a full screen"));
    mount.types(b"\n");
    shows("left-it");
    rig::agrees(&pane, &mount.dir);
    assert_eq!(shown(), Path::new("main"));
    // (And the link did to the session's packets what its name says.)
    let (down, up) = (rig.net.counts(mount.id), rig.net.counts(rig.server_id));
    println!("{name}, seed {seed}: to the client {down:?}, to the server {up:?}");
    match name {
        "25ms-5%" => assert!(down.lost > 0 && up.lost > 0),
        "256kbit" | "1Mbit" => assert!(down.waited > 0),
        "dup-reorder" => assert!(down.duplicated > 0 && down.held_back > 0),
        _ => {}
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mirror_is_the_pane_on_a_clean_link() {
    the_mirror_is_the_pane_on("clean", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mirror_is_the_pane_at_25_ms_each_way() {
    the_mirror_is_the_pane_on("25ms", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mirror_is_the_pane_at_25_ms_with_5_percent_lost() {
    the_mirror_is_the_pane_on("25ms-5%", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mirror_is_the_pane_at_1_mbit() {
    the_mirror_is_the_pane_on("1Mbit", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mirror_is_the_pane_at_256_kbit() {
    the_mirror_is_the_pane_on("256kbit", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_mirror_is_the_pane_through_duplicates_and_reordering() {
    the_mirror_is_the_pane_on("dup-reorder", 1).await;
}

/// A paste of `bytes` into a program that reads its terminal raw, on a link of `profile`: what
/// the program read is what was pasted, every byte once and in its order.
async fn a_paste_arrives_whole_on(name: &str, seed: u64, bytes: usize) {
    let rig = Rig::start(name, Profile::named(name), seed).await;
    let out = rig.file("out");
    rig.pane("s", &rig::reads_into(&out));
    let mount = rig.mount("s", "a").await;
    rig::until("the program is ready", Duration::from_secs(20), || {
        rig::screen(&mount.dir).contains("READY")
    });
    let pasted: Vec<u8> = (0..bytes as u64 / 16).flat_map(rig::line).collect();
    let (paste, into, began) = (pasted.clone(), mount.dir.join("in"), Instant::now());
    let pasting = std::thread::spawn(move || fs::write(into, paste).unwrap());
    let what = format!("{name}, seed {seed}: the program read all of the paste");
    rig::until(&what, Duration::from_secs(28), || {
        fs::metadata(&out).is_ok_and(|out| out.len() >= pasted.len() as u64)
    });
    let (took, up) = (began.elapsed(), rig.net.counts(rig.server_id));
    println!("{name}, seed {seed}: {bytes} bytes in {took:?}; to the server {up:?}");
    assert!(up.lost + up.duplicated.min(up.held_back) > 20, "{up:?}");
    pasting.join().unwrap();
    let read = fs::read(&out).unwrap();
    let left_out = rig::stretches(&read, &pasted);
    assert!(
        read == pasted,
        "{name}, seed {seed}: {} bytes read: {left_out:?}",
        read.len()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paste_of_megabytes_arrives_whole_through_5_percent_loss() {
    a_paste_arrives_whole_on("25ms-5%", 1, 2 << 20).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paste_of_megabytes_arrives_whole_through_duplicates_and_reordering() {
    a_paste_arrives_whole_on("dup-reorder", 1, 3 << 20).await;
}

/// What is typed, a line every 10 ms, through 5% loss while the link is gone three times, for
/// 2 to 10 s: nothing of it arrives twice, what arrives is in its order, and its end arrives.
/// (No link dies of ten seconds: nothing is left out either, and that is asserted too.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_is_typed_through_loss_and_blackouts_arrives_once_and_in_order() {
    let seed = 1;
    let rig = Rig::start("blackouts", Profile::named("25ms-5%"), seed).await;
    let out = rig.file("out");
    rig.pane("s", &rig::reads_into(&out));
    let mount = rig.mount("s", "a").await;
    rig::until("the program is ready", Duration::from_secs(20), || {
        rig::screen(&mount.dir).contains("READY")
    });
    let typing = Arc::new(AtomicBool::new(true));
    let (goes_on, into) = (typing.clone(), mount.dir.join("in"));
    let typist = std::thread::spawn(move || {
        let mut keys = fs::OpenOptions::new().write(true).open(into).unwrap();
        let mut all = Vec::new();
        for line in (0..).map(rig::line) {
            if !goes_on.load(SeqCst) {
                break;
            }
            keys.write_all(&line).unwrap();
            all.extend(line);
            std::thread::sleep(Duration::from_millis(10));
        }
        all
    });
    // Gone for 2 s, for 10 s and for a time between, in the seed's order.
    let mut draws = rig::Draws(seed);
    let mut gone = [2000, 2000 + draws.below(2000), 10_000];
    gone.swap(0, draws.below(3) as usize);
    gone.swap(1, 1 + draws.below(2) as usize);
    let read = || fs::metadata(&out).map_or(0, |out| out.len());
    for gone in gone {
        tokio::time::sleep(Duration::from_millis(300 + draws.below(500))).await;
        rig.net.black_hole(Duration::from_millis(gone));
        tokio::time::sleep(Duration::from_millis(gone)).await;
        let (back, had) = (Instant::now(), read());
        // (Within three or four seconds as a rule: QUIC probes ever more seldom while nothing
        // answers, and a probe that is lost too is another wait as long as all before it.)
        rig::until("the program reads on", Duration::from_secs(25), || {
            read() > had
        });
        let took = back.elapsed();
        println!("seed {seed}: gone for {gone} ms, and typed again {took:?} after it was back");
    }
    typing.store(false, SeqCst);
    let (all, up) = (typist.join().unwrap(), rig.net.counts(rig.server_id));
    assert!(up.lost > 0 && up.black_holed > 0, "{up:?}");
    rig::until(
        "the end of what was typed arrives",
        Duration::from_secs(10),
        || rig::tail(&out, 16) == all[all.len() - 16..],
    );
    let read = fs::read(&out).unwrap();
    let left_out = rig::stretches(&read, &all);
    assert_eq!(
        left_out,
        Ok(0),
        "seed {seed}: {} typed, {} read",
        all.len(),
        read.len()
    );
}

/// A link that is gone for forty seconds, and back. koh notices after thirty seconds of
/// silence, dials for five seconds at a time and waits five between two (the README's words):
/// so it is back within ten seconds of the path, and a round. The mirror is then the pane as it
/// is now, and what was typed while koh said there was no link is typed, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_gone_for_forty_seconds_is_back_within_the_readmes_time() {
    let rig = Rig::start("forty", Profile::named("25ms"), 1).await;
    let pane = rig.pane("s", &["sh"]);
    let mount = rig.mount("s", "a").await;
    rig::agrees(&pane, &mount.dir);
    let gone = Instant::now();
    rig.net.black_hole(Duration::from_secs(40));
    // The session goes on without its client: the pane changes, the mirror stays.
    fs::write(pane.join("in"), "echo while-$((6 * 7))-away\n").unwrap();
    tokio::time::sleep(Duration::from_secs(36)).await;
    assert!(!rig::screen(&mount.dir).contains("while-42-away"));
    mount.types(b"echo held-$((6 * 7))-typed\n");
    tokio::time::sleep(Duration::from_secs(40).saturating_sub(gone.elapsed())).await;
    let back = Instant::now();
    rig::until(
        "the mirror shows the present",
        Duration::from_secs(12),
        || rig::screen(&mount.dir).contains("while-42-away"),
    );
    println!(
        "the mirror is the present {:?} after the link was back",
        back.elapsed()
    );
    rig::until("what was held is typed", Duration::from_secs(5), || {
        rig::screen(&mount.dir).contains("held-42-typed")
    });
    rig::agrees(&pane, &mount.dir);
    assert_eq!(rig::screen(&pane).matches("held-42-typed").count(), 1);
}

/// A session whose history is `lines` lines of `seq`, and a client that comes anew to it on a
/// link of `profile`: how long until its mirror has a first round (until then it shows
/// nothing), or none in `long`; and the bytes the link carried to it.
async fn a_fresh_attach(profile: Profile, lines: u32, long: Duration) -> (Option<Duration>, u64) {
    let rig = Rig::start("fresh", profile, 1).await;
    let pane = rig.pane("s", &["sh"]);
    fs::write(
        pane.join("in"),
        format!("seq 1 {lines}; echo all-pr''inted\n"),
    )
    .unwrap();
    rig::until("the history is there", Duration::from_secs(20), || {
        rig::screen(&pane).contains("all-printed")
    });
    let began = Instant::now();
    let mount = rig.mount_now("s", "a").await;
    while !mount.dir.join("generation").is_file() && began.elapsed() < long {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let took = mount
        .dir
        .join("generation")
        .is_file()
        .then(|| began.elapsed());
    if took.is_some() {
        rig::agrees(&pane, &mount.dir);
    }
    (took, rig.net.counts(mount.id).bytes)
}

/// A megabyte of history is two megabytes of files, and at 256 kbit/s they take a minute: the
/// attach completes, at the link's pace.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "takes a minute: megabytes at 32 kB a second"]
async fn a_fresh_attach_to_megabytes_of_history_at_256_kbit_completes() {
    let (took, bytes) =
        a_fresh_attach(Profile::named("256kbit"), 150_000, Duration::from_secs(120)).await;
    println!("a first round after {took:?}: {bytes} bytes to the client");
    // (What the link carries in that time, and a tenth more.)
    let took = took.expect("a first round in two minutes");
    assert!(
        took.as_secs_f64() < bytes as f64 / 32_000.0 * 1.1 + 2.0,
        "{took:?}"
    );
}

/// KOH'S FAULT (report 15, the first): a client that comes anew sees nothing until every file
/// of the session has arrived, the history among them and that twice (`history` and
/// `history.styled`). Here 229 kB of history are 14 s without a screen at 256 kbit/s; a
/// megabyte is a minute, and a history at fux's bound is six. What a user would expect: the
/// screen at once, the history after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "koh's fault: the first round carries the whole history before a screen is shown"]
async fn a_fresh_attach_on_a_slow_link_shows_the_screen_before_the_history() {
    let long = Duration::from_secs(60);
    let (took, bytes) = a_fresh_attach(Profile::named("256kbit"), 40_000, long).await;
    println!("a first round after {took:?}: {bytes} bytes to the client");
    assert!(
        took.is_some_and(|took| took < Duration::from_secs(3)),
        "{took:?}"
    );
}

/// KOH'S FAULT (report 15, the second): on a link slower than about 70 kbit/s a session with
/// a file of more than 256 KiB cannot be attached to at all. A file comes in messages of up
/// to 256 KiB, the mirror takes a link for broken when thirty seconds bring no whole message
/// (`carry::STILL`), and at 8 kB a second such a message takes thirty-three: the round is
/// thrown away, koh attaches anew, and so for ever. At 96 kbit/s the same attach takes a minute.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "koh's fault: a round is thrown away while its bytes still arrive, for ever"]
async fn a_fresh_attach_at_64_kbit_completes() {
    let profile = Profile {
        rate: Some(64_000),
        queue: Duration::from_secs(1),
        ..Profile::named("25ms")
    };
    // (700 kB of files: a minute and a half at the link's pace.)
    let (took, bytes) = a_fresh_attach(profile, 60_000, Duration::from_secs(180)).await;
    println!("a first round after {took:?}: {bytes} bytes to the client");
    assert!(
        took.is_some(),
        "no first round in three minutes: {bytes} bytes were carried"
    );
}
