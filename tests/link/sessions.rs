//! Sessions on the fault link: what a user would notice of one, and what a link that is cut
//! at any byte must not leave behind.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::time::{Duration, Instant};

use iroh::endpoint::{Connection, RecvStream, SendStream};
use koh::proto::{
    Attach, Attached, MAX_CTRL, Reply, Request, VIEW_FRAME, ViewInput, ViewOutput, recv_msg,
    send_msg,
};

use crate::net::Profile;
use crate::rig::{self, Rig};

/// A program that takes the whole screen, as an editor or a pager does: the alternate screen,
/// twelve frames drawn by the cursor's address, a last line, and it waits for a key to leave.
const FULL_SCREEN: &str = r"printf '\033[?1049h'; f=0; while [ $f -lt 12 ]; do printf '\033[H\033[2J'; r=1; while [ $r -le 23 ]; do printf '\033[%d;1Hframe %d row %d of a full screen' $r $f $r; r=$((r+1)); done; f=$((f+1)); sleep 0.05; done; printf '\033[24;1HFULL-%s' SCREEN; read key; printf '\033[?1049l'; echo left''-it";

/// A build that scrolls: six hundred lines, a pause after every tenth, as a compiler prints.
const BUILD: &str = "i=0; while [ $i -lt 600 ]; do echo \"   Compiling crate-$i v0.1.$i (/src/crate-$i)\"; i=$((i+1)); [ $((i % 10)) -eq 0 ] && sleep 0.02; done; echo build-is-d''one";

/// A shell session, a build that scrolls, a full-screen program, and a resize on a link of
/// `profile`: at the end of each the client's terminal screen matches the server pane.
async fn the_screen_is_right_on(name: &str, seed: u64) {
    let rig = Rig::start(name, Profile::named(name), seed).await;
    let pane = rig.pane("s", &["sh"]);
    let client = rig.connect("s", "a").await;
    rig::screen_agrees(&pane, &client);
    let shows = |what: &str| {
        let said = format!("{name}, seed {seed}: client screen shows {what:?}");
        rig::until(&said, Duration::from_secs(25), || {
            client.screen().contains(what)
        });
    };
    // A shell session.
    client.types(b"cd /; echo in-$(pwd)-$((6 * 7))\n");
    shows("in-/-42");
    client.types(b"ls -d /dev/nul?; echo status-$?\n");
    shows("status-0");
    rig::screen_agrees(&pane, &client);
    // A build that scrolls into history on the server.
    client.types(format!("{BUILD}\n").as_bytes());
    shows("build-is-done");
    rig::screen_agrees(&pane, &client);
    let history = fs::read_to_string(pane.join("history")).unwrap();
    assert!(history.contains("Compiling crate-0 v0.1.0") && history.contains("crate-500 "));
    // A full-screen program, and back from it.
    client.types(format!("{FULL_SCREEN}\n").as_bytes());
    shows("FULL-SCREEN");
    rig::screen_agrees(&pane, &client);
    assert_eq!(fs::read_link(pane.join("shown")).unwrap(), Path::new("alt"));
    assert!(client.screen().contains("frame 11 row 23 of a full screen"));
    client.types(b"\n");
    shows("left-it");
    rig::screen_agrees(&pane, &client);
    assert_eq!(
        fs::read_link(pane.join("shown")).unwrap(),
        Path::new("main")
    );
    // Resize the client terminal and verify the server pane takes the new size.
    client.resize(100, 30);
    rig::until("pane resized to 100 30", Duration::from_secs(10), || {
        fs::read_to_string(pane.join("size"))
            .unwrap_or_default()
            .trim()
            == "100 30"
    });
    client.types(b"echo after-re''size\n");
    shows("after-resize");
    rig::screen_agrees(&pane, &client);

    let (down, up) = (rig.net.counts(client.id), rig.net.counts(rig.server_id));
    println!("{name}, seed {seed}: to the client {down:?}, to the server {up:?}");
    match name {
        "25ms-5%" => assert!(down.lost > 0 && up.lost > 0),
        "256kbit" | "1Mbit" => assert!(down.waited > 0),
        "dup-reorder" => assert!(down.duplicated > 0 && down.held_back > 0),
        _ => {}
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_screen_is_right_on_a_clean_link() {
    the_screen_is_right_on("clean", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_screen_is_right_at_25_ms_each_way() {
    the_screen_is_right_on("25ms", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_screen_is_right_at_25_ms_with_5_percent_lost() {
    the_screen_is_right_on("25ms-5%", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_screen_is_right_at_1_mbit() {
    the_screen_is_right_on("1Mbit", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_screen_is_right_at_256_kbit() {
    the_screen_is_right_on("256kbit", 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_screen_is_right_through_duplicates_and_reordering() {
    the_screen_is_right_on("dup-reorder", 1).await;
}

/// A paste of `bytes` into a program that reads its terminal raw, on a link of `profile`: what
/// the program read is what was pasted, every byte once and in its order.
async fn a_paste_arrives_whole_on(name: &str, seed: u64, bytes: usize) {
    let rig = Rig::start(name, Profile::named(name), seed).await;
    let out = rig.file("out");
    rig.pane("s", &rig::reads_into(&out));
    let client = rig.connect("s", "a").await;
    rig::until("the program is ready", Duration::from_secs(20), || {
        client.screen().contains("READY")
    });
    let pasted: Vec<u8> = (0..bytes as u64 / 16).flat_map(rig::line).collect();
    let (paste, master, began) = (pasted.clone(), client.master_clone(), Instant::now());
    let pasting = std::thread::spawn(move || rig::write_all_pty(&master, &paste));
    let what = format!("{name}, seed {seed}: the program read all of the paste");
    rig::until(&what, Duration::from_secs(40), || {
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
    a_paste_arrives_whole_on("25ms-5%", 1, 1 << 20).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paste_of_megabytes_arrives_whole_through_duplicates_and_reordering() {
    a_paste_arrives_whole_on("dup-reorder", 1, 1 << 20).await;
}

/// What is typed, a line every 10 ms, through 5% loss while the link is gone three times, for
/// 2 to 10 s: nothing of it arrives twice, what arrives is in its order, and its end arrives.
/// The two short times nothing is lost; the long one costs what was typed into a link that
/// was not yet known to be gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_is_typed_through_loss_and_blackouts_arrives_once_and_in_order() {
    let seed = 1;
    let rig = Rig::start("blackouts", Profile::named("25ms-5%"), seed).await;
    let out = rig.file("out");
    rig.pane("s", &rig::reads_into(&out));
    let client = rig.connect("s", "a").await;
    rig::until("the program is ready", Duration::from_secs(20), || {
        client.screen().contains("READY")
    });
    let typing = Arc::new(AtomicBool::new(true));
    let (goes_on, master) = (typing.clone(), client.master_clone());
    let typist = std::thread::spawn(move || {
        let mut all = Vec::new();
        for line in (0..).map(rig::line) {
            if !goes_on.load(SeqCst) {
                break;
            }
            rig::write_all_pty(&master, &line);
            all.extend(line);
            std::thread::sleep(Duration::from_millis(10));
        }
        all
    });
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
    // What was on its way when a link died may be lost: a stretch for each time the link was
    // gone for longer than it may be silent (eight seconds), and no more. Nothing came twice.
    let read = fs::read(&out).unwrap();
    let left_out = rig::stretches(&read, &all);
    assert!(
        left_out.as_ref().is_ok_and(|stretches| *stretches <= 1),
        "seed {seed}: {} typed, {} read: {left_out:?}",
        all.len(),
        read.len()
    );
}

/// A link gone for forty seconds, and back: koh shows the disconnected notice, holds typing,
/// redials automatically, paints the fresh screen within seconds of the path returning, and
/// types the held command once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_gone_for_forty_seconds_is_back_within_seconds() {
    let rig = Rig::start("forty", Profile::named("25ms"), 1).await;
    let pane = rig.pane("s", &["sh"]);
    let client = rig.connect("s", "a").await;
    rig::screen_agrees(&pane, &client);
    let gone = Instant::now();
    rig.net.black_hole(Duration::from_secs(40));
    fs::write(pane.join("in"), "echo while-$((6 * 7))-away\n").unwrap();
    // koh says so once the link has been silent for eight seconds.
    rig::until(
        "the client says there is no link",
        Duration::from_secs(15),
        || client.screen().contains("no link"),
    );
    assert!(!client.screen().contains("while-42-away"));
    client.types(b"echo held-$((6 * 7))-typed\n");
    tokio::time::sleep(Duration::from_secs(40).saturating_sub(gone.elapsed())).await;
    let back = Instant::now();
    rig::until(
        "the screen shows the present",
        Duration::from_secs(12),
        || client.screen().contains("while-42-away"),
    );
    println!(
        "screen is back {:?} after the link returned",
        back.elapsed()
    );
    rig::until("what was held is typed", Duration::from_secs(5), || {
        client.screen().contains("held-42-typed")
    });
    rig::screen_agrees(&pane, &client);
    assert_eq!(rig::screen(&pane).matches("held-42-typed").count(), 1);
}

/// Fresh attach to a session with megabytes of history on a slow link: gets its first screen
/// in seconds (not minutes), whatever history the session has.
async fn a_fresh_attach(profile: Profile, lines: u32, long: Duration) -> (Duration, u64) {
    let rig = Rig::start("fresh", profile, 1).await;
    let pane = rig.pane("s", &["sh"]);
    fs::write(
        pane.join("in"),
        format!("seq 1 {lines}; echo all-pr''inted\n"),
    )
    .unwrap();
    rig::until("the history is there", Duration::from_secs(30), || {
        rig::screen(&pane).contains("all-printed")
    });
    let hist_bytes = fs::metadata(pane.join("history")).map_or(0, |m| m.len())
        + fs::metadata(pane.join("history.styled")).map_or(0, |m| m.len());
    let began = Instant::now();
    let client = rig.connect_now("s", "a").await;
    rig::until("first screen shows all-printed", long, || {
        client.screen().contains("all-printed")
    });
    let took = began.elapsed();
    let bytes = rig.net.counts(client.id).bytes;
    println!("fresh attach ({hist_bytes} B history): first screen in {took:?}, {bytes} B carried");
    rig::screen_agrees(&pane, &client);
    (took, bytes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_attach_to_megabytes_of_history_at_256_kbit_takes_seconds() {
    let (took, bytes) =
        a_fresh_attach(Profile::named("256kbit"), 150_000, Duration::from_secs(10)).await;
    assert!(took < Duration::from_secs(4), "took {took:?} ({bytes} B)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_attach_to_megabytes_of_history_at_64_kbit_takes_seconds() {
    let profile = Profile {
        rate: Some(64_000),
        queue: Duration::from_secs(1),
        ..Profile::named("25ms")
    };
    let (took, bytes) = a_fresh_attach(profile, 150_000, Duration::from_secs(15)).await;
    assert!(took < Duration::from_secs(6), "took {took:?} ({bytes} B)");
}

// ---- A link cut at any byte: what the terminal is left in, and what is typed. ----

/// What a program of a session turns on in the terminal it is shown in, through the viewer:
/// the alternate screen, mouse reports, pastes marked, the focus told, the cursor hidden.
const MODES_ON: &str = r"printf '\033[?1049h\033[?1002h\033[?1006h\033[?2004h\033[?1004h\033[?25l\033[5;5HMODES-%s' ON; exec sleep 600";

/// Waits until the client's terminal is its own again: the main screen, nothing asked of it
/// (no mouse, no pastes marked, no focus told), the cursor shown.
fn the_terminal_is_put_back(client: &rig::Connected, when: &str) {
    let said = format!("the terminal is put back {when}");
    rig::until(&said, Duration::from_secs(10), || {
        client.shown() == "main" && client.says("modes").trim().is_empty()
    });
    assert!(client.says("cursor").contains("shown"), "{when}");
}

/// The attach is cut at a byte, twelve times, while a program redraws a full screen with
/// colours, links and a title, a sequence of each kind in every row: whatever sequence
/// the cut fell in, the terminal is put back at once (what was cut is ended first), and the
/// screen that comes next is the session's, cell for cell.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cut_at_any_byte_leaves_the_terminal_right_and_the_next_screen_whole() {
    cut_at_any_byte(12, 7).await;
}

/// The same two hundred times, of another seed: run by hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "two minutes: the same test with two hundred cuts"]
async fn two_hundred_cuts_at_any_byte_leave_the_terminal_right() {
    cut_at_any_byte(200, 21).await;
}

async fn cut_at_any_byte(cuts: usize, seed: u64) {
    let rig = Rig::start("cuts", Profile::named("clean"), seed).await;
    // (Styled text, a link's address and a title: a CSI, an OSC and a string in every frame.)
    let draws = r"n=0; while :; do n=$((n+1)); printf '\033]2;title-%d\033\\\033[H' $n; r=1; while [ $r -le 23 ]; do printf '\033[%d;1H\033[38;2;%d;20;30m\033]8;;https://example.com/%d\033\\row %d of frame %d\033]8;;\033\\\033[m\033[K' $r $r $n $r $n; r=$((r+1)); done; [ -e $0 ] && break; done; printf '\033[2J\033[HDRAWN-%s\n' OUT; exec sleep 600";
    let stop = rig.file("stop");
    let pane = rig.pane("s", &["sh", "-c", draws, stop.to_str().unwrap()]);
    let client = rig.connect("s", "a").await;
    let mut random = rig::Draws(seed);
    for cut in 0..cuts {
        tokio::time::sleep(Duration::from_millis(30 + random.below(250))).await;
        let before = client.raw().len();
        rig.cut();
        // What koh writes at the cut begins by ending what was cut: CAN, then ST.
        rig::until("koh says there is no link", Duration::from_secs(10), || {
            client.raw()[before..]
                .windows(7)
                .any(|said| said == b"no link")
        });
        let raw = client.raw();
        let reset = raw[before..].windows(3).position(|at| at == b"\x18\x1b\\");
        assert!(reset.is_some(), "cut {cut}: nothing ended what was cut");
        rig::until("the viewer is back", Duration::from_secs(10), || {
            client.raw()[before..]
                .windows(8)
                .rposition(|at| at == b"\x1b[?1049h")
                .is_some_and(|back| back > reset.unwrap())
        });
    }
    fs::write(&stop, "").unwrap();
    rig::until(
        "the program has drawn its last",
        Duration::from_secs(20),
        || rig::screen(&pane).contains("DRAWN-OUT"),
    );
    rig::screen_agrees(&pane, &client);
    assert_eq!(client.screen().trim_end(), "DRAWN-OUT");
    // The session's program asks for the mouse and more; the link is cut, and the terminal
    // is its own while there is none: nothing of the viewer's stays on.
    fs::write(pane.join("ctl"), "kill\n").unwrap();
    let pane = rig.pane("m", &["sh", "-c", MODES_ON]);
    let client = rig.connect("m", "b").await;
    rig::until("the modes are on", Duration::from_secs(10), || {
        client.screen().contains("MODES-ON") && client.says("modes").contains("mouse")
    });
    assert!(client.shown() == "alt" && client.says("modes").contains("paste"));
    rig.net.black_hole(Duration::from_secs(11));
    rig::until("koh says there is no link", Duration::from_secs(15), || {
        client.screen().contains("no link")
    });
    the_terminal_is_put_back(&client, "while there is no link");
    rig::until("the modes are on again", Duration::from_secs(20), || {
        client.shown() == "alt" && client.says("modes").contains("mouse")
    });
    rig::screen_agrees(&pane, &client);
}

/// However `koh connect` ends, the terminal is put back: when its user leaves a session whose
/// program has the mouse and the alternate screen, when that program ends, and when the
/// terminal's user leaves while there is no link, also when the two bytes of the key come in
/// two reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_terminal_is_put_back_however_koh_ends_and_its_key_leaves_with_no_link_too() {
    let rig = Rig::start("leaves", Profile::named("clean"), 1).await;
    let pane = rig.pane("s", &["sh", "-c", MODES_ON]);
    let on = |client: &rig::Connected| {
        rig::until("the modes are on", Duration::from_secs(10), || {
            client.screen().contains("MODES-ON") && client.says("modes").contains("mouse")
        });
    };
    // Its user leaves: 0, and the session runs on.
    let mut client = rig.connect("s", "a").await;
    on(&client);
    client.types(b"\x1d.");
    assert_eq!(client.ends(Duration::from_secs(10)).await.unwrap(), 0);
    the_terminal_is_put_back(&client, "after Ctrl-] .");
    assert_eq!(rig::state(&pane), "running");
    // There is no link, and its user leaves: at once, with nothing to answer the key.
    for leaves in [&[b"\x1d.".as_slice()][..], &[b"\x1d", b"."]] {
        let mut client = rig.connect("s", "a").await;
        on(&client);
        rig.net.black_hole(Duration::from_secs(600));
        rig::until("koh says there is no link", Duration::from_secs(15), || {
            client.screen().contains("no link")
        });
        the_terminal_is_put_back(&client, "while there is no link");
        client.types(b"typed while away");
        for keys in leaves {
            client.types(keys);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(client.ends(Duration::from_secs(5)).await.unwrap(), 0);
        the_terminal_is_put_back(&client, "after it left with no link");
        // (What it said of the link is wiped from the line it was on.)
        assert!(!client.screen().contains("no link"), "{}", client.screen());
        rig.net.black_hole(Duration::ZERO);
    }
    // The program ends: its status, and the terminal as it was.
    let mut client = rig.connect("s", "a").await;
    on(&client);
    fs::write(pane.join("ctl"), "kill\n").unwrap();
    assert_eq!(client.ends(Duration::from_secs(10)).await.unwrap(), 128 + 1);
    the_terminal_is_put_back(&client, "after the program ended");
}

/// A megabyte is pasted into a program that reads nothing: it waits, all of it, for the
/// program (the session's viewer drops none of it, and reads no further), and the viewer
/// hears no key meanwhile. koh's key is the client's: it leaves all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kohs_key_leaves_a_session_whose_program_reads_nothing_of_what_was_pasted() {
    let rig = Rig::start("deaf", Profile::named("clean"), 1).await;
    let out = rig.file("out");
    let reads = "stty raw -echo; echo READY; until [ -e \"$0.go\" ]; do sleep 0.05; done; exec cat > \"$0\"";
    let pane = rig.pane("s", &["sh", "-c", reads, out.to_str().unwrap()]);
    let mut client = rig.connect("s", "a").await;
    rig::until("the program is there", Duration::from_secs(20), || {
        client.screen().contains("READY")
    });
    let pasted: Vec<u8> = (0..(1 << 20) / 16).flat_map(rig::line).collect();
    client.types(&[b"\x1b[200~", pasted.as_slice(), b"\x1b[201~"].concat());
    tokio::time::sleep(Duration::from_millis(500)).await;
    client.types(b"\x1d.");
    assert_eq!(client.ends(Duration::from_secs(10)).await.unwrap(), 0);
    assert_eq!(rig::state(&pane), "running");
    // What the session had taken by then is the paste's start, in its order; a client that
    // comes then and pastes it again, into a program that reads, has it typed whole.
    fs::write(rig.file("out.go"), "").unwrap();
    // (All that waited for it in the session: until half a second brings no more.)
    let read = || fs::metadata(&out).map_or(0, |out| out.len());
    let (mut had, mut since) = (0, Instant::now());
    rig::until(
        "the program has read what waited",
        Duration::from_secs(20),
        || {
            if read() != had {
                (had, since) = (read(), Instant::now());
            }
            had > 0 && since.elapsed() > Duration::from_millis(500)
        },
    );
    let before = fs::read(&out).unwrap();
    assert!(
        before.len() < pasted.len() && pasted.starts_with(&before),
        "{} bytes",
        before.len()
    );
    let client = rig.connect("s", "a").await;
    client.types(&pasted);
    rig::until(
        "the second paste is read whole",
        Duration::from_secs(30),
        || fs::metadata(&out).is_ok_and(|out| out.len() == (before.len() + pasted.len()) as u64),
    );
    assert!(fs::read(&out).unwrap().ends_with(&pasted));
}

/// What is typed while there is no link is held and typed once on return, a key whose bytes
/// came in two reads among it; and a terminal made another size meanwhile is the session's
/// size on return.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_is_typed_with_no_link_is_typed_once_on_return_and_a_resize_meanwhile_is_not_lost() {
    let rig = Rig::start("held", Profile::named("25ms"), 1).await;
    let out = rig.file("out");
    let pane = rig.pane("s", &rig::reads_into(&out));
    let client = rig.connect("s", "a").await;
    rig::until("the program is ready", Duration::from_secs(15), || {
        client.screen().contains("READY")
    });
    // The link is lost, and koh knows. An arrow key comes in two reads, as a slow terminal
    // sends one: it is held whole, with what is typed after it.
    rig.net.black_hole(Duration::from_secs(13));
    rig::until("koh says there is no link", Duration::from_secs(15), || {
        client.screen().contains("no link")
    });
    client.types(b"\x1b[");
    tokio::time::sleep(Duration::from_millis(5)).await;
    client.types(b"A");
    client.types(b"HELD");
    client.resize(92, 26);
    rig::until("the held keys are typed", Duration::from_secs(25), || {
        fs::read(&out).unwrap_or_default().ends_with(b"HELD")
    });
    client.types(b"-AFTER");
    rig::until("and what is typed then", Duration::from_secs(10), || {
        fs::read(&out).unwrap_or_default().ends_with(b"-AFTER")
    });
    assert_eq!(fs::read(&out).unwrap(), b"\x1b[AHELD-AFTER");
    rig::until(
        "the session has the terminal's size",
        Duration::from_secs(10),
        || {
            fs::read_to_string(pane.join("size"))
                .unwrap_or_default()
                .trim()
                == "92 26"
        },
    );
}

/// A link that is not there when `koh connect` starts, or goes before its first attach is
/// answered, is dialled again as any other: the first screen comes when the path does. But a
/// new session that was given no name is asked for once: asked again after an answer that was
/// lost, it would be started twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_that_goes_in_the_first_attach_is_dialled_again_and_a_new_session_is_asked_for_once()
{
    let rig = Rig::start("first", Profile::named("25ms"), 1).await;
    let pane = rig.pane("s", &["sh", "-c", "echo FIRST-''SCREEN; exec sleep 600"]);
    // (Gone for longer than a link may be silent: the connection the attach was asked on is lost.)
    let on = rig.dialled("a").await;
    rig.net.black_hole(Duration::from_secs(11));
    let client = rig.connect_on(on, Some("s"), false);
    rig::until("the first screen comes", Duration::from_secs(30), || {
        client.screen().contains("FIRST-SCREEN")
    });
    rig::screen_agrees(&pane, &client);
    assert!(rig.net.counts(rig.server_id).black_holed > 0);
    let on = rig.dialled("b").await;
    rig.net.black_hole(Duration::from_secs(600));
    let mut client = rig.connect_on(on, None, true);
    let ended = client.ends(Duration::from_secs(20)).await;
    assert_eq!(ended.unwrap_err().code, koh::Exit::UNREACHABLE);
    assert_eq!(rig.sessions(), ["s"]);
}

/// A server of the test's own, which answers an attach and then says what a test has it say.
struct Says(iroh::Endpoint);

impl Says {
    async fn start(rig: &Rig) -> (Says, iroh::EndpointId) {
        let secret = iroh::SecretKey::generate();
        let id = secret.public();
        (Says(rig.net.endpoint(secret, true).await), id)
    }

    /// The next connection, and its attach answered with the run `run` of a session `s`: the
    /// stream, and what the client asked.
    async fn attached(&self, run: u128) -> (Connection, SendStream, RecvStream, Attach) {
        let conn = self.0.accept().await.unwrap().await.unwrap();
        let (send, recv, asked) = Says::again(&conn, run).await;
        (conn, send, recv, asked)
    }

    /// The next attach on a connection there is.
    async fn again(conn: &Connection, run: u128) -> (SendStream, RecvStream, Attach) {
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        koh::net::verify_client(conn, &mut recv).await.unwrap();
        let Request::Attach(asked) = recv_msg(&mut recv, MAX_CTRL).await.unwrap() else {
            panic!("no attach")
        };
        send_msg(&mut send, &Reply::Ok, MAX_CTRL).await.unwrap();
        let name = "s".to_string();
        send_msg(&mut send, &Attached { name, run }, MAX_CTRL)
            .await
            .unwrap();
        (send, recv, asked)
    }
}

/// A client `who` that dials the test's own server and is answered there with the run 7.
async fn comes(
    rig: &Rig,
    (server, id): &(Says, iroh::EndpointId),
    who: &str,
) -> (rig::Connected, Connection, SendStream, RecvStream, Attach) {
    let connects = async { rig.connect_on(rig.dialled_to(who, *id).await, None, false) };
    let (client, (conn, send, recv, asked)) = tokio::join!(connects, server.attached(7));
    (client, conn, send, recv, asked)
}

async fn draws(send: &mut SendStream, bytes: &str) {
    let drawn = ViewOutput::Bytes(bytes.as_bytes().to_vec());
    send_msg(send, &drawn, VIEW_FRAME).await.unwrap();
}

/// What a server can do to a client is what a terminal's output can do, and koh ends what it
/// left: a stream cut in the middle of a sequence, a string or a picture, with modes on and a
/// scroll region set, by a server that says no last word.
/// Before a first screen Ctrl-C ends koh; after it, it is typed. And a server that answers
/// with another run, or with what is no message, is the client's end, the terminal put back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_that_cuts_a_sequence_or_says_what_none_says_leaves_the_terminal_its_own() {
    let rig = Rig::start("says", Profile::named("clean"), 1).await;
    let server = Says::start(&rig).await;
    // Ctrl-C before the first screen ends koh: nothing was drawn, and nothing is put back.
    let (mut client, _conn, _send, mut typed, asked) = comes(&rig, &server, "a").await;
    assert_eq!(
        (asked.run, asked.size.cols, asked.size.rows),
        (None, 80, 24)
    );
    client.types(&[3]);
    assert_eq!(client.ends(Duration::from_secs(5)).await.unwrap(), 130);
    assert!(
        client.raw().is_empty() && recv_msg::<ViewInput>(&mut typed, VIEW_FRAME).await.is_err()
    );
    // What a viewer may be in the middle of: its modes going on, a scroll region, a frame
    // begun; text in a colour, a title, a link, a picture.
    // It is cut at a byte, twenty-four times, each at another.
    let (mut client, mut conn, mut send, mut typed, _) = comes(&rig, &server, "a").await;
    let begins = "\x1b[?1049h\x1b[?2004h\x1b[?1002h\x1b[?1006h\x1b[?25l\x1b[3;9r\x1b[?2026h";
    let frame = format!(
        "{begins}\x1b[5;5H\x1b[38;2;10;20;30mcoloured\x1b]2;a title of some length\x1b\\\x1b]8;;https://example.com/a/link\x1b\\linked\x1b]8;;\x1b\\\x1b[7;1H\x1bPq#0;2;100;0;0#0~~~~-~~~~-~~~~\x1b\\\x1b[mafter"
    );
    let mut random = rig::Draws(5);
    for n in 0..24 {
        let cut = 1 + random.below(frame.len() as u64 - 1) as usize;
        let before = client.raw().len();
        draws(&mut send, &frame[..cut]).await;
        rig::until(
            "what was sent is on the terminal",
            Duration::from_secs(10),
            || client.raw().len() >= before + cut,
        );
        if n == 0 {
            // (After a first screen Ctrl-C is a key as any other.)
            client.types(&[3]);
            let key: ViewInput = recv_msg(&mut typed, VIEW_FRAME).await.unwrap();
            assert!(matches!(key, ViewInput::Bytes(key) if key == [3]));
        }
        conn.close(0u32.into(), b"cut");
        rig::until("koh says there is no link", Duration::from_secs(10), || {
            client.raw()[before + cut..]
                .windows(7)
                .any(|said| said == b"no link")
        });
        the_terminal_is_put_back(&client, &format!("after a cut at byte {cut}"));
        // What was cut is ended first, then the frame and the region; the main screen is
        // come back to, and no keyboard flags are taken back: koh's viewer sets none aside.
        let said = String::from_utf8_lossy(&client.raw()[before + cut..]).into_owned();
        assert!(
            said.starts_with("\x18\x1b\\\x1b[?2026l\x1b[r"),
            "{cut}: {said:?}"
        );
        assert!(
            said.contains("\x1b[?1049l") && !said.contains("\x1b[<u"),
            "{cut}: {said:?}"
        );
        // No byte of the cut sequence was taken for text: the terminal's own screen has koh's
        // line on it, and nothing else.
        let screen = client.screen();
        assert!(
            screen.trim().starts_with("koh: no link") && screen.trim().lines().count() == 1,
            "{cut}: {screen:?}"
        );
        // The client comes again, to the run it was shown.
        let (again, asked);
        (conn, again, typed, asked) = server.0.attached(7).await;
        send = again;
        assert_eq!(asked.run, Some(7));
    }
    draws(
        &mut send,
        &format!("{begins}\x1b[2J\x1b[2;2H\x1b[32mRIGHT-AGAIN\x1b[m\x1b[?2026l"),
    )
    .await;
    rig::until(
        "the next screen is read right",
        Duration::from_secs(10),
        || client.screen().trim() == "RIGHT-AGAIN",
    );
    // The server says its last word with all of that still on: koh ends with it, and puts
    // the terminal back all the same.
    let ended = ViewOutput::Exit(9);
    send_msg(&mut send, &ended, VIEW_FRAME).await.unwrap();
    assert_eq!(client.ends(Duration::from_secs(5)).await.unwrap(), 9);
    the_terminal_is_put_back(&client, "after the server's last word");
    assert!(!client.screen().contains("no link"), "{}", client.screen());
    // A server that answers a client that comes again with another run: nothing is typed
    // there, and koh ends. One that sends what is no message: koh ends, saying so.
    for other in [true, false] {
        let (mut client, conn, mut send, _typed, _) = comes(&rig, &server, "b").await;
        draws(&mut send, &format!("{begins}\x1b[5;5HSHOWN")).await;
        rig::until("the screen", Duration::from_secs(10), || {
            client.screen().contains("SHOWN")
        });
        client.types(b"typed");
        let _answered = if other {
            conn.close(0u32.into(), b"cut");
            Some(server.0.attached(8).await)
        } else {
            let long = ViewOutput::Bytes(vec![b'x'; VIEW_FRAME + 1]);
            // (The client reads its length and no further: the rest is sent to nobody.)
            let _ = send_msg(&mut send, &long, MAX_CTRL).await;
            None
        };
        let ended = client.ends(Duration::from_secs(10)).await.unwrap_err();
        let said = if other {
            "another run"
        } else {
            "exceeds bound"
        };
        assert!(
            ended.code == koh::Exit::FAILED && ended.message.contains(said),
            "{ended:?}"
        );
        the_terminal_is_put_back(&client, "after what no server says");
    }
}

/// A key's echo during a flood at 256 kbit/s does not wait behind seconds of old frames: the
/// viewer draws its next frame when its terminal has taken the last, and the stream reads no
/// further ahead than its window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_keys_echo_during_a_flood_at_256_kbit_is_not_behind_old_frames() {
    let rig = Rig::start("flood-256k", Profile::named("256kbit"), 1).await;
    // Saturate rows 2..24 with a continuous `seq`-style flood while echoing typed keys on row 1
    // (single writer so escape sequences never interleave).
    let py = r#"
import os, select, sys, termios, tty
tty.setraw(0)
out = sys.stdout.buffer
out.write(b'\x1b[2;24r\x1b[2;1H'); out.flush()
n = 1
while True:
    if select.select([0], [], [], 0)[0]:
        k = os.read(0, 1)
        if not k: break
        out.write(b'\x1b[1;1H===ECHO-' + k + b'===\x1b[24;1H')
        out.flush()
    batch = ''.join(f'{i}\r\n' for i in range(n, n + 200)).encode()
    n = (n + 200) % 2000000 + 1
    out.write(batch); out.flush()
"#;
    rig.pane("s", &["python3", "-c", py]);
    let client = rig.connect("s", "a").await;
    // Let the flood saturate the 256 kbit/s link for 1 second first.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let before = rig.net.counts(client.id);
    let t0 = Instant::now();

    let mut echoes = Vec::new();
    for ch in ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'] {
        let want = format!("===ECHO-{ch}===");
        let at = Instant::now();
        client.types(&[ch as u8]);
        rig::until(&want, Duration::from_secs(10), || {
            client.screen().contains(&want)
        });
        echoes.push(at.elapsed());
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let after = rig.net.counts(client.id);
    let secs = t0.elapsed().as_secs_f64();
    let bps = (after.bytes - before.bytes) as f64 / secs;
    echoes.sort();
    let median = echoes[echoes.len() / 2];
    let worst = *echoes.last().unwrap();
    println!(
        "key echo during seq 1 2000000 flood at 256 kbit/s ({bps:.0} B/s down, waited={}): median={median:?}, worst={worst:?}, all={echoes:?}",
        after.waited - before.waited
    );
    assert!(
        after.bytes - before.bytes > 20_000,
        "flood did not saturate during echo test: {} B",
        after.bytes - before.bytes
    );
    assert!(
        median < Duration::from_secs(2) && worst < Duration::from_secs(3),
        "echo queued behind flood: median={median:?}, worst={worst:?}"
    );
}
