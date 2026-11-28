//! Sessions on the fault link: what a user would notice of one when the link goes silent, or is
//! cut in the middle of a sequence.

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::time::{Duration, Instant};

use iroh::endpoint::{Connection, RecvStream, SendStream};
use koh::proto::{
    Attach, Attached, MAX_CTRL, Reply, Request, VIEW_FRAME, ViewOutput, recv_msg, send_msg,
};

use crate::rig::{self, Rig, secs};

/// A link gone for forty seconds while a line is typed every 25 ms, and back: koh says there is
/// no link once it has been silent for eight seconds, holds what is typed from then on and a
/// resize, dials again, and is back within seconds of the path. What was typed arrives once
/// and in its order: all of it, but what was on its way when the link went (one stretch).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_gone_for_forty_seconds_is_back_within_seconds_and_what_is_typed_arrives_once() {
    let rig = Rig::start("forty").await;
    let out = rig.file("out");
    let pane = rig.pane("s", &rig::reads_into(&out));
    let client = rig.connect("s", "a").await;
    rig::until("the program is ready", secs(20), || {
        client.screen().contains("READY")
    });
    let (typing, typed) = (
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicUsize::new(0)),
    );
    let (goes_on, count, master) = (typing.clone(), typed.clone(), client.master.try_clone());
    let typist = std::thread::spawn(move || {
        let (mut all, master) = (Vec::new(), master.unwrap());
        for line in (0..).map(rig::line).take_while(|_| goes_on.load(SeqCst)) {
            rig::write_all_pty(&master, &line);
            all.extend(line);
            count.store(all.len(), SeqCst);
            // (640 B/s: what is held stays well under its 64 KiB however long the redial takes.)
            std::thread::sleep(Duration::from_millis(25));
        }
        all
    });
    rig::until("the program reads", secs(10), || {
        fs::metadata(&out).is_ok_and(|o| o.len() > 0)
    });
    let gone = Instant::now();
    rig.net.black_hole(secs(40));
    rig::until("koh says there is no link", secs(20), || {
        client.screen().contains("no link")
    });
    let held = typed.load(SeqCst);
    client.resize(92, 26);
    // (The outage is the test's: it ends forty seconds after it began.)
    tokio::time::sleep(secs(40).saturating_sub(gone.elapsed())).await;
    // Within seconds: a dial every ten at most, and not the server's thirty of silence.
    rig::until("the session is shown again", secs(20), || {
        !client.screen().contains("no link")
    });
    rig::screen_agrees(&pane, &client);
    typing.store(false, SeqCst);
    let all = typist.join().unwrap();
    rig::until("the end of what was typed arrives", secs(20), || {
        fs::read(&out)
            .unwrap_or_default()
            .ends_with(&all[all.len() - 16..])
    });
    // Read is a start of what was typed and an end of it, which has all typed since koh said
    // there was no link. (Whole lines: the next line's leading zeros are no line kept.)
    let read = fs::read(&out).unwrap();
    let kept = read
        .chunks(16)
        .zip(all.chunks(16))
        .take_while(|(read, typed)| read == typed);
    let end = read.len() - 16 * kept.count();
    let whole = all.ends_with(&read[read.len() - end..]) && end >= all.len() - held;
    assert!(
        whole,
        "{} typed, {} read, the last {end} in order; {held} before koh said so",
        all.len(),
        read.len()
    );
    let size = || fs::read_to_string(pane.join("size")).unwrap_or_default();
    rig::until("the session has the terminal's size", secs(10), || {
        size().trim() == "92 26"
    });
}

/// A first attach to a session with megabytes of history is sent the screen, not the history.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_attach_to_megabytes_of_history_is_sent_a_screen() {
    let rig = Rig::start("fresh").await;
    let pane = rig.pane("s", &["sh"]);
    fs::write(pane.join("in"), "seq 1 150000; echo all-pr''inted\n").unwrap();
    rig::until("the history is there", secs(30), || {
        rig::screen(&pane).contains("all-printed")
    });
    let history = fs::metadata(pane.join("history")).map_or(0, |m| m.len());
    let client = rig.connect("s", "a").await;
    rig::screen_agrees(&pane, &client);
    let bytes = rig.net.counts(client.id).bytes;
    assert!(
        history > 500_000 && bytes < 64_000,
        "{bytes} B sent of {history} B"
    );
}

/// What a program of a session turns on in the terminal it is shown in, through the viewer:
/// the alternate screen, mouse reports, pastes marked, the focus told, the cursor hidden.
const MODES_ON: &str = r"printf '\033[?1049h\033[?1002h\033[?1006h\033[?2004h\033[?1004h\033[?25l\033[5;5HMODES-%s' ON; exec sleep 600";

/// Waits until the client's terminal is its own again: the main screen, nothing asked of it
/// (no mouse, no pastes marked, no focus told), the cursor shown.
fn the_terminal_is_put_back(client: &rig::Connected, when: &str) {
    let said = format!("the terminal is put back {when}");
    rig::until(&said, secs(10), || {
        client.shown() == "main" && client.says("modes").trim().is_empty()
    });
    assert!(client.says("cursor").contains("shown"), "{when}");
}

/// While there is no link the terminal is its own: nothing of the session's modes stays on. Its
/// user leaves then, the two bytes of the key in two reads: koh ends at once with nothing to
/// answer the key, and wipes what it said of the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kohs_key_leaves_with_no_link_and_the_terminal_is_put_back() {
    let rig = Rig::start("leaves").await;
    rig.pane("s", &["sh", "-c", MODES_ON]);
    let mut client = rig.connect("s", "a").await;
    rig::until("the modes are on", secs(10), || {
        client.screen().contains("MODES-ON") && client.says("modes").contains("mouse")
    });
    rig.net.black_hole(secs(600));
    rig::until("koh says there is no link", secs(20), || {
        client.screen().contains("no link")
    });
    the_terminal_is_put_back(&client, "while there is no link");
    client.types(b"typed while away\x1d");
    // (So that the key's second byte is read apart from its first: the test of a key in
    // pieces, which passes as well with the two read together.)
    tokio::time::sleep(Duration::from_millis(50)).await;
    client.types(b".");
    assert_eq!(client.ends(secs(10)).await.unwrap(), 0);
    the_terminal_is_put_back(&client, "after it left with no link");
    rig::until("what it said is wiped", secs(10), || {
        !client.screen().contains("no link")
    });
}

/// A megabyte is pasted into a program that reads nothing: it waits, all of it, for the
/// program (the session's viewer drops none of it, and reads no further), and the viewer
/// hears no key meanwhile. koh's key is the client's: it leaves all the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kohs_key_leaves_a_session_whose_program_reads_nothing_of_what_was_pasted() {
    let rig = Rig::start("deaf").await;
    let out = rig.file("out");
    let reads = "stty raw -echo; echo READY; until [ -e \"$0.go\" ]; do sleep 0.05; done; exec cat > \"$0\"";
    let pane = rig.pane("s", &["sh", "-c", reads, out.to_str().unwrap()]);
    let mut client = rig.connect("s", "a").await;
    rig::until("the program is there", secs(20), || {
        client.screen().contains("READY")
    });
    let pasted: Vec<u8> = (0..(1 << 20) / 16).flat_map(rig::line).collect();
    client.types(&[b"\x1b[200~", pasted.as_slice(), b"\x1b[201~"].concat());
    // (So that the key comes behind the paste that waits: sooner, it is the easier test.)
    tokio::time::sleep(Duration::from_millis(500)).await;
    client.types(b"\x1d.");
    assert_eq!(client.ends(secs(10)).await.unwrap(), 0);
    assert_eq!(fs::read_to_string(pane.join("state")).unwrap(), "running\n");
    // What the session had taken by then is the paste's start, in its order; a client that
    // comes then and pastes more, into a program that reads, has it typed whole after it.
    fs::write(rig.file("out.go"), "").unwrap();
    let gone = || {
        // (A viewer's folder is beside the sessions', in koh's fux session.)
        let mut left = fs::read_dir(rig.sessions.parent().unwrap())
            .unwrap()
            .flatten();
        left.all(|f| !f.file_name().to_string_lossy().starts_with(".view."))
    };
    rig::until("the viewer that was left is gone", secs(20), gone);
    let more: Vec<u8> = (1 << 20..(1 << 20) + 4096).flat_map(rig::line).collect();
    let client = rig.connect("s", "a").await;
    client.types(&more);
    rig::until("the second paste is read whole", secs(30), || {
        fs::read(&out).unwrap_or_default().ends_with(&more)
    });
    let read = fs::read(&out).unwrap();
    let before = &read[..read.len() - more.len()];
    assert!(pasted.starts_with(before), "{} bytes", before.len());
}

/// A link that is not there when `koh connect` starts, or goes before its first attach is
/// answered, is dialled again as any other: the first screen comes when the path does. But a
/// new session that was given no name is asked for once: asked again after an answer that was
/// lost, it would be started twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_that_goes_in_the_first_attach_is_dialled_again_and_a_new_session_is_asked_for_once()
{
    let rig = Rig::start("first").await;
    let pane = rig.pane("s", &["sh", "-c", "echo FIRST-''SCREEN; exec sleep 600"]);
    // (Gone for longer than a link may be silent: the connection the attach was asked on is lost.)
    let on = rig.dialled("a").await;
    rig.net.black_hole(secs(11));
    let client = rig.connect_on(on, Some("s"), false);
    rig::until("the first screen comes", secs(30), || {
        client.screen().contains("FIRST-SCREEN")
    });
    rig::screen_agrees(&pane, &client);
    assert!(rig.net.counts(rig.server_id).black_holed > 0);
    let on = rig.dialled("b").await;
    rig.net.black_hole(secs(600));
    let mut client = rig.connect_on(on, None, true);
    let ended = client.ends(secs(20)).await;
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

    /// The next connection, and its attach answered with the run 7 of a session `s`: the
    /// stream, and what the client asked.
    async fn attached(&self) -> (Connection, SendStream, RecvStream, Attach) {
        let conn = self.0.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        koh::net::verify_client(&conn, &mut recv).await.unwrap();
        let Request::Attach(asked) = recv_msg(&mut recv, MAX_CTRL).await.unwrap() else {
            panic!("no attach")
        };
        send_msg(&mut send, &Reply::Ok, MAX_CTRL).await.unwrap();
        let name = "s".to_string();
        send_msg(&mut send, &Attached { name, run: 7 }, MAX_CTRL)
            .await
            .unwrap();
        (conn, send, recv, asked)
    }
}

/// A client `who` that dials the test's own server and is answered there with the run 7.
async fn comes(
    rig: &Rig,
    (server, id): &(Says, iroh::EndpointId),
    who: &str,
) -> (rig::Connected, Connection, SendStream, RecvStream, Attach) {
    let connects = async { rig.connect_on(rig.dialled_to(who, *id).await, None, false) };
    let (client, (conn, send, recv, asked)) = tokio::join!(connects, server.attached());
    (client, conn, send, recv, asked)
}

async fn draws(send: &mut SendStream, bytes: &str) {
    let drawn = ViewOutput::Bytes(bytes.as_bytes().to_vec());
    send_msg(send, &drawn, VIEW_FRAME).await.unwrap();
}

/// What a server can do to a client is what a terminal's output can do, and koh ends what it
/// left: a stream cut in the middle of a sequence, a string or a picture, with modes on and a
/// scroll region set, by a server that says no last word. And a server that answers with what
/// is no message is the client's end, the terminal put back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_that_cuts_a_sequence_or_says_what_none_says_leaves_the_terminal_its_own() {
    let rig = Rig::start("says").await;
    let server = Says::start(&rig).await;
    // What a viewer may be in the middle of: its modes going on, a scroll region, a frame
    // begun; text in a colour, a title, a link, a picture. It is cut inside each.
    let (mut client, mut conn, mut send, mut _typed, _) = comes(&rig, &server, "a").await;
    let begins = "\x1b[?1049h\x1b[?2004h\x1b[?1002h\x1b[?1006h\x1b[?25l\x1b[3;9r\x1b[?2026h";
    let frame = format!(
        "{begins}\x1b[5;5H\x1b[38;2;10;20;30mcoloured\x1b]2;a title of some length\x1b\\\x1b]8;;https://example.com/a/link\x1b\\linked\x1b]8;;\x1b\\\x1b[7;1H\x1bPq#0;2;100;0;0#0~~~~-~~~~-~~~~\x1b\\\x1b[mafter"
    );
    let insides = [
        "\x1b[3;",
        "\x1b[?202",
        "38;2;1",
        "a title",
        "example",
        "#0~~",
    ];
    for inside in insides {
        let cut = frame.find(inside).unwrap() + inside.len();
        let before = client.raw().len();
        draws(&mut send, &frame[..cut]).await;
        rig::until("what was sent is on the terminal", secs(10), || {
            client.raw().len() >= before + cut
        });
        conn.close(0u32.into(), b"cut");
        rig::until("koh says there is no link", secs(10), || {
            client.raw()[before + cut..]
                .windows(7)
                .any(|said| said == b"no link")
        });
        the_terminal_is_put_back(&client, &format!("after a cut in {inside:?}"));
        // What was cut is ended first (CAN, then ST), and no byte of it was taken for text:
        // the terminal's own screen has koh's line on it, and nothing else.
        let said = String::from_utf8_lossy(&client.raw()[before + cut..]).into_owned();
        assert!(said.starts_with("\x18\x1b\\"), "{inside:?}: {said:?}");
        let alone = |screen: String| {
            screen.trim().starts_with("koh: no link") && screen.trim().lines().count() == 1
        };
        rig::until(
            &format!("after a cut in {inside:?}, the screen is koh's line and no more"),
            secs(10),
            || alone(client.screen()),
        );
        // The client comes again, to the run it was shown.
        let asked;
        (conn, send, _typed, asked) = server.0.attached().await;
        assert_eq!(asked.run, Some(7));
    }
    draws(
        &mut send,
        &format!("{begins}\x1b[2J\x1b[2;2H\x1b[32mRIGHT-AGAIN\x1b[m\x1b[?2026l"),
    )
    .await;
    rig::until("the next screen is read right", secs(10), || {
        client.screen().trim() == "RIGHT-AGAIN"
    });
    // The server says its last word with all of that still on: koh ends with it, and puts
    // the terminal back all the same.
    let ended = ViewOutput::Exit(9);
    send_msg(&mut send, &ended, VIEW_FRAME).await.unwrap();
    assert_eq!(client.ends(secs(10)).await.unwrap(), 9);
    the_terminal_is_put_back(&client, "after the server's last word");
    rig::until("what it said is wiped", secs(10), || {
        !client.screen().contains("no link")
    });
    // A server that sends what is no message: koh ends, saying so.
    let (mut client, _conn, mut send, _typed, _) = comes(&rig, &server, "b").await;
    draws(&mut send, &format!("{begins}\x1b[5;5HSHOWN")).await;
    rig::until("the screen", secs(10), || client.screen().contains("SHOWN"));
    let long = ViewOutput::Bytes(vec![b'x'; VIEW_FRAME + 1]);
    // (The client reads its length and no further: the rest is sent to nobody.)
    let _ = send_msg(&mut send, &long, MAX_CTRL).await;
    let ended = client.ends(secs(10)).await.unwrap_err();
    assert!(
        ended.code == koh::Exit::FAILED && ended.message.contains("exceeds bound"),
        "{ended:?}"
    );
    the_terminal_is_put_back(&client, "after what no server says");
}
