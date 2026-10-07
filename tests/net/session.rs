//! A session end to end: a PTY-hosted `sh` behind `koh serve`, driven through `koh connect`.
//!
//! Covers what a session must survive: flow-control bytes in the input, many connects and
//! disconnects in a row (with and without input in flight), a window resize, a disconnect and
//! reattach, and the shell exiting.

use std::time::Duration;

use crate::harness::{identity, session, Client, Options, Server};
use crate::link::{FaultNet, Profile};

const WAIT: Duration = Duration::from_secs(15);

fn clean() -> FaultNet {
    FaultNet::new(Profile::default(), 1)
}

#[test]
fn xon_xoff_does_not_wedge_the_session() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            // A ^S (XOFF) / ^Q (XON) cycle in the input must not break the session: output after it still
            // flows. (koh's PTY reader is a dedicated blocking thread, so the BSD select+read race that
            // could wedge a session cannot occur; this guards the observable contract.)
            let net = clean();
            let (server, mut client) = session(&net, &["sh"]).await.expect("start a session");
            client.send(b"echo XON_O''NE\r").await.expect("type");
            assert!(client
                .wait_until(WAIT, |t| t.contains("XON_ONE"))
                .await
                .is_some());
            client
                .send(b"\x13\x11echo XON_T''WO\r")
                .await
                .expect("type");
            assert!(
                client
                    .wait_until(WAIT, |t| t.contains("XON_TWO"))
                    .await
                    .is_some(),
                "the session must keep delivering output across a ^S/^Q cycle; screen:\n{}",
                client.screen()
            );
            let _ = client.finish().await;
            server.stop().await;
        });
}

#[test]
fn many_connects_in_a_row_reattach_the_same_session() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            // A leak or teardown race shows up as a hang or a failure on some iteration.
            let net = clean();
            let secret = identity().expect("OS randomness");
            let server = Server::start(&net, &[secret.public()], &["sh"])
                .await
                .expect("start the server");
            let endpoint = net.endpoint(secret, false).await.expect("bind the client");
            for i in 0..20 {
                let mut client =
                    Client::connect_on(endpoint.clone(), server.id, Options::default())
                        .await
                        .unwrap_or_else(|e| panic!("iteration {i}: connect failed: {e:#}"));
                let marker = format!("REPEAT_{i}");
                client
                    .send(format!("echo REPEAT''_{i}\r").as_bytes())
                    .await
                    .expect("type");
                assert!(
                    client
                        .wait_until(WAIT, |t| t.contains(&marker))
                        .await
                        .is_some(),
                    "iteration {i}: {marker} never appeared; screen:\n{}",
                    client.screen()
                );
                let _ = client.finish().await;
            }
            server.stop().await;
        });
}

#[test]
fn connections_dropped_with_input_in_flight_do_not_hurt_the_session() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            // Input arriving as or after a connection tears down must not crash the server. Each
            // iteration sends a burst of CRs, confirms a marker, then drops the connection without
            // a close.
            let net = clean();
            let secret = identity().expect("OS randomness");
            let server = Server::start(&net, &[secret.public()], &["sh"])
                .await
                .expect("start the server");
            let endpoint = net.endpoint(secret, false).await.expect("bind the client");
            for i in 0..15 {
                let mut client =
                    Client::connect_on(endpoint.clone(), server.id, Options::default())
                        .await
                        .unwrap_or_else(|e| panic!("iteration {i}: connect failed: {e:#}"));
                client.send(b"\r\r\r\r\r").await.expect("type");
                let marker = format!("RWI_{i}");
                client
                    .send(format!("echo RWI''_{i}\r").as_bytes())
                    .await
                    .expect("type");
                assert!(
                    client
                        .wait_until(WAIT, |t| t.contains(&marker))
                        .await
                        .is_some(),
                    "iteration {i}: {marker} never appeared under input spam; screen:\n{}",
                    client.screen()
                );
                client.send(b"\r\r\r\r\r").await.expect("type");
                client.abort();
            }
            server.stop().await;
        });
}

#[test]
fn a_window_resize_reaches_the_shell() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, mut client) = session(&net, &["sh"]).await.expect("start a session");
            client.resize_to(30, 100).await.expect("resize");
            client.send(b"stty size\r").await.expect("type");
            assert!(
                client
                    .wait_until(WAIT, |t| t.contains("30 100"))
                    .await
                    .is_some(),
                "after resizing to 30x100, `stty size` must report it; screen:\n{}",
                client.screen()
            );
            let _ = client.finish().await;
            server.stop().await;
        });
}

#[test]
fn a_detached_session_is_reattached_at_its_current_screen() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let secret = identity().expect("OS randomness");
            let server = Server::start(&net, &[secret.public()], &["sh"])
                .await
                .expect("start the server");
            let endpoint = net.endpoint(secret, false).await.expect("bind the client");
            let mut first = Client::connect_on(endpoint.clone(), server.id, Options::default())
                .await
                .expect("connect #1");
            first.send(b"echo REATTACH''_MARKER\r").await.expect("type");
            assert!(first
                .wait_until(WAIT, |t| t.contains("REATTACH_MARKER"))
                .await
                .is_some());
            let _ = first.finish().await;
            // No input this time: the new connection must repaint the same session's screen.
            let mut second = Client::connect_on(endpoint, server.id, Options::default())
                .await
                .expect("connect #2");
            assert!(
                second
                    .wait_until(WAIT, |t| t.contains("REATTACH_MARKER"))
                    .await
                    .is_some(),
                "the reconnect must show the same session; screen:\n{}",
                second.screen()
            );
            let _ = second.finish().await;
            server.stop().await;
        });
}

#[test]
fn the_shell_exit_status_becomes_the_client_result() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, client) = session(&net, &["sh"]).await.expect("start a session");
            client.send(b"exit 42\r").await.expect("type");
            let result = client.exit(WAIT).await.expect("the client returns");
            assert_eq!(result.expect("a clean end"), Some(42));
            server.stop().await;
        });
}

#[test]
fn a_program_that_stops_reading_input_never_freezes_the_client() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            // The program puts its terminal in raw mode and never reads. Pasting megabytes must not block
            // the client: the PTY queue fills, the server stops reading, QUIC flow control stops the
            // client's stream, and typing past the client's own queue is dropped with a status line. The
            // quit escape still works at once.
            let net = clean();
            let (server, mut client) = session(
                &net,
                &[
                    "sh",
                    "-c",
                    "stty raw -echo; echo NOT_READING; exec sleep 600",
                ],
            )
            .await
            .expect("start a session");
            assert!(client
                .wait_until(WAIT, |t| t.contains("NOT_READING"))
                .await
                .is_some());
            // 16 MiB: more than the PTY, the server's queue, QUIC's windows and the client's queue
            // hold, in reads of 1 KiB as koh's stdin reader makes them.
            let chunk = vec![b'y'; 1024];
            for _ in 0..16 * 1024 {
                client.send(&chunk).await.expect("type");
            }
            assert!(
                client
                    .wait_for(WAIT, |p| p
                        .status
                        .as_deref()
                        .is_some_and(|s| s.contains("input paused")))
                    .await
                    .is_some(),
                "typing past what the server takes is reported"
            );
            let quit_at = tokio::time::Instant::now();
            client
                .send(&[0x1e, b'.'])
                .await
                .expect("type the quit escape");
            let result = client.exit(Duration::from_secs(5)).await;
            assert!(
                matches!(result, Some(Ok(None))),
                "Ctrl-^ . must quit promptly while the server is not reading: {result:?}"
            );
            let took = quit_at.elapsed();
            assert!(
                took < Duration::from_secs(2),
                "the quit escape took {took:?} behind the flood"
            );
            server.stop().await;
        });
}

#[test]
fn a_forced_mid_session_drop_reconnects_to_the_same_shell() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            // A phone screen turning off: the connection dies mid-session while the shell keeps
            // running. The client must transparently reconnect and land back on the same shell, with the
            // earlier output still on screen.
            let net = clean();
            let secret = identity().expect("OS randomness");
            let server = Server::start(&net, &[secret.public()], &["sh"])
                .await
                .expect("start the server");
            let endpoint = net.endpoint(secret, false).await.expect("bind the client");
            let mut client = Client::connect_on(endpoint, server.id, Options::default())
                .await
                .expect("connect");
            client.send(b"echo MARK_O''NE\r").await.expect("type");
            assert!(client
                .wait_until(WAIT, |t| t.contains("MARK_ONE"))
                .await
                .is_some());
            // Kill the connection without closing the session; the client should re-dial.
            client.drop_first_connection();
            // Retype until the reattached session runs it (input during the reconnect is dropped).
            let mut ran = false;
            for _ in 0..150 {
                let _ = client.send(b"echo MARK_T''WO\r").await;
                if client
                    .wait_until(Duration::from_millis(200), |t| t.contains("MARK_TWO"))
                    .await
                    .is_some()
                {
                    ran = true;
                    break;
                }
            }
            let screen = client.screen();
            assert!(
                ran,
                "the second command never ran after reconnect; screen:\n{screen}"
            );
            assert!(
        screen.contains("MARK_ONE"),
        "the reconnect must reattach the SAME shell (MARK_ONE preserved); screen:\n{screen}"
    );
            let _ = client.finish().await;
            server.stop().await;
        });
}

#[test]
fn a_program_that_asked_hears_of_a_resize_on_its_input() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            // Mode 2048: the program gets `CSI 48 ; rows ; cols ; 0 ; 0 t` when it sets the mode,
            // and again after each resize. `cat -v` shows what reaches its input.
            let net = clean();
            let (server, mut client) = session(
                &net,
                &[
                    "sh",
                    "-c",
                    "stty raw -echo; printf '\\033[?2048h'; exec cat -v",
                ],
            )
            .await
            .expect("start a session");
            assert!(
                client
                    .wait_until(WAIT, |t| t.contains("^[[48;24;80;0;0t"))
                    .await
                    .is_some(),
                "the report when the mode was set; screen:\n{}",
                client.screen()
            );
            client.resize_to(30, 90).await.expect("resize");
            assert!(
                client
                    .wait_until(WAIT, |t| t.contains("^[[48;30;90;0;0t"))
                    .await
                    .is_some(),
                "the report after the resize; screen:\n{}",
                client.screen()
            );
            let _ = client.finish().await;
            server.stop().await;
        });
}

#[test]
fn scrollback_shows_output_that_scrolled_off_and_again_after_a_reattach() {
    crate::harness::runtime().expect("runtime").block_on(async {
        let net = FaultNet::new(Profile::default(), 7);
        let (server, mut client) = crate::harness::session(&net, &["sh"])
            .await
            .expect("session");
        client
            .send(b"i=0; while [ $i -lt 200 ]; do echo old line $i; i=$((i+1)); done\r")
            .await
            .expect("send");
        assert!(client
            .wait_until(WAIT, |t| t.contains("old line 199"))
            .await
            .is_some());
        // Ctrl-^ [ opens the view; g goes to the oldest row.
        client.send(b"\x1e[g").await.expect("send");
        let top = client.wait_until(WAIT, oldest).await;
        assert!(
            top.is_some(),
            "the view never showed the oldest row:\n{}",
            client.screen()
        );
        client.send(b"q").await.expect("send");
        client.drop_first_connection();
        // Once reattached, the view fetches the history afresh.
        let mut shown = false;
        for _ in 0..150 {
            let _ = client.send(b"q\x1e[g").await;
            if client
                .wait_until(Duration::from_millis(200), oldest)
                .await
                .is_some()
            {
                shown = true;
                break;
            }
        }
        assert!(
            shown,
            "no scrollback after the reattach:\n{}",
            client.screen()
        );
        let _ = client.send(b"q").await;
        let _ = client.finish().await;
        server.stop().await;
    });
}

/// Whether `screen` shows the first line the scrollback test wrote.
fn oldest(screen: &str) -> bool {
    screen.lines().any(|line| line.trim_end() == "old line 0")
}

/// A client frozen between dialing and its loop (a phone asleep while the terminal is probed, at
/// connect) reconnects as from any freeze: the freeze detector counts from the dial, not from the
/// loop's first iteration. Found on the Android emulator, where adb's pty answers no probe and
/// the client was stopped inside the probe's wait.
#[test]
fn a_freeze_between_dialing_and_the_loop_still_reconnects() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let secret = identity().expect("OS randomness");
            let server = Server::start(&net, &[secret.public()], &["sh"])
                .await
                .expect("start the server");
            let endpoint = net.endpoint(secret, false).await.expect("bind the client");
            let frozen = std::time::SystemTime::now()
                .checked_sub(Duration::from_secs(30))
                .expect("a time 30 s ago");
            let mut client = Client::connect_on(
                endpoint,
                server.id,
                Options {
                    dialed_at: Some(frozen),
                    ..Options::default()
                },
            )
            .await
            .expect("connect");
            assert!(
                client.first_connection_closes(Duration::from_secs(5)).await,
                "the client must drop the connection it held through the freeze"
            );
            // And the session goes on over the new one (retyped: input during the reconnect is
            // dropped).
            let mut ran = false;
            for _ in 0..75 {
                let _ = client.send(b"echo AFTER''_FREEZE\r").await;
                if client
                    .wait_until(Duration::from_millis(200), |t| t.contains("AFTER_FREEZE"))
                    .await
                    .is_some()
                {
                    ran = true;
                    break;
                }
            }
            assert!(
                ran,
                "the reconnected client must reach the shell:\n{}",
                client.screen()
            );
            let _ = client.finish().await;
            server.stop().await;
        });
}

/// Whether the client is painting its "reconnecting" banner.
fn reconnecting(painted: &crate::harness::Painted) -> bool {
    painted
        .status
        .as_deref()
        .is_some_and(|status| status.contains("reconnecting"))
}

/// A line typed while the link is down is not run after the reattach, and the status line says
/// so: the client cannot tell its session from a new shell (an expired session, a restarted
/// server), where keys typed at the old screen must not run. Typing after the reattach runs.
#[test]
fn a_line_typed_during_an_outage_is_not_run_after_the_reattach_and_the_user_is_told() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let secret = identity().expect("OS randomness");
            let server = Server::start(&net, &[secret.public()], &["sh"])
                .await
                .expect("start the server");
            let endpoint = net.endpoint(secret, false).await.expect("bind the client");
            let mut client = Client::connect_on(endpoint, server.id, Options::default())
                .await
                .expect("connect");
            client.send(b"echo READY''_ONE\r").await.expect("type");
            assert!(client
                .wait_until(WAIT, |t| t.contains("READY_ONE"))
                .await
                .is_some());
            // The link goes down for a while; the client notices and shows its banner.
            net.black_hole(Duration::from_secs(4));
            client.drop_first_connection();
            assert!(
                client.wait_for(WAIT, reconnecting).await.is_some(),
                "the client must show the reconnecting banner"
            );
            // The user types a line while the banner is up.
            client.send(b"echo TYPED''_OFFLINE\r").await.expect("type");
            // Back on the session, the status line says it was not sent.
            assert!(
                client
                    .wait_for(Duration::from_secs(20), |p| p
                        .status
                        .as_deref()
                        .is_some_and(|s| s.contains("not sent")))
                    .await
                    .is_some(),
                "the client must say the outage's typing was not sent; screen:\n{}",
                client.screen()
            );
            client.send(b"echo TYPED''_AFTER\r").await.expect("type");
            assert!(
                client
                    .wait_until(WAIT, |t| t.contains("TYPED_AFTER"))
                    .await
                    .is_some(),
                "typing after the reattach runs; screen:\n{}",
                client.screen()
            );
            assert!(
                !client.screen().contains("TYPED_OFFLINE"),
                "the line typed during the outage must not run; screen:\n{}",
                client.screen()
            );
            let _ = client.finish().await;
            server.stop().await;
        });
}

/// `Ctrl-^ .` quits however the two keys fall around a link drop: the prefix typed while
/// connected and the `.` typed at the reconnecting banner is still the quit escape.
#[test]
fn an_escape_split_across_a_link_drop_still_quits() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let secret = identity().expect("OS randomness");
            let server = Server::start(&net, &[secret.public()], &["sh"])
                .await
                .expect("start the server");
            let endpoint = net.endpoint(secret, false).await.expect("bind the client");
            let mut client = Client::connect_on(endpoint, server.id, Options::default())
                .await
                .expect("connect");
            client.send(b"echo READY''_TWO\r").await.expect("type");
            assert!(client
                .wait_until(WAIT, |t| t.contains("READY_TWO"))
                .await
                .is_some());
            // The prefix, while connected; give the client a moment to take it.
            client.send(&[0x1e]).await.expect("type the prefix");
            tokio::time::sleep(Duration::from_millis(300)).await;
            // The link drops (and stays down), then the '.'.
            net.black_hole(Duration::from_secs(6));
            client.drop_first_connection();
            assert!(
                client.wait_for(WAIT, reconnecting).await.is_some(),
                "the client must show the reconnecting banner"
            );
            client.send(b".").await.expect("type the dot");
            let result = client.exit(Duration::from_secs(3)).await;
            assert!(
                matches!(result, Some(Ok(None))),
                "Ctrl-^ (before the drop) . (during the reconnect) must quit; got {result:?}"
            );
            server.stop().await;
        });
}

/// A line typed across the moment the client notices the drop: its start went out on the dark
/// link and was lost with it, so its end, typed at the banner, must not run alone (here
/// `false && echo DANGEROUS` would run `echo DANGEROUS`).
#[test]
fn the_end_of_a_line_whose_start_was_lost_with_the_link_does_not_run() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let secret = identity().expect("OS randomness");
            let server = Server::start(&net, &[secret.public()], &["sh"])
                .await
                .expect("start the server");
            let endpoint = net.endpoint(secret, false).await.expect("bind the client");
            let mut client = Client::connect_on(endpoint, server.id, Options::default())
                .await
                .expect("connect");
            client.send(b"echo READY''_G\r").await.expect("type");
            assert!(client
                .wait_until(WAIT, |t| t.contains("READY_G"))
                .await
                .is_some());
            net.black_hole(Duration::from_secs(5));
            tokio::time::sleep(Duration::from_millis(200)).await;
            client.send(b"false && ").await.expect("type");
            tokio::time::sleep(Duration::from_secs(1)).await;
            client.drop_first_connection();
            assert!(
                client.wait_for(WAIT, reconnecting).await.is_some(),
                "the client must show the reconnecting banner"
            );
            client.send(b"echo DANGER''OUS\r").await.expect("type");
            // Once back, a line typed then runs: the session goes on.
            let mut back = false;
            for _ in 0..100 {
                let _ = client.send(b"echo BAC''K\r").await;
                if client
                    .wait_until(Duration::from_millis(200), |t| t.contains("BACK"))
                    .await
                    .is_some()
                {
                    back = true;
                    break;
                }
            }
            let screen = client.screen();
            let _ = client.finish().await;
            server.stop().await;
            assert!(back, "the session never came back:\n{screen}");
            assert!(
                !screen.lines().any(|l| l.trim_end() == "DANGEROUS"),
                "the end of a line ran without its start:\n{screen}"
            );
        });
}

/// The reattach lands on a new shell (the server restarted during the outage): the scrollback
/// view shows the new shell's history, not the rows the client held of the old one.
#[test]
fn after_a_server_restart_the_scrollback_is_the_new_shells() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let client_secret = identity().expect("OS randomness");
            let server_secret = identity().expect("OS randomness");
            let allow = [client_secret.public()];
            let server = Server::start_as(&net, server_secret.clone(), &allow, &["sh"])
                .await
                .expect("start the server");
            let endpoint = net
                .endpoint(client_secret, false)
                .await
                .expect("bind the client");
            let mut client = Client::connect_on(endpoint, server.id, Options::default())
                .await
                .expect("connect");
            client
                .send(b"i=0; while [ $i -lt 200 ]; do echo old line $i; i=$((i+1)); done\r")
                .await
                .expect("send");
            assert!(client
                .wait_until(WAIT, |t| t.contains("old line 199"))
                .await
                .is_some());
            // The old shell's history is held: the view showed it.
            client.send(b"\x1e[g").await.expect("send");
            assert!(client.wait_until(WAIT, oldest).await.is_some(), "the view");
            client.send(b"q").await.expect("send");
            // Long enough for the server to confirm the input.
            tokio::time::sleep(Duration::from_millis(500)).await;
            // The server restarts during an outage.
            net.black_hole(Duration::from_secs(3));
            client.drop_first_connection();
            server.stop().await;
            let server = Server::start_as(&net, server_secret, &allow, &["sh"])
                .await
                .expect("restart the server");
            assert!(
                client.wait_for(WAIT, reconnecting).await.is_some(),
                "the client must show the reconnecting banner"
            );
            // Once the client is on the new shell, the loop is typed there.
            assert!(
                client
                    .wait_for(Duration::from_secs(20), |p| !reconnecting(p))
                    .await
                    .is_some(),
                "the client must reattach to the restarted server"
            );
            client
                .send(b"i=0; while [ $i -lt 200 ]; do echo new line $i; i=$((i+1)); done\r")
                .await
                .expect("send");
            let ran = client
                .wait_until(WAIT, |t| t.contains("new line 199"))
                .await
                .is_some();
            assert!(ran, "the new shell never ran:\n{}", client.screen());
            tokio::time::sleep(Duration::from_millis(500)).await;
            client.send(b"\x1e[g").await.expect("send");
            let top = client
                .wait_until(WAIT, |t| t.contains("new line 0") || t.contains("old line"))
                .await;
            let screen = client.screen();
            let _ = client.send(b"q").await;
            let _ = client.finish().await;
            server.stop().await;
            assert!(
                top.is_some_and(|p| !p.text.contains("old line")),
                "the scrollback view shows the dead shell's rows:\n{screen}"
            );
        });
}
