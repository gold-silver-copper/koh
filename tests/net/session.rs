//! A session end to end: a PTY-hosted `sh` behind `koh serve`, driven through `koh connect`.
//!
//! Covers what a session must survive: flow-control bytes in the input, many connects and
//! disconnects in a row (with and without input in flight), a window resize, a disconnect and
//! reattach, and the shell exiting.

use std::time::Duration;

use crate::harness::{hosting, identity, session, Client, Options, Painted, Server};
use crate::link::{FaultNet, Profile};

const WAIT: Duration = Duration::from_secs(15);

fn clean() -> FaultNet {
    FaultNet::new(Profile::default(), 1)
}

/// Every packet of a session crosses the fault link, and nothing routes around it: the session
/// stops through an outage of the link and recovers after.
#[test]
fn the_fault_link_is_the_only_path() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, mut client) = session(&net, &["sh"]).await.expect("start a session");
            // `ON''E` so the typed command itself never matches the output.
            assert!(
                client.ran(b"echo ON''E\r", "ONE").await,
                "{}",
                client.screen()
            );
            assert!(
                net.delivered(server.id).packets > 0,
                "nothing reached the server"
            );
            assert!(
                net.delivered(client.id).packets > 0,
                "nothing reached the client"
            );

            net.black_hole(Duration::from_secs(3));
            client.send(b"echo TW''O\r").await.expect("type");
            assert!(
                client
                    .wait_until(Duration::from_secs(2), |t| t.contains("TWO"))
                    .await
                    .is_none(),
                "the session kept working through an outage of the only link"
            );
            assert!(
                client
                    .wait_until(Duration::from_secs(20), |t| t.contains("TWO"))
                    .await
                    .is_some(),
                "the session never recovered; screen:\n{}",
                client.screen()
            );
            let _ = client.finish().await;
            server.stop().await.expect("the server stops cleanly");
        });
}

/// A ^S (XOFF) / ^Q (XON) cycle in the input does not break the session: output after it still
/// flows. (koh's PTY reader is a dedicated blocking thread, so the BSD select+read race that could
/// wedge a session cannot occur; this guards the observable contract.)
#[test]
fn xon_xoff_does_not_wedge_the_session() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, mut client) = session(&net, &["sh"]).await.expect("start a session");
            assert!(client.ran(b"echo XON_O''NE\r", "XON_ONE").await);
            assert!(
                client.ran(b"\x13\x11echo XON_T''WO\r", "XON_TWO").await,
                "output must flow across a ^S/^Q cycle; screen:\n{}",
                client.screen()
            );
            let _ = client.finish().await;
            server.stop().await.expect("the server stops cleanly");
        });
}

/// Many connections in a row, each closed or dropped (with input in flight), reattach the same
/// session: a variable the first connection set is still there. A leak or teardown race shows up
/// as a hang or a failure on some iteration; a new shell, as the variable gone.
#[test]
fn many_connects_in_a_row_reattach_the_same_session() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, endpoint) = hosting(&net, &["sh"]).await.expect("start the server");
            for i in 0..20 {
                let mut client =
                    Client::connect_on(endpoint.clone(), server.id, Options::default())
                        .await
                        .unwrap_or_else(|e| panic!("iteration {i}: connect failed: {e:#}"));
                let set = if i == 0 { "KEPT=SAME; " } else { "" };
                let typed = format!("\r\r{set}echo REPEAT''_{i}_$KEPT\r");
                assert!(
                    client
                        .ran(typed.as_bytes(), &format!("REPEAT_{i}_SAME"))
                        .await,
                    "iteration {i}; screen:\n{}",
                    client.screen()
                );
                // Every other one goes without a goodbye, more input on its way.
                if i % 2 == 0 {
                    let _ = client.finish().await;
                } else {
                    client.send(b"\r\r\r\r\r").await.expect("type");
                    client.abort();
                }
            }
            server.stop().await.expect("the server stops cleanly");
        });
}

#[test]
fn a_window_resize_reaches_the_shell() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, mut client) = session(&net, &["sh"]).await.expect("start a session");
            client.resize_to(30, 100).await.expect("resize");
            assert!(
                client.ran(b"stty size\r", "30 100").await,
                "after resizing to 30x100, `stty size` must report it; screen:\n{}",
                client.screen()
            );
            let _ = client.finish().await;
            server.stop().await.expect("the server stops cleanly");
        });
}

/// A new connection, typing nothing, is repainted the detached session's screen.
#[test]
fn a_detached_session_is_reattached_at_its_current_screen() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, endpoint) = hosting(&net, &["sh"]).await.expect("start the server");
            let mut first = Client::connect_on(endpoint.clone(), server.id, Options::default())
                .await
                .expect("connect #1");
            assert!(
                first
                    .ran(b"echo REATTACH''_MARKER\r", "REATTACH_MARKER")
                    .await
            );
            let _ = first.finish().await;
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
            server.stop().await.expect("the server stops cleanly");
        });
}

#[test]
fn the_shell_exit_status_becomes_the_client_result() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, client) = session(&net, &["sh"]).await.expect("start a session");
            client.send(b"exit 42\r").await.expect("type");
            let result = client.exit(WAIT).await.expect("the client returns");
            assert_eq!(result.expect("a clean end"), Some(42));
            server.stop().await.expect("the server stops cleanly");
        });
}

/// The program puts its terminal in raw mode and never reads. Pasting megabytes must not block
/// the client: the PTY queue fills, the server stops reading, QUIC flow control stops the client's
/// stream, and typing past the client's own queue is dropped with a status line. The quit escape
/// still works.
#[test]
fn a_program_that_stops_reading_input_never_freezes_the_client() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
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
            client
                .send(&[0x1e, b'.'])
                .await
                .expect("type the quit escape");
            let result = client.exit(Duration::from_secs(5)).await;
            assert!(
                matches!(result, Some(Ok(None))),
                "Ctrl-^ . must quit while the server is not reading: {result:?}"
            );
            server.stop().await.expect("the server stops cleanly");
        });
}

/// Keystrokes that never stop coming do not starve the frames: the client still shows the
/// program's output while the user's terminal floods it with input.
#[test]
fn a_flood_of_typing_does_not_starve_the_frames() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, mut client) = session(
                &net,
                &[
                    "sh",
                    "-c",
                    "stty raw -echo; cat >/dev/null & i=0; while :; do echo TICK $i; i=$((i+1)); sleep 0.05; done",
                ],
            )
            .await
            .expect("start a session");
            assert!(client
                .wait_until(WAIT, |t| t.contains("TICK 1"))
                .await
                .is_some());
            let printed = |t: &str| {
                t.lines()
                    .filter_map(|line| line.trim().strip_prefix("TICK ")?.parse::<u32>().ok())
                    .max()
                    .unwrap_or(0)
            };
            let before = printed(&client.screen());
            // Typing all the while, until 20 more ticks are shown.
            let chunk = vec![b'y'; 1024];
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            while printed(&client.screen()) < before + 20 && tokio::time::Instant::now() < deadline
            {
                client.send(&chunk).await.expect("type");
            }
            let during = printed(&client.screen());
            server.stop().await.expect("the server stops cleanly");
            assert!(
                during >= before + 20,
                "the program's output stopped reaching the client while it was typed at: TICK \
                 {before} then {during}"
            );
        });
}

/// A phone screen turning off: the connection dies mid-session while the shell keeps running. The
/// client reconnects and lands back on the same shell, with the earlier output still on screen.
#[test]
fn a_forced_mid_session_drop_reconnects_to_the_same_shell() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, mut client) = session(&net, &["sh"]).await.expect("start a session");
            assert!(client.ran(b"echo MARK_O''NE\r", "MARK_ONE").await);
            client.drop_first_connection();
            let ran = client
                .retype_until(b"echo MARK_T''WO\r", |t| t.contains("MARK_TWO"))
                .await;
            assert!(
                ran.is_some_and(|p| p.text.contains("MARK_ONE")),
                "the reconnect must reattach the SAME shell (MARK_ONE kept); screen:\n{}",
                client.screen()
            );
            let _ = client.finish().await;
            server.stop().await.expect("the server stops cleanly");
        });
}

/// Mode 2048: the program gets `CSI 48 ; rows ; cols ; 0 ; 0 t` when it sets the mode, and again
/// after each resize. `cat -v` shows what reaches its input.
#[test]
fn a_program_that_asked_hears_of_a_resize_on_its_input() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
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
            server.stop().await.expect("the server stops cleanly");
        });
}

/// The scrollback view (Ctrl-^ [, then g for the oldest row) shows what scrolled off, and fetches
/// it afresh once reattached.
#[test]
fn scrollback_shows_output_that_scrolled_off_and_again_after_a_reattach() {
    koh_testkit::multi_thread(4)
        .expect("runtime")
        .block_on(async {
            let net = FaultNet::new(Profile::default(), 7);
            let (server, mut client) = session(&net, &["sh"]).await.expect("session");
            assert!(client.ran(OLD_LINES, "old line 199").await);
            client.send(b"\x1e[g").await.expect("send");
            assert!(
                client.wait_until(WAIT, oldest).await.is_some(),
                "the view never showed the oldest row:\n{}",
                client.screen()
            );
            client.send(b"q").await.expect("send");
            client.drop_first_connection();
            assert!(
                client.retype_until(b"q\x1e[g", oldest).await.is_some(),
                "no scrollback after the reattach:\n{}",
                client.screen()
            );
            let _ = client.send(b"q").await;
            let _ = client.finish().await;
            server.stop().await.expect("the server stops cleanly");
        });
}

/// What the scrollback tests type: 200 lines, most of which scroll off.
const OLD_LINES: &[u8] = b"i=0; while [ $i -lt 200 ]; do echo old line $i; i=$((i+1)); done\r";

/// Whether `screen` shows the first line [`OLD_LINES`] wrote.
fn oldest(screen: &str) -> bool {
    screen.lines().any(|line| line.trim_end() == "old line 0")
}

/// A client frozen between dialing and its loop (a phone asleep while it enters raw mode, at
/// connect) reconnects as from any freeze: the freeze detector counts from the dial, not from the
/// loop's first iteration. Found on the Android emulator, where the client was stopped in the
/// start-up probe's wait, which is gone since.
#[test]
fn a_freeze_between_dialing_and_the_loop_still_reconnects() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, endpoint) = hosting(&net, &["sh"]).await.expect("start the server");
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
            assert!(
                client
                    .retype_until(b"echo AFTER''_FREEZE\r", |t| t.contains("AFTER_FREEZE"))
                    .await
                    .is_some(),
                "the reconnected client must reach the shell:\n{}",
                client.screen()
            );
            let _ = client.finish().await;
            server.stop().await.expect("the server stops cleanly");
        });
}

/// Whether the client is painting its "reconnecting" banner.
fn reconnecting(painted: &Painted) -> bool {
    painted
        .status
        .as_deref()
        .is_some_and(|status| status.contains("reconnecting"))
}

/// The client reads keys while it redials: the escape typed at the reconnecting banner quits.
#[test]
fn the_escape_quits_at_the_reconnecting_banner() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, mut client) = session(&net, &["sh"]).await.expect("start a session");
            assert!(client.ran(b"echo RE''ADY\r", "READY").await);
            net.black_hole(Duration::from_secs(6));
            client.drop_first_connection();
            assert!(
                client.wait_for(WAIT, reconnecting).await.is_some(),
                "the client must show the reconnecting banner"
            );
            client.send(b"\x1e.").await.expect("type the escape");
            let result = client.exit(Duration::from_secs(3)).await;
            server.stop().await.expect("the server stops cleanly");
            assert!(matches!(result, Some(Ok(None))), "{result:?}");
        });
}

/// A redial goes back to the session the client was on, never to another: after a server restart
/// during the outage that session is gone, though the new server would start one, and the client
/// ends saying so instead of typing into a new shell.
#[test]
fn after_a_server_restart_the_client_ends_as_its_session_is_gone() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let client_secret = identity().expect("OS randomness");
            let server_secret = identity().expect("OS randomness");
            let allow = [client_secret.public()];
            let server = Server::start_as(&net, server_secret.clone(), &allow, &["sh"])
                .await
                .expect("start the server");
            let mut client = Client::connect(&net, client_secret, server.id)
                .await
                .expect("connect");
            assert!(client.ran(b"echo RE''ADY\r", "READY").await);
            // The server restarts during an outage.
            net.black_hole(Duration::from_secs(3));
            client.drop_first_connection();
            server.stop().await.expect("the server stops cleanly");
            let server = Server::start_as(&net, server_secret, &allow, &["sh"])
                .await
                .expect("restart the server");
            let ended = client.exit(Duration::from_secs(30)).await;
            server.stop().await.expect("the server stops cleanly");
            let Some(Err(error)) = ended else {
                panic!("the client went on: {ended:?}");
            };
            assert!(
                matches!(
                    error.downcast_ref(),
                    Some(koh::client::Refused::NoSuchSession)
                ),
                "{error:#}"
            );
        });
}
