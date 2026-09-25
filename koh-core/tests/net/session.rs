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
            let secret = identity();
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
            // Input arriving as or after a connection tears down used to be able to crash a server. Each
            // iteration sends a burst of CRs, confirms a marker, then drops the connection without a close.
            let net = clean();
            let secret = identity();
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
            let secret = identity();
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
            // 16 MiB: more than the PTY, the server's queue, QUIC's windows and the client's queue hold.
            let chunk = vec![b'y'; 64 * 1024];
            for _ in 0..256 {
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
            assert!(quit_at.elapsed() < Duration::from_secs(2));
            server.stop().await;
        });
}

#[test]
fn a_forced_mid_session_drop_reconnects_to_the_same_shell() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            // The phone-screen-off regression: the connection dies mid-session while the shell keeps
            // running. The client must transparently reconnect and land back on the same shell, with the
            // earlier output still on screen.
            let net = clean();
            let secret = identity();
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
