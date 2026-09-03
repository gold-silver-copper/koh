//! The client bell hook end to end (KB-01, KB-02): a real PTY shell rings the bell, the client
//! (over the generic `run_client_with` wiring) runs the hook command, a burst of bells is
//! rate-limited, bells from before the attach do not fire, and bells during a reconnect do.

// Integration test: a failed unwrap/expect/assert IS the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::items_after_statements,
    clippy::default_trait_access,
    clippy::unwrap_in_result,
    reason = "integration test code; panics are assertion failures"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use koh::client::{run_client_with, BellHook, ClientTerminal, IrohConnector};
use koh::input::UserInput;
use koh::predict::{DisplayPreference, Overlay};
use koh::server::session::spawn_session;
use koh::server::{run_attached, run_session, ClientId, SessionExit};
use koh::ssp::Transport;
use koh::terminal::TerminalScreen;
use koh::transport_iroh::{
    bind_endpoint_local, generate_secret_key, loopback_addr, IrohChannel, MonoClock, ALPN,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

struct MockTerminal {
    latest: Arc<Mutex<String>>,
}

impl ClientTerminal<TerminalScreen> for MockTerminal {
    fn render(
        &mut self,
        state: &TerminalScreen,
        _overlay: &Overlay,
        _status: Option<&str>,
    ) -> std::io::Result<()> {
        *self.latest.lock().unwrap() = state.screen().contents();
        Ok(())
    }

    fn size(&self) -> std::io::Result<(u16, u16)> {
        Ok((24, 80))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_bell_runs_the_hook_once_per_second_at_most() {
    let server_ep = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let addr = loopback_addr(&server_ep);
    let accept = tokio::spawn(async move {
        while let Some(incoming) = server_ep.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                koh::transport_iroh::admission::admit(&conn)
                    .await
                    .expect("admit");
                let _ = run_session(conn, &["sh".to_owned()], 0).await;
            });
        }
    });

    let tmp = std::env::temp_dir().join(format!("koh-bell-hook-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let log = tmp.join("rang.log");
    // Each spawn appends one line, so the line count is the spawn count.
    let hook = BellHook::new(format!("echo rang $KOH_BELL_COUNT >> '{}'", log.display()));

    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let connector = IrohConnector::new(client_ep, addr);
    let channel = connector.connect().await.expect("connect");
    let latest = Arc::new(Mutex::new(String::new()));
    let term = MockTerminal {
        latest: latest.clone(),
    };
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(8);
    let (_resize_tx, resize_rx) = mpsc::channel::<()>(1);
    let shutdown = CancellationToken::new();
    let client = tokio::spawn(run_client_with(
        channel,
        connector,
        DisplayPreference::Always,
        (24, 80),
        input_rx,
        resize_rx,
        term,
        shutdown.clone(),
        Some(hook),
    ));

    // One bell: the hook fires within the marker deadline.
    input_tx
        .send(b"printf '\\a'; echo BELL_ONE\r".to_vec())
        .await
        .unwrap();
    let mut lines = 0;
    for _ in 0..100 {
        lines = std::fs::read_to_string(&log).map_or(0, |s| s.lines().count());
        if lines >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(lines, 1, "the first bell spawns the hook exactly once");

    // Wait out the rate-limit window, then five bells in one command: at most one more spawn
    // (the burst coalesces), never five.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    input_tx
        .send(b"printf '\\a\\a\\a\\a\\a'; echo BELL_BURST\r".to_vec())
        .await
        .unwrap();
    for _ in 0..30 {
        if latest.lock().unwrap().contains("BELL_BURST") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let lines = std::fs::read_to_string(&log).map_or(0, |s| s.lines().count());
    assert!(
        (2..=3).contains(&lines),
        "a burst of five bells must coalesce to at most one or two spawns, got {lines}"
    );
    let content = std::fs::read_to_string(&log).unwrap();
    assert!(
        content.contains("rang 1"),
        "KOH_BELL_COUNT is exported to the hook: {content:?}"
    );

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), client).await;
    accept.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}

/// Line count of the hook's log, or 0 if it does not exist yet.
fn spawns(log: &std::path::Path) -> usize {
    std::fs::read_to_string(log).map_or(0, |s| s.lines().count())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_bells_before_attach_do_not_fire_but_bells_after_reconnect_do() {
    // KB-02: the bell count is cumulative per server session. A bell rung BEFORE the hooked
    // client attaches must not fire the hook (the first synced frame primes it); a bell rung
    // while the client is reconnecting must (the hook is not re-primed).
    let server_ep = bind_endpoint_local(generate_secret_key(), true)
        .await
        .expect("bind server");
    let addr = loopback_addr(&server_ep);
    let (kill_tx, kill_rx) = oneshot::channel::<()>();
    // One detachable pty session, accepted over a loop: a raw first connection rings the bell,
    // the hooked client attaches second, and its reconnect reattaches the same shell.
    let accept = tokio::spawn(async move {
        let handle = spawn_session(&["sh".to_owned()], 0).expect("spawn session");
        let mut arm_kill = Some(kill_rx);
        let mut seen = 0u32;
        while let Some(incoming) = server_ep.accept().await {
            let Ok(conn) = incoming.await else { continue };
            seen += 1;
            // The hooked client's FIRST connection (#2) is force-closed when the test says so.
            if seen == 2 {
                if let Some(krx) = arm_kill.take() {
                    let victim = conn.clone();
                    tokio::spawn(async move {
                        if krx.await.is_ok() {
                            IrohChannel::new(victim).close(0, b"simulated idle timeout");
                        }
                    });
                }
            }
            if koh::transport_iroh::admission::admit(&conn).await.is_err() {
                continue;
            }
            match run_attached(conn, handle.clone(), ClientId::next()).await {
                Ok(SessionExit::Detached) => {}
                _ => break,
            }
        }
    });

    // Connection #1: a raw transport rings the bell once, then leaves.
    {
        let ep = bind_endpoint_local(generate_secret_key(), false)
            .await
            .expect("bind raw client");
        let conn = ep.connect(addr.clone(), ALPN).await.expect("raw connect");
        koh::transport_iroh::admission::await_admission(&conn)
            .await
            .expect("admitted");
        let chan = IrohChannel::new(conn);
        let clock = MonoClock::new();
        let mut t =
            Transport::<UserInput, TerminalScreen>::new(clock.now_ms(), chan.max_datagram_size());
        t.set_connected(true);
        t.observe_rtt(10.0);
        t.current_mut()
            .push_bytes(b"printf '\\a'; echo STALE_BELL\r");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline && t.remote_state().bell_count() < 1 {
            for dg in t.tick(clock.now_ms()) {
                chan.send(&dg);
            }
            tokio::select! {
                r = chan.recv() => { if let Ok(b) = r { t.recv(clock.now_ms(), &b); } }
                () = tokio::time::sleep(Duration::from_millis(5)) => {}
            }
        }
        assert!(t.remote_state().bell_count() >= 1, "the stale bell rang");
        chan.close(0, b"raw client leaves");
        // Flush the CONNECTION_CLOSE before the endpoint goes away, so the server's loop detaches
        // now rather than at the idle timeout.
        ep.close().await;
    }

    let tmp = std::env::temp_dir().join(format!("koh-bell-stale-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let log = tmp.join("rang.log");
    let hook = BellHook::new(format!("echo rang $KOH_BELL_COUNT >> '{}'", log.display()));

    // Connection #2: the hooked client attaches to the session whose count is already >= 1.
    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let connector = IrohConnector::new(client_ep, addr);
    let channel = connector.connect().await.expect("connect");
    let latest = Arc::new(Mutex::new(String::new()));
    let term = MockTerminal {
        latest: latest.clone(),
    };
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(8);
    let (_resize_tx, resize_rx) = mpsc::channel::<()>(1);
    let shutdown = CancellationToken::new();
    let client = tokio::spawn(run_client_with(
        channel,
        connector,
        DisplayPreference::Always,
        (24, 80),
        input_rx,
        resize_rx,
        term,
        shutdown.clone(),
        Some(hook),
    ));
    for _ in 0..100 {
        if latest.lock().unwrap().contains("STALE_BELL") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        latest.lock().unwrap().contains("STALE_BELL"),
        "the hooked client synced the existing screen"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        spawns(&log),
        0,
        "a bell from before the attach must not fire the hook"
    );

    // Ring during the outage: arm a delayed bell, then force-close connection #2. Whether the
    // bell lands before or after the reconnect completes, it is a rise past the primed count
    // and must fire exactly once after the client is back.
    input_tx
        .send(b"sleep 1; printf '\\a'; echo OUTAGE_BELL\r".to_vec())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    kill_tx.send(()).expect("force the drop");
    for _ in 0..150 {
        if latest.lock().unwrap().contains("OUTAGE_BELL") && spawns(&log) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        latest.lock().unwrap().contains("OUTAGE_BELL"),
        "the client reconnected and saw the outage command's output"
    );
    assert_eq!(
        spawns(&log),
        1,
        "the bell during the outage fires the hook once after reconnect"
    );

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), client).await;
    accept.abort();
    let _ = std::fs::remove_dir_all(&tmp);
}
