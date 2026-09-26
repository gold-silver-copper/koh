//! The client bell hook end to end: a real shell rings the bell, the client runs the hook command,
//! a burst of bells is rate-limited, bells from before the attach do not fire, and bells during a
//! reconnect do.

use std::path::{Path, PathBuf};
use std::time::Duration;

use koh_core::client::BellHook;

use crate::harness::{identity, Client, Options, Server};
use crate::link::{FaultNet, Profile};

const WAIT: Duration = Duration::from_secs(15);

/// A scratch directory and a hook that appends one line per spawn to `rang.log` in it.
fn hook(name: &str) -> std::io::Result<(PathBuf, PathBuf, BellHook)> {
    let dir = std::env::temp_dir().join(format!("koh-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let log = dir.join("rang.log");
    let hook = BellHook::new(format!("echo rang $KOH_BELL_COUNT >> '{}'", log.display()));
    Ok((dir, log, hook))
}

/// How many times the hook has spawned.
fn spawns(log: &Path) -> usize {
    std::fs::read_to_string(log).map_or(0, |s| s.lines().count())
}

async fn wait_for_spawns(log: &Path, n: usize) {
    for _ in 0..100 {
        if spawns(log) >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[test]
fn a_remote_bell_runs_the_hook_at_most_once_a_second() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            let net = FaultNet::new(Profile::default(), 1);
            let secret = identity().expect("OS randomness");
            let server = Server::start(&net, &[secret.public()], &["sh"])
                .await
                .expect("start the server");
            let (dir, log, hook) = hook("bell-hook").expect("scratch dir");
            let endpoint = net.endpoint(secret, false).await.expect("bind");
            let mut client = Client::connect_on(
                endpoint,
                server.id,
                Options {
                    bell: Some(hook),
                    ..Options::default()
                },
            )
            .await
            .expect("connect");
            assert!(client
                .wait_until(WAIT, |t| !t.trim().is_empty())
                .await
                .is_some());

            client
                .send(b"printf '\\a'; echo BELL_O''NE\r")
                .await
                .expect("type");
            wait_for_spawns(&log, 1).await;
            assert_eq!(
                spawns(&log),
                1,
                "the first bell spawns the hook exactly once"
            );

            // Past the rate-limit window, five bells in one command coalesce: one more spawn, maybe two.
            tokio::time::sleep(Duration::from_millis(1100)).await;
            client
                .send(b"printf '\\a\\a\\a\\a\\a'; echo BELL_BU''RST\r")
                .await
                .expect("type");
            assert!(client
                .wait_until(WAIT, |t| t.contains("BELL_BURST"))
                .await
                .is_some());
            tokio::time::sleep(Duration::from_millis(300)).await;
            let n = spawns(&log);
            assert!(
                (2..=3).contains(&n),
                "a burst of five bells must coalesce, got {n} spawns"
            );
            let content = std::fs::read_to_string(&log).expect("the log");
            assert!(
                content.contains("rang 1"),
                "KOH_BELL_COUNT reaches the hook: {content:?}"
            );

            let _ = client.finish().await;
            server.stop().await;
            let _ = std::fs::remove_dir_all(&dir);
        });
}

#[test]
fn stale_bells_before_attach_do_not_fire_but_bells_after_a_reconnect_do() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            // The bell count is cumulative per server session. A bell rung before the hooked client
            // attaches must not fire the hook (the first synced frame primes it); a bell rung while the
            // client is reconnecting must (the hook is not re-primed).
            let net = FaultNet::new(Profile::default(), 1);
            let secret = identity().expect("OS randomness");
            let server = Server::start(&net, &[secret.public()], &["sh"])
                .await
                .expect("start the server");
            let endpoint = net.endpoint(secret, false).await.expect("bind");

            // Connection #1, without a hook, rings the bell once and leaves.
            let mut first = Client::connect_on(endpoint.clone(), server.id, Options::default())
                .await
                .expect("connect #1");
            first
                .send(b"printf '\\a'; echo STALE''_BELL\r")
                .await
                .expect("type");
            assert!(first
                .wait_until(WAIT, |t| t.contains("STALE_BELL"))
                .await
                .is_some());
            let _ = first.finish().await;

            // Connection #2 carries the hook and attaches to a session whose count is already 1.
            let (dir, log, hook) = hook("bell-stale").expect("scratch dir");
            let mut client = Client::connect_on(
                endpoint,
                server.id,
                Options {
                    bell: Some(hook),
                    ..Options::default()
                },
            )
            .await
            .expect("connect #2");
            assert!(client
                .wait_until(WAIT, |t| t.contains("STALE_BELL"))
                .await
                .is_some());
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert_eq!(
                spawns(&log),
                0,
                "a bell from before the attach must not fire the hook"
            );

            // A delayed bell, then a dropped connection: whether the bell lands before or after the
            // reconnect, it is a rise past the primed count and fires once when the client is back.
            client
                .send(b"sleep 1; printf '\\a'; echo OUTAGE''_BELL\r")
                .await
                .expect("type");
            tokio::time::sleep(Duration::from_millis(200)).await;
            client.drop_first_connection();
            assert!(
                client
                    .wait_until(WAIT, |t| t.contains("OUTAGE_BELL"))
                    .await
                    .is_some(),
                "the client reconnected and saw the outage command's output; screen:\n{}",
                client.screen()
            );
            wait_for_spawns(&log, 1).await;
            assert_eq!(
                spawns(&log),
                1,
                "the bell during the outage fires the hook once"
            );

            let _ = client.finish().await;
            server.stop().await;
            let _ = std::fs::remove_dir_all(&dir);
        });
}
