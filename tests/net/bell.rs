//! The client bell hook end to end: a real shell rings the bell, the client runs the hook command,
//! a burst of bells is rate-limited, bells from before the attach do not fire, and bells during a
//! reconnect do.

use std::path::{Path, PathBuf};
use std::time::Duration;

use koh::client::BellHook;

use crate::harness::{hosting, Client, Options};
use crate::link::{FaultNet, Profile};

/// A scratch directory and a hook that appends `rang <bell count>` to `rang.log` in it.
fn hook(name: &str) -> std::io::Result<(koh_testkit::Scratch, PathBuf, BellHook)> {
    let dir = koh_testkit::scratch!(name)?;
    let log = dir.join("rang.log");
    let hook = BellHook::new(format!("echo rang $KOH_BELL_COUNT >> '{}'", log.display()));
    Ok((dir, log, hook))
}

/// The bell count of each time the hook ran, in order.
fn rang(log: &Path) -> Vec<u64> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.strip_prefix("rang ")?.parse().ok())
        .collect()
}

/// Wait up to 10 s for the hook to have run `n` times: the counts it ran with.
async fn wait_for_rings(log: &Path, n: usize) -> Vec<u64> {
    for _ in 0..100 {
        if rang(log).len() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    rang(log)
}

#[test]
fn a_remote_bell_runs_the_hook_at_most_once_a_second() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = FaultNet::new(Profile::default(), 1);
            let (server, endpoint) = hosting(&net, &["sh"]).await.expect("start the server");
            let (_dir, log, hook) = hook("bell-hook").expect("scratch dir");
            let options = Options {
                bell: Some(hook),
                ..Options::default()
            };
            let mut client = Client::connect_on(endpoint, server.id, options)
                .await
                .expect("connect");
            assert!(
                client
                    .ran(b"printf '\\a'; echo BELL_O''NE\r", "BELL_ONE")
                    .await
            );
            assert_eq!(wait_for_rings(&log, 1).await, [1], "the first bell");

            // The rate limit's window is what passes here: past it, five bells in one command
            // coalesce, into one more run, maybe two.
            tokio::time::sleep(Duration::from_millis(1100)).await;
            assert!(
                client
                    .ran(
                        b"printf '\\a\\a\\a\\a\\a'; echo BELL_BU''RST\r",
                        "BELL_BURST"
                    )
                    .await
            );
            wait_for_rings(&log, 2).await;
            // A later frame, past the rate limit's window so that it would not absorb a duplicate
            // run: one for an earlier bell would have started by now.
            tokio::time::sleep(Duration::from_millis(1100)).await;
            assert!(client.ran(b"echo LA''TER\r", "LATER").await);
            let _ = client.finish().await;
            server.stop().await.expect("the server stops cleanly");
            let rang = rang(&log);
            assert!(
                (2..=3).contains(&rang.len()) && rang.is_sorted_by(|a, b| a < b),
                "once for the first bell, once or twice for the burst, never twice for one count: \
                 {rang:?}"
            );
        });
}

/// The bell count is cumulative per server session. A bell rung before the hooked client
/// attaches does not run the hook (the first synced frame primes it); a bell rung while the client
/// is reconnecting does, once (the hook is not re-primed).
#[test]
fn stale_bells_before_attach_do_not_fire_but_bells_after_a_reconnect_do() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            let net = FaultNet::new(Profile::default(), 1);
            let (server, endpoint) = hosting(&net, &["sh"]).await.expect("start the server");

            // Connection #1, without a hook, rings the bell once and leaves.
            let mut first = Client::connect_on(endpoint.clone(), server.id, Options::default())
                .await
                .expect("connect #1");
            assert!(
                first
                    .ran(b"printf '\\a'; echo STALE''_BELL\r", "STALE_BELL")
                    .await
            );
            let _ = first.finish().await;

            // Connection #2 carries the hook and attaches to a session whose count is already 1.
            let (_dir, log, hook) = hook("bell-stale").expect("scratch dir");
            let options = Options {
                bell: Some(hook),
                ..Options::default()
            };
            let mut client = Client::connect_on(endpoint, server.id, options)
                .await
                .expect("connect #2");
            // A delayed bell, then a dropped connection: whether the bell lands before or after the
            // reconnect, it is a rise past the primed count and fires once when the client is back.
            // The shell echoed the line, so it has it.
            assert!(
                client
                    .ran(
                        b"sleep 1; printf '\\a'; echo OUTAGE''_BELL\r",
                        "OUTAGE''_BELL"
                    )
                    .await
            );
            client.drop_first_connection();
            assert!(
                client
                    .wait_until(Duration::from_secs(20), |t| t.contains("OUTAGE_BELL"))
                    .await
                    .is_some(),
                "the client reconnected and saw the outage command's output; screen:\n{}",
                client.screen()
            );
            wait_for_rings(&log, 1).await;
            // A later frame, past the rate limit's window so that it would not absorb a duplicate
            // run: one for an earlier bell would have started by now.
            tokio::time::sleep(Duration::from_millis(1100)).await;
            assert!(client.ran(b"echo LA''TER\r", "LATER").await);
            let _ = client.finish().await;
            server.stop().await.expect("the server stops cleanly");
            assert_eq!(
                rang(&log),
                [2],
                "only the bell during the outage runs the hook, and once"
            );
        });
}
