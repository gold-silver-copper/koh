//! The screen and the input under every network profile: the screen converges, frames only ever
//! move it forward, and typed input arrives exactly once, in order.

use std::time::Duration;

use crate::harness::session;
use crate::link::{FaultNet, Profile};

const WAIT: Duration = Duration::from_secs(90);

fn lossy() -> Profile {
    Profile {
        loss: 0.05,
        delay: Duration::from_millis(50),
        ..Profile::default()
    }
}

fn bad() -> Profile {
    Profile {
        loss: 0.20,
        delay: Duration::from_millis(150),
        jitter: Duration::from_millis(100),
        dup: 0.02,
        reorder: 0.02,
        ..Profile::default()
    }
}

/// The largest number on a line of its own, as `seq` prints them.
fn largest_seq_line(text: &str) -> Option<u32> {
    text.lines().filter_map(|l| l.trim().parse().ok()).max()
}

/// Print 3000 lines under `profile` (black-holing the link for 2 s mid-output if `outage`), and
/// check the client ends on the final screen without ever painting an older one after a newer one.
async fn converges(profile: Profile, seed: u64, outage: bool) -> anyhow::Result<()> {
    let net = FaultNet::new(profile, seed);
    let (server, mut client) = session(&net, &["sh"]).await?;
    anyhow::ensure!(client
        .wait_until(WAIT, |t| !t.trim().is_empty())
        .await
        .is_some());
    client.send(b"clear; seq 1 30''00; echo E''ND\r").await?;
    if outage {
        tokio::time::sleep(Duration::from_millis(50)).await;
        net.black_hole(Duration::from_secs(2));
    }
    anyhow::ensure!(
        client
            .wait_until(WAIT, |t| t.contains("END")
                && largest_seq_line(t) == Some(3000))
            .await
            .is_some(),
        "seed {seed}: the client never converged; screen:\n{}",
        client.screen()
    );
    let mut newest = 0;
    for painted in client.history() {
        if let Some(n) = largest_seq_line(&painted.text) {
            anyhow::ensure!(
                n >= newest,
                "seed {seed}: painted a screen ending at {n} after one ending at {newest}"
            );
            newest = n;
        }
    }
    let _ = client.finish().await;
    server.stop().await;
    Ok(())
}

#[test]
fn the_screen_converges_on_a_clean_link() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        for seed in 1..=3 {
            converges(Profile::default(), seed, false).await?;
        }
        Ok(())
    })
}

#[test]
fn the_screen_converges_under_light_loss() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        for seed in 1..=3 {
            converges(lossy(), seed, false).await?;
        }
        Ok(())
    })
}

#[test]
fn the_screen_converges_under_heavy_loss_jitter_duplication_and_reordering() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        for seed in 1..=3 {
            converges(bad(), seed, false).await?;
        }
        Ok(())
    })
}

#[test]
fn the_screen_converges_across_an_outage() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        for seed in 1..=3 {
            converges(Profile::default(), seed, true).await?;
        }
        Ok(())
    })
}

#[test]
fn input_arrives_exactly_once_and_in_order_under_loss() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        let net = FaultNet::new(bad(), 3);
        let (server, mut client) = session(&net, &["sh"]).await?;
        anyhow::ensure!(client
            .wait_until(WAIT, |t| !t.trim().is_empty())
            .await
            .is_some());
        let dir = koh_testkit::scratch!("input")?;
        let out = dir.join("typed.txt");
        // The process that says READY becomes `cat`, so once it shows, typed lines go to cat's stdin,
        // not the shell.
        client
            .send(format!("(echo RE''ADY >&2; exec cat) > '{}'\r", out.display()).as_bytes())
            .await?;
        anyhow::ensure!(client
            .wait_until(WAIT, |t| t.contains("READY"))
            .await
            .is_some());
        let expected: Vec<String> = (0..300).map(|i| format!("line-{i:04}")).collect();
        for line in &expected {
            client.send(format!("{line}\r").as_bytes()).await?;
        }
        // End `cat`'s input, then prove the shell is back.
        client.send(b"\x04echo DO''NE\r").await?;
        anyhow::ensure!(
            client
                .wait_until(WAIT, |t| t.contains("DONE"))
                .await
                .is_some(),
            "the shell never came back; screen:\n{}",
            client.screen()
        );
        let written = std::fs::read_to_string(&out)?;
        anyhow::ensure!(
            written.lines().collect::<Vec<_>>() == expected,
            "input did not arrive exactly once in order"
        );
        let _ = client.finish().await;
        server.stop().await;
        Ok(())
    })
}
