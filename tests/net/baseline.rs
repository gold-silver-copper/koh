//! The link carries the session, and a transport baseline over four network profiles.
//!
//! The baseline is `#[ignore]`d (it takes minutes); run it with
//! `cargo test --test net -- --ignored --nocapture baseline`. Set `KOH_BASELINE_OUT` to also
//! append the results to a file.

use std::time::Duration;

use anyhow::Context as _;
use tokio::time::Instant;

use crate::harness::session;
use crate::link::{Count, FaultNet, Profile};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fault_link_is_the_only_path() {
    let net = FaultNet::new(Profile::default(), 1);
    let (server, mut client) = session(&net, &["sh"]).await.expect("start a session");
    // `ON''E` so the typed command itself never matches the output.
    client.send(b"echo ON''E\r").await.expect("type");
    assert!(
        client
            .wait_until(Duration::from_secs(20), |t| t.contains("ONE"))
            .await
            .is_some(),
        "the session never came up; screen:\n{}",
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

    // If any other path existed, the session would keep working through the outage.
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
    server.stop().await;
}

/// What one profile measured.
struct Metrics {
    echo_median: Duration,
    echo_p95: Duration,
    burst: Duration,
    recovery: Option<Duration>,
    to_server: Count,
    to_client: Count,
}

const KEYSTROKES: usize = 200;

/// Run one session over `profile`, black-holing the link for 5 s at the end if `outage`.
async fn measure(profile: Profile, outage: bool, seed: u64) -> anyhow::Result<Metrics> {
    let net = FaultNet::new(profile, seed);
    let (server, mut client) = session(&net, &["sh"]).await?;
    let long = Duration::from_secs(120);
    client
        .wait_until(long, |t| !t.trim().is_empty())
        .await
        .context("the shell prompt never appeared")?;
    let base = client.screen().matches('x').count();

    // Keystroke to echo: one `x` at a time, each waited for.
    let mut echoes = Vec::with_capacity(KEYSTROKES);
    for n in 1..=KEYSTROKES {
        let typed = Instant::now();
        client.send(b"x").await?;
        let painted = client
            .wait_until(long, |t| t.matches('x').count() >= base + n)
            .await
            .context("a keystroke was never echoed")?;
        echoes.push(painted.at.saturating_duration_since(typed));
    }
    echoes.sort_unstable();

    // A burst of output: until its last line is on screen.
    let started = Instant::now();
    client.send(b"\rclear; seq 1 50000; echo DO''NE\r").await?;
    let painted = client
        .wait_until(long, |t| t.contains("DONE"))
        .await
        .context("the burst never finished")?;
    let burst = painted.at.saturating_duration_since(started);

    let recovery = if outage {
        let outage_len = Duration::from_secs(5);
        let ends = Instant::now() + outage_len;
        net.black_hole(outage_len);
        client.send(b"echo RE''COVERED\r").await?;
        let painted = client
            .wait_until(long, |t| t.contains("RECOVERED"))
            .await
            .context("the session never recovered")?;
        Some(painted.at.saturating_duration_since(ends))
    } else {
        None
    };

    let percentile = |p: usize| {
        echoes
            .get((KEYSTROKES * p).div_euclid(100))
            .copied()
            .context("no echo measured")
    };
    let metrics = Metrics {
        echo_median: percentile(50)?,
        echo_p95: percentile(95)?,
        burst,
        recovery,
        to_server: net.sent(server.id),
        to_client: net.sent(client.id),
    };
    let _ = client.finish().await;
    server.stop().await;
    Ok(metrics)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a multi-minute measurement; run explicitly"]
async fn baseline() {
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let profiles = [
        ("clean", Profile::default(), false),
        (
            "5% loss, 50 ms",
            Profile {
                loss: 0.05,
                delay: Duration::from_millis(50),
                ..Profile::default()
            },
            false,
        ),
        (
            "20% loss, 150±100 ms, 2% dup+reorder",
            Profile {
                loss: 0.20,
                delay: Duration::from_millis(150),
                jitter: Duration::from_millis(100),
                dup: 0.02,
                reorder: 0.02,
            },
            false,
        ),
        ("5 s outage", Profile::default(), true),
    ];
    // `KOH_BASELINE_PROFILE` picks one profile by index; `KOH_BASELINE_SEED` changes the link's
    // RNG seed (default 7).
    let only: Option<usize> = std::env::var("KOH_BASELINE_PROFILE")
        .ok()
        .and_then(|v| v.parse().ok());
    let seed: u64 = std::env::var("KOH_BASELINE_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7);
    let mut report = String::new();
    for (i, (name, profile, outage)) in profiles.into_iter().enumerate() {
        if only.is_some_and(|only| only != i) {
            continue;
        }
        let m = measure(profile, outage, seed).await.expect(name);
        let line = format!(
            "seed {seed:<3} {name:<38} echo p50 {:>7.1} ms  p95 {:>7.1} ms  burst {:>8.1} ms  recovery {:>8}  \
             to server {:>9} B / {:>6} pkts  to client {:>10} B / {:>6} pkts\n",
            ms(m.echo_median),
            ms(m.echo_p95),
            ms(m.burst),
            m.recovery
                .map_or_else(|| "-".to_owned(), |r| format!("{:.1} ms", ms(r))),
            m.to_server.bytes,
            m.to_server.packets,
            m.to_client.bytes,
            m.to_client.packets,
        );
        print!("{line}");
        report.push_str(&line);
    }
    if let Ok(path) = std::env::var("KOH_BASELINE_OUT") {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open KOH_BASELINE_OUT");
        file.write_all(report.as_bytes())
            .expect("write KOH_BASELINE_OUT");
    }
}
