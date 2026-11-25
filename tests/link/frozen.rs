//! A client that is stopped and goes on, as a laptop that slept does: no test, and run by hand
//! (`cargo test --release --test link frozen -- --ignored --nocapture`).

use std::fs;
use std::time::{Duration, Instant};

use crate::net::Profile;
use crate::rig::{self, Rig};

/// What a sleep is to a client: its clock stands still, so on waking it takes its link for a
/// living one, while the server has forgotten it after 30 s. How long, once the link is whole
/// again, until the client's screen is live?
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement: a client its server forgot, and how long until it is live"]
async fn forgotten() {
    let rig = Rig::start("forgotten", Profile::named("25ms"), 1).await;
    let pane = rig.pane("s", &["sh"]);
    let client = rig.connect("s", "a").await;
    rig::screen_agrees(&pane, &client);
    rig.net
        .black_hole_towards(rig.server_id, Duration::from_secs(36));
    tokio::time::sleep(Duration::from_secs(36)).await;
    let whole = Instant::now();
    fs::write(pane.join("in"), "echo while-$((6 * 7))-forgotten\n").unwrap();
    rig::until("the screen is the present", Duration::from_secs(90), || {
        client.screen().contains("while-42-forgotten")
    });
    let live = whole.elapsed();
    println!(
        "forgotten by its server: the screen is the present {live:?} after the link was whole"
    );
}
