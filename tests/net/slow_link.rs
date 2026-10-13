//! A slow link: a screen whose frame takes many round trips to send still lands.

use std::time::Duration;

use crate::harness::session;
use crate::link::{FaultNet, Profile};

/// A full screen of random characters in random true colours, which no compressor shrinks much
/// (some 15 kB a frame), then a marker.
const BIG_SCREEN: &str = r#"awk 'BEGIN { srand(7); for (i = 0; i < 23 * 80; i++) printf "\033[38;2;%d;%d;%dm\033[48;2;%d;%d;%dm%c", rand()*256, rand()*256, rand()*256, rand()*256, rand()*256, rand()*256, 33 + rand()*90; printf "\033[0mBIG_END" }'; read x"#;

#[test]
fn a_large_first_screen_lands_on_a_slow_link() {
    koh_testkit::multi_thread(4)
        .expect("tokio runtime")
        .block_on(async {
            // 64 kbit/s each way, a 100 ms round trip, a bottleneck buffer of a second: the frame
            // takes some two seconds to send, twenty round trips. Resent every retry interval,
            // each resend reset the one before it, and it never landed.
            let profile = Profile {
                delay: Duration::from_millis(50),
                rate: Some(64_000),
                queue: Duration::from_secs(1),
                ..Profile::default()
            };
            let net = FaultNet::new(profile, 3);
            let (server, mut client) = session(&net, &["sh", "-c", BIG_SCREEN])
                .await
                .expect("start a session");
            // Some ten times what the screen takes to send.
            let landed = client.wait_until(Duration::from_secs(30), |t| t.contains("BIG_END"));
            assert!(landed.await.is_some(), "never landed:\n{}", client.screen());
            let _ = client.finish().await;
            server.stop().await;
        });
}
