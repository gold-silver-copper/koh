//! The predictor against real frames on a lossy link: keystrokes the shell echoes are predicted
//! and then confirmed, and keystrokes it does not echo (a password prompt) are never shown.

use std::time::Duration;

use koh::predict::DisplayPreference;

use crate::harness::{identity, Client, Options, Server};
use crate::link::{FaultNet, Profile};

const WAIT: Duration = Duration::from_secs(30);

fn lossy() -> FaultNet {
    FaultNet::new(
        Profile {
            loss: 0.05,
            delay: Duration::from_millis(50),
            ..Profile::default()
        },
        1,
    )
}

async fn predicting_session(net: &FaultNet) -> anyhow::Result<(Server, Client)> {
    let secret = identity();
    let server = Server::start(net, &[secret.public()], &["sh"]).await?;
    let endpoint = net.endpoint(secret, false).await?;
    let options = Options {
        predict: Some(DisplayPreference::Always),
        ..Options::default()
    };
    let client = Client::connect_on(endpoint, server.id, options).await?;
    Ok((server, client))
}

async fn type_slowly(client: &Client, text: &[u8]) -> anyhow::Result<()> {
    for byte in text {
        client.send(std::slice::from_ref(byte)).await?;
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echoed_keystrokes_are_predicted_then_confirmed() -> anyhow::Result<()> {
    let net = lossy();
    let (server, mut client) = predicting_session(&net).await?;
    anyhow::ensure!(client
        .wait_until(WAIT, |t| !t.trim().is_empty())
        .await
        .is_some());
    // The first keystroke is only ever tentative; once the shell has echoed it, later ones show.
    type_slowly(&client, b"e").await?;
    anyhow::ensure!(client.wait_until(WAIT, |t| t.contains('e')).await.is_some());
    type_slowly(&client, b"cho hello").await?;
    anyhow::ensure!(client
        .wait_until(WAIT, |t| t.contains("echo hello"))
        .await
        .is_some());
    anyhow::ensure!(
        client
            .wait_for(WAIT, |p| p.text.contains("echo hello")
                && p.predicted.is_empty())
            .await
            .is_some(),
        "every prediction is confirmed and cleared once the echo arrives"
    );
    anyhow::ensure!(
        client.history().iter().any(|p| p.predicted.contains('l')),
        "keystrokes were predicted before their echo arrived"
    );
    let _ = client.finish().await;
    server.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keystrokes_at_a_no_echo_prompt_are_never_shown() -> anyhow::Result<()> {
    // The password-prompt property, end to end: after `stty -echo`, typed keys must never be
    // drawn, not even briefly as a prediction.
    let net = lossy();
    let (server, mut client) = predicting_session(&net).await?;
    anyhow::ensure!(client
        .wait_until(WAIT, |t| !t.trim().is_empty())
        .await
        .is_some());
    // `read` with echo off, as a password prompt does it (bash's line editor echoes by itself, so
    // the prompt must not be the shell's own line).
    type_slowly(&client, b"stty -echo; read x; stty echo; echo BA''CK\r").await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    // Letters that appear nowhere else in this session.
    let secret = b"zqjvwfm";
    type_slowly(&client, secret).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    type_slowly(&client, b"\r").await?;
    anyhow::ensure!(client
        .wait_until(WAIT, |t| t.contains("BACK"))
        .await
        .is_some());
    for painted in client.history() {
        for &c in secret {
            anyhow::ensure!(
                !painted.predicted.contains(char::from(c)) && !painted.text.contains(char::from(c)),
                "the unechoed key {:?} was drawn: {painted:?}",
                char::from(c)
            );
        }
    }
    let _ = client.finish().await;
    server.stop().await;
    Ok(())
}
