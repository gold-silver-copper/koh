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
    let secret = identity()?;
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

#[test]
fn echoed_keystrokes_are_predicted_then_confirmed() -> anyhow::Result<()> {
    crate::harness::runtime()?.block_on(async {
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
    })
}

#[test]
fn keystrokes_at_a_no_echo_prompt_are_never_shown() -> anyhow::Result<()> {
    crate::harness::runtime()?.block_on(async {
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
                    !painted.predicted.contains(char::from(c))
                        && !painted.text.contains(char::from(c)),
                    "the unechoed key {:?} was drawn: {painted:?}",
                    char::from(c)
                );
            }
        }
        let _ = client.finish().await;
        server.stop().await;
        Ok(())
    })
}

#[test]
fn a_trusted_session_shows_nothing_typed_at_real_password_prompts() -> anyhow::Result<()> {
    crate::harness::runtime()?.block_on(async {
        // Trust first (the shell echoes, so typing shows as predicted), then each prompt in turn:
        // the PTY's modes (lines read without echo) must keep every secret off the screen, however
        // trusted the session was a moment before.
        let net = lossy();
        let (server, mut client) = predicting_session(&net).await?;
        anyhow::ensure!(client
            .wait_until(WAIT, |t| !t.trim().is_empty())
            .await
            .is_some());
        type_slowly(&client, b"echo trusted\r").await?;
        anyhow::ensure!(client
            .wait_until(WAIT, |t| t.matches("trusted").count() >= 2)
            .await
            .is_some());
        // Each prompt reads a line without echo, and is known by its last line; a missing program
        // just prints its marker.
        let prompts: [(&[u8], &str); 4] = [
            // bash's `read -s`.
            (
                b"command -v bash >/dev/null && bash -c 'read -s -p \"Secret: \" x'; echo DO''NE0\r",
                "Secret:",
            ),
            // sudo's own prompt (a wrong password; -k forgets any cached one).
            (
                b"command -v sudo >/dev/null && timeout 20 sudo -k -p 'Password: ' true; echo DO''NE1\r",
                "Password:",
            ),
            // passwd, through PAM.
            (
                b"command -v passwd >/dev/null && timeout 20 passwd; echo DO''NE2\r",
                "assword:",
            ),
            // ssh's prompt, as readpassphrase draws it: echo off, then the prompt.
            (
                b"stty -echo; printf \"me@host's password: \"; read x; stty echo; echo DO''NE3\r",
                "password:",
            ),
        ];
        // Letters that appear nowhere else in this session.
        let secret = b"QZJQZJ";
        let last_line = |t: &str| t.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").to_owned();
        let mut prompted = Vec::new();
        for (n, (command, prompt)) in prompts.iter().enumerate() {
            let marker = format!("DONE{n}");
            type_slowly(&client, command).await?;
            let up = client
                .wait_until(WAIT, |t| last_line(t).trim_end().ends_with(prompt) || t.contains(&marker))
                .await;
            anyhow::ensure!(up.is_some(), "prompt {n} never came; screen:\n{}", client.screen());
            if last_line(&client.screen()).trim_end().ends_with(prompt) {
                prompted.push(n);
                type_slowly(&client, secret).await?;
                type_slowly(&client, b"\r").await?;
                // sudo and passwd ask again after a wrong password: end them.
                tokio::time::sleep(Duration::from_secs(4)).await;
                if !client.screen().contains(&marker) {
                    client.send(b"\x03").await?;
                }
            }
            anyhow::ensure!(
                client
                    .wait_until(WAIT, |t| t.contains(&marker))
                    .await
                    .is_some(),
                "prompt {n} never finished; screen:\n{}",
                client.screen()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        eprintln!("prompts shown: {prompted:?}");
        anyhow::ensure!(
            prompted.contains(&0) || prompted.contains(&3),
            "no prompt was ever shown: {prompted:?}"
        );
        for painted in client.history() {
            for &c in secret {
                anyhow::ensure!(
                    !painted.predicted.contains(char::from(c))
                        && !painted.text.contains(char::from(c)),
                    "the secret's {:?} was drawn: {painted:?}",
                    char::from(c)
                );
            }
        }
        let _ = client.finish().await;
        server.stop().await;
        Ok(())
    })
}

#[test]
fn kernel_echo_is_predicted_from_the_first_key() -> anyhow::Result<()> {
    crate::harness::runtime()?.block_on(async {
        // `cat` reads lines the kernel echoes: the first key typed shows before its echo arrives.
        let net = lossy();
        let (server, mut client) = predicting_session(&net).await?;
        anyhow::ensure!(client
            .wait_until(WAIT, |t| !t.trim().is_empty())
            .await
            .is_some());
        type_slowly(&client, b"cat\r").await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        client.send(b"Q").await?;
        anyhow::ensure!(
            client
                .wait_for(WAIT, |p| p.predicted.contains('Q'))
                .await
                .is_some(),
            "the first key at kernel echo was predicted"
        );
        client.send(b"\x04").await?;
        let _ = client.finish().await;
        server.stop().await;
        Ok(())
    })
}
