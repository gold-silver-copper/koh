//! Keys, decoded by the client and encoded by the server for the program: a program gets what it
//! asked for, whatever terminal the user types on, across a reattach too.

use std::time::Duration;

use crate::harness::{identity, session, Client, Options, Server};
use crate::link::{FaultNet, Profile};

const WAIT: Duration = Duration::from_secs(15);

fn clean() -> FaultNet {
    FaultNet::new(Profile::default(), 7)
}

/// nvim asks for the kitty keyboard protocol and gets it from koh's server: Ctrl-I and Tab reach
/// it as different keys from a terminal that tells them apart (a kitty-protocol terminal sends
/// `CSI 105 ; 5 u`), and Tab is Tab from one that does not.
#[test]
fn nvim_tells_ctrl_i_from_tab_from_a_kitty_terminal() {
    if std::process::Command::new("nvim")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("nvim is not installed; skipped");
        return;
    }
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let (server, mut client) = session(
                &net,
                &[
                    "nvim",
                    "--clean",
                    "-n",
                    "-c",
                    "nnoremap <C-i> :echo 'got CTRL'..'-I'<CR>",
                    "-c",
                    "nnoremap <Tab> :echo 'got T'..'AB'<CR>",
                ],
            )
            .await
            .expect("start nvim");
            // nvim is up once it draws its empty buffer's `~` lines. It asks for the kitty protocol
            // (`CSI ? u`) at start-up and pushes its flags once answered, after which a kitty
            // terminal's Ctrl-I reaches it as <C-i>; before, as Tab. So Ctrl-I is typed until it
            // does, which it must within the wait.
            assert!(
                client.wait_until(WAIT, |t| t.contains('~')).await.is_some(),
                "nvim did not start:\n{}",
                client.screen()
            );
            let mut told = false;
            for _ in 0..30 {
                client.send(b"\x1b[105;5u").await.expect("type Ctrl-I");
                if client
                    .wait_until(Duration::from_millis(500), |t| t.contains("got CTRL-I"))
                    .await
                    .is_some()
                {
                    told = true;
                    break;
                }
            }
            assert!(
                told,
                "Ctrl-I from a kitty terminal must reach nvim as <C-i>:\n{}",
                client.screen()
            );
            client.send(b"\t").await.expect("type Tab");
            assert!(
                client
                    .wait_until(WAIT, |t| t.contains("got TAB"))
                    .await
                    .is_some(),
                "Tab must reach nvim as <Tab>:\n{}",
                client.screen()
            );
            client
                .send(b"\x1b[105;5u")
                .await
                .expect("type Ctrl-I again");
            assert!(
                client
                    .wait_until(WAIT, |t| t.contains("got CTRL-I"))
                    .await
                    .is_some(),
                "and Ctrl-I again:\n{}",
                client.screen()
            );
            let _ = client.finish().await;
            server.stop().await;
        });
}

/// A program pushes kitty's disambiguate, its client leaves, and another reattaches from a legacy
/// terminal: Ctrl-A, which that terminal sends as 0x01, reaches the program as kitty's
/// `CSI 97 ; 5 u`, as it asked.
#[test]
fn a_reattach_from_a_legacy_terminal_keeps_the_programs_keyboard() {
    crate::harness::runtime()
        .expect("tokio runtime")
        .block_on(async {
            let net = clean();
            let secret = identity().expect("OS randomness");
            let server = Server::start(
                &net,
                &[secret.public()],
                &[
                    "sh",
                    "-c",
                    "printf '\\033[>1u'; stty raw -echo; echo READY; \
                     head -c 7 | od -An -tx1; sleep 600",
                ],
            )
            .await
            .expect("start the server");
            let endpoint = net.endpoint(secret, false).await.expect("bind the client");
            let mut first = Client::connect_on(endpoint.clone(), server.id, Options::default())
                .await
                .expect("connect #1");
            assert!(first
                .wait_until(WAIT, |t| t.contains("READY"))
                .await
                .is_some());
            let _ = first.finish().await;
            let mut second = Client::connect_on(endpoint, server.id, Options::default())
                .await
                .expect("connect #2");
            assert!(second
                .wait_until(WAIT, |t| t.contains("READY"))
                .await
                .is_some());
            second.send(&[0x01]).await.expect("type Ctrl-A");
            assert!(
                second
                    // `od` spaces its bytes by one on Linux, by two on macOS.
                    .wait_until(WAIT, |t| {
                        t.split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ")
                            .contains("1b 5b 39 37 3b 35 75")
                    })
                    .await
                    .is_some(),
                "the program must get CSI 97;5u:\n{}",
                second.screen()
            );
            let _ = second.finish().await;
            server.stop().await;
        });
}
