//! A `koh serve` whose binary is removed or replaced while it runs (an upgrade) still starts
//! sessions: on Linux it launches them from its own image, `/proc/self/exe`, not from the path it
//! was started from.
#![cfg(target_os = "linux")]
#![forbid(clippy::disallowed_methods)]

use std::process::Stdio;
use std::time::Duration;

use koh::pty::{Launcher, Pty};
use koh_testkit::{command, Capture};

/// The endpoint id and port a `koh serve --local` prints: `connect : koh connect ID --direct
/// <this-host-ip>:PORT`.
fn parse_connect_hint(line: &str) -> Option<(String, String)> {
    let rest = line.split("koh connect ").nth(1)?;
    let mut words = rest.split_whitespace();
    let id = words.next()?.to_owned();
    let port = words.nth(1)?.rsplit(':').next()?.to_owned();
    Some((id, port))
}

#[test]
fn a_server_whose_binary_was_removed_still_starts_sessions() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let dir = koh_testkit::scratch!("upgrade").expect("a scratch directory");
            let installed = dir.join("koh");
            std::fs::copy(env!("CARGO_BIN_EXE_koh"), &installed).expect("install a copy of koh");
            let client_key = dir.join("client.key");
            let id = command(env!("CARGO_BIN_EXE_koh"))
                .expect("spawn koh")
                .arg("id")
                .arg("--key-file")
                .arg(&client_key)
                .output()
                .expect("koh id");
            let client_id = String::from_utf8_lossy(&id.stdout).trim().to_owned();

            let mut server = command(&installed)
                .expect("spawn koh")
                .args(["serve", "--local", "--allow", &client_id, "--shell", "sh"])
                .arg("--key-file")
                .arg(dir.join("server.key"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start koh serve");
            // Pick the connect hint out of the server's logs.
            let logs = koh_testkit::stderr_lines(&mut server);
            let (server_id, port) =
                std::iter::from_fn(|| logs.recv_timeout(Duration::from_secs(30)).ok())
                    .find_map(|line| parse_connect_hint(&line))
                    .expect("koh serve prints how to connect");

            // The upgrade: the file the server was started from is gone.
            std::fs::remove_file(&installed).expect("remove the installed binary");

            let (client, output) = Pty::spawn(
                24,
                80,
                &[
                    env!("CARGO_BIN_EXE_koh").to_owned(),
                    "connect".to_owned(),
                    server_id,
                    "--direct".to_owned(),
                    format!("127.0.0.1:{port}"),
                    "--key-file".to_owned(),
                    client_key.display().to_string(),
                ],
                "xterm-256color",
                &Launcher::new(env!("CARGO_BIN_EXE_koh")),
                &koh::pty::Reaper::start().expect("reaper"),
            )
            .expect("spawn the client");
            let seen = Capture::new(output);
            // Only the remote shell turns `$((6*7))` into 42.
            let up = seen
                .type_until(0, "up_42", 15, || {
                    let _ = client.write(b"echo up_$((6*7))\r".to_vec());
                })
                .await;

            let _ = client.write(vec![0x1e, b'.']);
            drop(client);
            let _ = server.kill();
            let _ = server.wait();
            up.unwrap_or_else(|e| {
                panic!("no session started after the server's binary was removed: {e}")
            });
        });
}
