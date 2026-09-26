//! A `koh serve` whose binary is removed or replaced while it runs (an upgrade) still starts
//! sessions: on Linux it launches them from its own image, `/proc/self/exe`, not from the path it
//! was started from.
#![cfg(target_os = "linux")]

use std::io::{BufRead as _, BufReader};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use koh_core::pty::{Launcher, Pty};

/// The endpoint id and port a `koh serve --local` prints: `connect : koh connect ID --direct
/// <this-host-ip>:PORT`.
fn parse_connect_hint(line: &str) -> Option<(String, String)> {
    let rest = line.split("koh connect ").nth(1)?;
    let mut words = rest.split_whitespace();
    let id = words.next()?.to_owned();
    let port = words.nth(1)?.rsplit(':').next()?.to_owned();
    Some((id, port))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_server_whose_binary_was_removed_still_starts_sessions() {
    let dir = std::env::temp_dir().join(format!("koh-upgrade-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).expect("temp dir");
    let installed = dir.join("koh");
    std::fs::copy(env!("CARGO_BIN_EXE_koh"), &installed).expect("install a copy of koh");
    let client_key = dir.join("client.key");
    let id = Command::new(env!("CARGO_BIN_EXE_koh"))
        .arg("id")
        .arg("--key-file")
        .arg(&client_key)
        .output()
        .expect("koh id");
    let client_id = String::from_utf8_lossy(&id.stdout).trim().to_owned();

    let mut server = Command::new(&installed)
        .args(["serve", "--local", "--allow", &client_id, "--shell", "sh"])
        .arg("--key-file")
        .arg(dir.join("server.key"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start koh serve");
    // Keep draining the server's stderr (its logs), and pick the connect hint out of it.
    let (hints, hint) = mpsc::channel();
    let stderr = server.stderr.take().expect("server stderr");
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if let Some(found) = parse_connect_hint(&line) {
                let _ = hints.send(found);
            }
        }
    });
    let (server_id, port) = hint
        .recv_timeout(Duration::from_secs(30))
        .expect("koh serve prints how to connect");

    // The upgrade: the file the server was started from is gone.
    std::fs::remove_file(&installed).expect("remove the installed binary");

    let (mut client, mut output) = Pty::spawn(
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
    )
    .expect("spawn the client");
    let seen = Arc::new(Mutex::new(String::new()));
    let sink = seen.clone();
    tokio::spawn(async move {
        while let Some(chunk) = output.recv().await {
            if let Ok(mut all) = sink.lock() {
                all.push_str(&String::from_utf8_lossy(&chunk));
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(2000)).await;
    // Only the remote shell turns `$((6*7))` into 42.
    client
        .write_input(b"echo up_$((6*7))\r")
        .expect("type into the session");
    let mut up = false;
    for _ in 0..150 {
        if seen.lock().is_ok_and(|all| all.contains("up_42")) {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let _ = client.write_input(&[0x1e, b'.']);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = client.kill();
    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        up,
        "no session started after the server's binary was removed; the client saw:\n{}",
        seen.lock().map(|all| all.clone()).unwrap_or_default()
    );
}
