//! The real `koh` binary's names for ids: `koh servers` and `koh clients`, `koh connect <name>`,
//! `koh serve` allowing the saved clients, `koh key info` and `reset` for both keys, and the menu
//! `koh` alone opens on a terminal (and help, off one).
//!
//! Every run has its own `HOME` and `XDG_CONFIG_HOME`, so the keys and lists live in a scratch
//! directory and the user's own `~/.config/koh` is never read or written.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use koh::pty::{Launcher, Pty};

/// A home of its own, removed afterwards; its koh directory is `<home>/.config/koh`.
struct Home(PathBuf);

impl Home {
    fn new(tag: &str) -> anyhow::Result<Self> {
        let dir = std::env::temp_dir().join(format!(
            "koh-names-cli-{tag}-{}-{:016x}",
            std::process::id(),
            getrandom::u64()?
        ));
        std::fs::create_dir_all(dir.join(".config"))?;
        Ok(Self(dir))
    }

    fn koh_dir(&self) -> PathBuf {
        self.0.join(".config").join("koh")
    }

    /// `koh args…` in this home, its stdin closed.
    fn koh(&self, args: &[&str]) -> anyhow::Result<Output> {
        Ok(Command::new(env!("CARGO_BIN_EXE_koh"))
            .args(args)
            .env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join(".config"))
            .stdin(Stdio::null())
            .output()?)
    }

    /// The argv that runs `koh args…` in this home, for a PTY (which takes no environment).
    fn argv(&self, args: &[&str]) -> Vec<String> {
        let mut argv = vec![
            "env".to_owned(),
            format!("HOME={}", self.0.display()),
            format!("XDG_CONFIG_HOME={}", self.0.join(".config").display()),
            env!("CARGO_BIN_EXE_koh").to_owned(),
        ];
        argv.extend(args.iter().map(|&a| a.to_owned()));
        argv
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A valid endpoint id, from a key of its own.
fn some_id(seed: u8) -> String {
    iroh::SecretKey::from_bytes(&[seed; 32])
        .public()
        .to_string()
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}

fn launcher() -> Launcher {
    Launcher::new(env!("CARGO_BIN_EXE_koh"))
}

/// Everything `output` delivers, gathered by a background task.
fn capture(mut output: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Arc<Mutex<Vec<u8>>> {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = buf.clone();
    tokio::spawn(async move {
        while let Some(chunk) = output.recv().await {
            let Ok(mut all) = sink.lock() else { break };
            all.extend_from_slice(&chunk);
        }
    });
    buf
}

fn captured(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    buf.lock().map_or_else(
        |_| String::new(),
        |all| String::from_utf8_lossy(&all).into_owned(),
    )
}

/// Wait up to `secs` for `needle` in what was captured.
async fn wait_for(buf: &Arc<Mutex<Vec<u8>>>, needle: &str, secs: u64) -> Result<(), String> {
    for _ in 0..secs.saturating_mul(10) {
        if captured(buf).contains(needle) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "never saw {needle:?}; captured:\n{}",
        captured(buf)
    ))
}

#[test]
fn servers_are_added_listed_renamed_and_removed_by_name() {
    let home = Home::new("servers").unwrap();
    let id = some_id(1);
    let out = home.koh(&["servers"]).unwrap();
    assert!(
        out.status.success() && text(&out).contains("no servers saved"),
        "{}",
        text(&out)
    );
    let out = home.koh(&["servers", "add", "laptop", &id]).unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let out = home.koh(&["servers"]).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("laptop {id}\n")
    );
    let out = home.koh(&["servers", "add", "other", &id]).unwrap();
    assert!(
        !out.status.success() && text(&out).contains("already saved as"),
        "{}",
        text(&out)
    );
    assert!(home
        .koh(&["servers", "rename", "laptop", "desk"])
        .unwrap()
        .status
        .success());
    let saved = std::fs::read_to_string(home.koh_dir().join("servers")).unwrap();
    assert_eq!(saved, format!("desk {id}\n"));
    assert!(home
        .koh(&["servers", "rm", "desk"])
        .unwrap()
        .status
        .success());
    let out = home.koh(&["servers", "rm", "desk"]).unwrap();
    assert!(
        !out.status.success() && text(&out).contains("not saved"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_bad_name_or_id_is_refused_on_the_command_line() {
    let home = Home::new("bad").unwrap();
    for args in [
        &["clients", "add", "-x", &some_id(1)][..],
        &["clients", "add", "phone", "not-an-id"][..],
        &["clients", "add", &some_id(2), &some_id(1)][..],
    ] {
        let out = home.koh(args).unwrap();
        assert!(!out.status.success(), "{args:?} was taken: {}", text(&out));
    }
    assert!(
        !home.koh_dir().join("clients").exists(),
        "nothing was saved"
    );
}

#[test]
fn connect_to_an_unsaved_name_lists_the_saved_ones() {
    let home = Home::new("unsaved").unwrap();
    home.koh(&["servers", "add", "laptop", &some_id(1)])
        .unwrap();
    let out = home.koh(&["connect", "desk"]).unwrap();
    let said = text(&out);
    assert!(!out.status.success(), "{said}");
    assert!(
        said.contains("nor a saved server name") && said.contains("saved: laptop"),
        "{said}"
    );
}

#[test]
fn serve_without_allow_allows_the_saved_clients() {
    let home = Home::new("serve").unwrap();
    let out = home.koh(&["serve", "--local", "--shell", "sh"]).unwrap();
    assert!(!out.status.success(), "no clients: {}", text(&out));
    assert!(text(&out).contains("koh clients add"), "{}", text(&out));
    home.koh(&["clients", "add", "phone", &some_id(3)]).unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_koh"))
        .args(["serve", "--local", "--shell", "sh"])
        .env("HOME", &home.0)
        .env("XDG_CONFIG_HOME", home.0.join(".config"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = server.stderr.take().unwrap();
    let (seen, banner) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead as _;
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if line.contains("auth") {
                let _ = seen.send(line);
            }
        }
    });
    let line = banner.recv_timeout(Duration::from_secs(20));
    let _ = server.kill();
    let _ = server.wait();
    let line = line.expect("the server's banner");
    assert!(line.contains("allowlist (1 client(s))"), "{line}");
}

#[test]
fn key_info_shows_both_keys_and_reset_names_the_one() {
    let home = Home::new("keys").unwrap();
    let out = home.koh(&["key", "info"]).unwrap();
    assert!(!out.status.success(), "no key yet: {}", text(&out));
    let client = home.koh(&["id"]).unwrap();
    let client = String::from_utf8_lossy(&client.stdout).trim().to_owned();
    let out = home.koh(&["key", "info"]).unwrap();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(
        said.contains(&client) && said.contains("server key"),
        "{said}"
    );
    assert!(said.contains("none yet (`koh serve` creates it)"), "{said}");
    let out = home.koh(&["key", "reset", "client"]).unwrap();
    assert!(
        !out.status.success() && text(&out).contains("--yes"),
        "{}",
        text(&out)
    );
    assert!(
        text(&out).contains("every server that allows you"),
        "{}",
        text(&out)
    );
    let out = home.koh(&["key", "reset", "client", "--yes"]).unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert!(!home.koh_dir().join("client.key").exists());
}

#[test]
fn koh_alone_off_a_terminal_prints_help() {
    let home = Home::new("help").unwrap();
    let out = home.koh(&[]).unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("Usage"), "{}", text(&out));
    assert!(!home.koh_dir().exists(), "help touches nothing");
}

#[test]
fn koh_alone_on_a_terminal_opens_the_menu_and_q_leaves_it() {
    let home = Home::new("menu").unwrap();
    home.koh(&["servers", "add", "laptop", &some_id(1)])
        .unwrap();
    runtime().unwrap().block_on(async {
        let (mut menu, output) = Pty::spawn(24, 80, &home.argv(&[]), "xterm-256color", &launcher())
            .expect("spawn koh on a PTY");
        let buf = capture(output);
        wait_for(&buf, "koh — this machine", 10).await.unwrap();
        wait_for(&buf, "1  laptop", 5).await.unwrap();
        menu.write_input(b"q\n").unwrap();
        let mut exited = false;
        for _ in 0..50 {
            if menu.try_wait().ok().flatten().is_some() {
                exited = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let _ = menu.kill();
        assert!(exited, "q left the menu; captured:\n{}", captured(&buf));
    });
}

/// The path the given home's `connected` file is at, for a test that connects.
fn connected(home: &Home) -> PathBuf {
    home.koh_dir().join("connected")
}

#[test]
fn connect_by_name_dials_the_saved_server_and_notes_it() {
    let home = Home::new("connect").unwrap();
    runtime().unwrap().block_on(async {
        let server = koh::transport_iroh::bind_endpoint_local(
            koh::transport_iroh::generate_secret_key().unwrap(),
            true,
        )
        .await
        .unwrap();
        let id = server.id().to_string();
        let port = server
            .bound_sockets()
            .iter()
            .find(|s| s.is_ipv4())
            .map(std::net::SocketAddr::port)
            .unwrap();
        let task = tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                if let Ok(conn) = incoming.await {
                    if koh::transport_iroh::admission::admit(&conn).await.is_ok() {
                        let _ =
                            koh::server::run_session(conn, &["sh".to_owned()], 0, launcher()).await;
                    }
                }
            }
        });
        home.koh(&["servers", "add", "box", &id]).unwrap();
        let direct = format!("127.0.0.1:{port}");
        let argv = home.argv(&["connect", "box", "--direct", &direct]);
        let (client, output) =
            Pty::spawn(24, 80, &argv, "xterm-256color", &launcher()).expect("spawn the client");
        let buf = capture(output);
        tokio::time::sleep(Duration::from_millis(2000)).await;
        client.write_input(b"echo by''_name\r").unwrap();
        let seen = wait_for(&buf, "by_name", 15).await;
        let _ = client.write_input(&[0x1e, b'.']);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = client.kill();
        task.abort();
        seen.unwrap();
        let noted = std::fs::read_to_string(connected(&home)).unwrap();
        assert!(noted.starts_with(&id), "the connect is noted: {noted:?}");
        assert!(Path::new(&connected(&home)).exists());
    });
}
