//! The real `koh` binary's names for ids: `koh servers` and `koh clients`, `koh connect <name>`,
//! `koh serve` allowing the saved clients, `koh key info` and `reset` for both keys, and the menu
//! `koh` alone opens on a terminal (and help, off one).
//!
//! Every run has its own `HOME` and `XDG_CONFIG_HOME`, so the keys and lists live in a scratch
//! directory and the user's own `~/.config/koh` is never read or written.
#![forbid(clippy::disallowed_methods)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::Duration;

use koh::pty::{Launcher, Pty};
use koh_testkit::{command, Capture, Scratch};

#[cfg(target_os = "linux")]
#[test]
fn unwritable_stdout_and_stderr_do_not_panic() {
    let home = Home::new("failed-output").expect("scratch home");
    for discard_diagnostics in [false, true] {
        let mut command =
            command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!()).expect("spawn koh");
        command
            .args(["key", "info"])
            .env("HOME", home.0.path())
            .env("XDG_CONFIG_HOME", home.0.join(".config"))
            .stdout(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/full")
                    .expect("full"),
            );
        if discard_diagnostics {
            command.stderr(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/full")
                    .expect("full"),
            );
        }
        let output = command.output().expect("run koh");
        assert_eq!(output.status.code(), Some(1));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
        assert!(!home.koh_dir().exists(), "info must not create identities");
    }
}

/// A home of its own, removed afterwards; its koh directory is `<home>/.config/koh`.
struct Home(Scratch);

impl Home {
    fn new(tag: &str) -> anyhow::Result<Self> {
        let dir = koh_testkit::scratch!(&format!("names-cli-{tag}"))?;
        std::fs::create_dir_all(dir.join(".config"))?;
        Ok(Self(dir))
    }

    fn koh_dir(&self) -> PathBuf {
        self.0.join(".config").join("koh")
    }

    /// `koh args…` in this home, its stdin closed.
    fn koh(&self, args: &[&str]) -> anyhow::Result<Output> {
        Ok(command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())?
            .args(args)
            .env("HOME", self.0.path())
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

fn launcher() -> Launcher {
    Launcher::isolated(env!("CARGO_BIN_EXE_koh"), koh_testkit::home!())
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
    // A hang-up drains the server, unless it was started ignoring them (`nohup`): then a logout
    // leaves it running, and SIGTERM still drains it.
    // Only Linux says a signal is ignored.
    for nohup in [false, cfg!(target_os = "linux")] {
        let koh = env!("CARGO_BIN_EXE_koh");
        let mut server =
            command(if nohup { "nohup" } else { koh }, &koh_testkit::home!()).expect("spawn koh");
        if nohup {
            server.arg(koh);
        }
        let mut server = server
            .args(["serve", "--local", "--shell", "sh"])
            .env("HOME", home.0.path())
            .env("XDG_CONFIG_HOME", home.0.join(".config"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let logs = koh_testkit::stderr_lines(&mut server);
        let next = |what: &str| {
            std::iter::from_fn(|| logs.recv_timeout(Duration::from_secs(20)).ok())
                .find(|line| line.contains(what))
        };
        let banner = next("auth");
        let pid = fuxix::process::Pid::of(&server).unwrap();
        fuxix::process::kill(pid, fuxix::process::Signal::Hup).unwrap();
        let hung_up = next(if nohup {
            "SIGHUP ignored"
        } else {
            "shutting down"
        });
        if nohup {
            fuxix::process::kill(pid, fuxix::process::Signal::Term).unwrap();
        }
        let drained = next("draining");
        let _ = server.kill();
        let _ = server.wait();
        let banner = banner.expect("the server's banner");
        assert!(banner.contains("allowlist (1 client(s))"), "{banner}");
        let hung_up = hung_up.expect("the hang-up seen");
        assert!(nohup || hung_up.contains("SIGHUP"), "{hung_up}");
        assert!(drained.is_some(), "nohup {nohup}: never drained");
    }
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
    // A server key that is there but no key is said so, not taken for none.
    let server_key = home.koh_dir().join("server.key");
    std::fs::write(&server_key, [7; 31]).unwrap();
    std::fs::set_permissions(&server_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = home.koh(&["key", "info"]).unwrap();
    let said = text(&out);
    assert!(
        !out.status.success() && said.contains("koh key reset"),
        "{said}"
    );
    std::fs::remove_file(&server_key).unwrap();
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
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let (mut menu, output) = Pty::spawn(
                24,
                80,
                &home.argv(&[]),
                "xterm-256color",
                &launcher(),
                &koh::pty::Reaper::start().expect("reaper"),
            )
            .expect("spawn koh on a PTY");
            let buf = Capture::new(output);
            buf.wait_for(0, "koh — this machine", 10).await.unwrap();
            buf.wait_for(0, "1  laptop", 5).await.unwrap();
            menu.write(b"q\n".to_vec()).unwrap();
            let mut exited = false;
            for _ in 0..50 {
                if menu.try_wait().ok().flatten().is_some() {
                    exited = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            drop(menu);
            assert!(exited, "q left the menu; captured:\n{}", buf.text_from(0));
        });
}

/// The path the given home's `connected` file is at, for a test that connects.
fn connected(home: &Home) -> PathBuf {
    home.koh_dir().join("connected")
}

#[test]
fn connect_by_name_dials_the_saved_server_and_notes_it() {
    let home = Home::new("connect").unwrap();
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
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
            // The server allows this home's client, as `koh serve` would.
            let me = home.koh(&["id"]).unwrap();
            let config = koh::server::ServeConfig {
                allow: vec![koh::transport_iroh::parse_endpoint_id(
                    String::from_utf8_lossy(&me.stdout).trim(),
                )
                .unwrap()],
                command: vec!["sh".to_owned()],
                launcher: launcher(),
                ..koh::server::ServeConfig::default()
            };
            let task = koh_testkit::spawn(koh::server::cli::serve_endpoint(
                server,
                koh::server::cli::Hosting::from_config(&config).unwrap(),
                tokio_util::sync::CancellationToken::new(),
            ));
            home.koh(&["servers", "add", "box", &id]).unwrap();
            let direct = format!("127.0.0.1:{port}");
            let argv = home.argv(&["connect", "box", "--direct", &direct]);
            let (client, output) = Pty::spawn(
                24,
                80,
                &argv,
                "xterm-256color",
                &launcher(),
                &koh::pty::Reaper::start().expect("reaper"),
            )
            .expect("spawn the client");
            let buf = Capture::new(output);
            let seen = buf
                .type_until(0, "by_name", 15, || {
                    let _ = client.write(b"echo by''_name\r".to_vec());
                })
                .await;
            let _ = client.write(vec![0x1e, b'.']);
            drop(client);
            task.abort();
            seen.unwrap();
            let noted = std::fs::read_to_string(connected(&home)).unwrap();
            assert!(noted.starts_with(&id), "the connect is noted: {noted:?}");
            assert!(Path::new(&connected(&home)).exists());
        });
}

/// Clients added and removed with `koh clients` take effect at a running server's next connection,
/// with no restart: a lost machine's key is refused at once.
#[test]
fn clients_added_and_removed_take_effect_on_a_running_server() {
    use koh::transport_iroh::{bind_endpoint_local, direct_addr, parse_endpoint_id, ALPN};
    let home = Home::new("live-allowlist").unwrap();
    let me = home.koh(&["id"]).unwrap();
    let me = String::from_utf8_lossy(&me.stdout).trim().to_owned();
    home.koh(&["clients", "add", "other", &some_id(4)]).unwrap();
    let mut server = command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())
        .expect("spawn koh")
        .args(["serve", "--local", "--shell", "sh"])
        .env("HOME", home.0.path())
        .env("XDG_CONFIG_HOME", home.0.join(".config"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let banner = koh_testkit::stderr_lines(&mut server);
    let (mut id, mut port) = (None, None);
    while id.is_none() || port.is_none() {
        let line = banner
            .recv_timeout(Duration::from_secs(20))
            .expect("banner");
        if let Some(rest) = line.split_once("endpoint id : ").map(|(_, r)| r) {
            id = Some(parse_endpoint_id(rest).unwrap());
        }
        if let Some(rest) = line.split_once("udp port    : ").map(|(_, r)| r) {
            port = rest
                .split_whitespace()
                .next()
                .and_then(|p| p.parse::<u16>().ok());
        }
    }
    let at = direct_addr(id.unwrap(), ([127, 0, 0, 1], port.unwrap()).into());
    let key = std::fs::read(home.koh_dir().join("client.key")).unwrap();
    let secret = iroh::SecretKey::from_bytes(&key.try_into().unwrap());
    let admitted = || {
        let (at, secret) = (at.clone(), secret.clone());
        async move {
            let endpoint = bind_endpoint_local(secret, false).await?;
            let conn = endpoint.connect(at, ALPN).await?;
            conn.accept_uni().await?;
            anyhow::Ok((endpoint, conn))
        }
    };
    let outcomes = koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let before = admitted().await.is_ok();
            home.koh(&["clients", "add", "me", &me]).unwrap();
            // Seen at the next read of the list, within two seconds.
            let mut live = admitted().await;
            let seen = tokio::time::Instant::now() + Duration::from_secs(10);
            while live.is_err() && tokio::time::Instant::now() < seen {
                live = admitted().await;
            }
            let added = live.is_ok();
            home.koh(&["clients", "rm", "me"]).unwrap();
            // The connection it already had is cut off too.
            let cut_off = match &live {
                Ok((_, conn)) => tokio::time::timeout(Duration::from_secs(10), conn.closed())
                    .await
                    .is_ok(),
                Err(_) => false,
            };
            let removed = admitted().await.is_ok();
            (before, added, cut_off, removed)
        });
    let _ = server.kill();
    let _ = server.wait();
    assert_eq!(
        outcomes,
        (false, true, true, false),
        "(before it was saved, once saved, its live connection once removed, once removed)"
    );
}
