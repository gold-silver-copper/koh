//! A client that is stopped and goes on, as a laptop that slept does: no test, and run by hand
//! (`cargo test --test link frozen -- --ignored --nocapture`). A stopped client is a stopped
//! process, so this one is the real `koh mount` under the real `koh serve`, on loopback and not
//! on the fault link. It says how long until the client is live again.

use std::fs;
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use koh::keys::{Role, load_or_create_key};

use crate::net::Profile;
use crate::rig::{self, Rig};

/// A process of the test's, killed when the test lets go of it.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn signal(pid: u32, signal: &str) {
    let _ = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status();
}

fn koh(tmp: &Path, config: &str, runtime: &str) -> Command {
    let mut koh = Command::new(env!("CARGO_BIN_EXE_koh"));
    koh.env("KOH_CONFIG_DIR", tmp.join(config))
        .env("XDG_RUNTIME_DIR", tmp.join(runtime))
        .env("HOME", tmp)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    koh
}

/// `koh mount` stopped for `stopped` under a living server while its session goes on: how long
/// after it goes on its mirror is the present, and what it said meanwhile.
fn stopped_for(stopped: Duration) -> (Duration, String) {
    let tmp = std::env::temp_dir().join(format!("koh-frozen-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    let tmp = fs::canonicalize(tmp).unwrap();
    let client = load_or_create_key(Role::Client, Some(&tmp.join("cli/client.key"))).unwrap();
    let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = port.local_addr().unwrap().to_string();
    drop(port);
    let mut serve = koh(&tmp, "srv", "run");
    serve
        .args([
            "serve",
            "--no-relay",
            "--shell",
            "/bin/sh",
            "--direct",
            &addr,
        ])
        .args(["--allow", &client.public().to_string()])
        .stderr(Stdio::piped());
    let mut serve = Killed(serve.spawn().unwrap());
    let mut said = BufReader::new(serve.0.stderr.take().unwrap());
    let mut says = |label: &str| loop {
        let mut line = String::new();
        assert!(said.read_line(&mut line).unwrap() > 0, "koh serve ended");
        if let Some(rest) = line.strip_prefix(label) {
            break rest.trim().to_string();
        }
    };
    let (id, sessions) = (says("koh server id:"), PathBuf::from(says("sessions dir:")));
    let (mirror, log) = (tmp.join("ws/m"), tmp.join("said"));
    fs::create_dir_all(tmp.join("ws")).unwrap();
    let mut mount = koh(&tmp, "cli", "crun");
    mount
        .args(["mount", &id, "--direct", &addr])
        .arg(&mirror)
        .stderr(fs::File::create(&log).unwrap());
    let mount = Killed(mount.spawn().unwrap());
    let pane = sessions.join("1");
    rig::until("the mirror has a round", Duration::from_secs(20), || {
        mirror.join("generation").is_file()
    });
    rig::agrees(&pane, &mirror);

    signal(mount.0.id(), "-STOP");
    fs::write(pane.join("in"), "echo while-$((6 * 7))-stopped\n").unwrap();
    std::thread::sleep(stopped);
    assert!(!rig::screen(&mirror).contains("while-42-stopped"));
    signal(mount.0.id(), "-CONT");
    let on = Instant::now();
    rig::until("the mirror is the present", Duration::from_secs(90), || {
        rig::screen(&mirror).contains("while-42-stopped")
    });
    let live = on.elapsed();
    rig::agrees(&pane, &mirror);
    let said = fs::read_to_string(&log).unwrap_or_default();
    // (The session's holder is no child of the server: it is ended by its number.)
    let status = fs::read_to_string(pane.join("status")).unwrap_or_default();
    if let Some(holder) = status
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("holder "))
    {
        let _ = Command::new("kill").args(["-KILL", holder]).status();
    }
    drop((mount, serve));
    let _ = fs::remove_dir_all(&tmp);
    (live, said)
}

#[test]
#[ignore = "a measurement: a client stopped for forty seconds, and how long until it is live"]
fn frozen() {
    for stopped in [20, 40] {
        let (live, said) = stopped_for(Duration::from_secs(stopped));
        let said: Vec<&str> = said
            .lines()
            .filter(|line| line.starts_with("koh:"))
            .collect();
        println!("stopped for {stopped} s: the mirror is the present {live:?} after it went on");
        println!("  koh mount said: {said:?}");
    }
}

/// What a sleep is to a client that SIGSTOP is not: its clock stands still with it, so that on
/// waking it takes its link for a living one, while the server has long forgotten it. That is
/// a link gone one way: the server hears nothing for 36 s and gives its client up after
/// thirty, and the client hears the server until then. How long, once the link is whole again,
/// until the client is live?
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement: a client its server forgot, and how long until it is live"]
async fn forgotten() {
    let rig = Rig::start("forgotten", Profile::named("25ms"), 1).await;
    let pane = rig.pane("s", &["sh"]);
    let mount = rig.mount("s", "a").await;
    rig::agrees(&pane, &mount.dir);
    rig.net
        .black_hole_towards(rig.server_id, Duration::from_secs(36));
    tokio::time::sleep(Duration::from_secs(36)).await;
    let whole = Instant::now();
    fs::write(pane.join("in"), "echo while-$((6 * 7))-forgotten\n").unwrap();
    rig::until("the mirror is the present", Duration::from_secs(90), || {
        rig::screen(&mount.dir).contains("while-42-forgotten")
    });
    let live = whole.elapsed();
    println!(
        "forgotten by its server: the mirror is the present {live:?} after the link was whole"
    );
}
