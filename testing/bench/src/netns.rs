//! Measures taken inside a network namespace of this user's own, whose loopback a kernel
//! queueing discipline (`tc netem`) delays and drops on: the same link profile for mosh's UDP and
//! ssh's TCP, with nothing in the way that TCP could hide a drop behind. No root is needed:
//! `unshare --user --map-root-user --net` gives a namespace in which this user may configure its
//! own loopback.
//!
//! The parent runs this binary again, through `unshare`, as `koh-bench --netns-child MEASURE
//! ARGS…`, after bringing the namespace's loopback up with netem on it (each packet crosses
//! loopback once, so the delay and the loss apply once each way). The child runs the measure with
//! no proxy in the way, and prints what it found on stdout, one value a line.

use std::process::Command;
use std::time::Duration;

use anyhow::Context as _;

use crate::proxy::Profile;

pub const CHILD: &str = "--netns-child";

/// Whether a namespace with netem can be made here.
pub fn available() -> bool {
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "sh", "-c"])
        .arg("ip link set lo up && tc qdisc add dev lo root netem delay 1ms")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Run this binary's `measure` with `args` in a fresh namespace whose loopback has `profile`; the
/// lines it printed.
///
/// The namespace is made as this user mapped to root, which may configure its loopback; the
/// measure then runs in a namespace nested in it that maps this user back to itself, because sshd
/// running as root would want users the namespace does not have, and run as this user it serves
/// this user as it does outside.
pub fn run(profile: Profile, measure: &str, args: &[String]) -> anyhow::Result<Vec<String>> {
    let exe = std::env::current_exe()?;
    let id = |flag: &str| -> anyhow::Result<String> {
        let out = Command::new("id").arg(flag).output()?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    let (uid, gid) = (id("-u")?, id("-g")?);
    let delay = profile.delay.as_millis();
    // A rate limit's buffer: 100 ms of the link's bytes, in packets of about 1,200 bytes.
    let rate = profile.rate.map_or_else(String::new, |rate| {
        let limit = rate.div_euclid(8 * 10 * 1200).max(4);
        format!(" rate {rate}bit limit {limit}")
    });
    let netem = if delay > 0 || profile.loss > 0.0 || profile.rate.is_some() {
        format!(
            " && tc qdisc add dev lo root netem delay {delay}ms loss {}%{rate}",
            profile.loss * 100.0
        )
    } else {
        String::new()
    };
    let quoted: Vec<String> = std::iter::once(exe.display().to_string())
        .chain([CHILD.to_owned(), measure.to_owned()])
        .chain(args.iter().cloned())
        .map(|a| format!("'{}'", a.replace('\'', "'\\''")))
        .collect();
    let script = format!(
        "ip link set lo up{netem} && exec unshare --user --map-user={uid} --map-group={gid} {}",
        quoted.join(" ")
    );
    let out = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "sh", "-c", &script])
        .output()
        .context("unshare")?;
    anyhow::ensure!(
        out.status.success(),
        "the namespaced {measure} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect())
}

/// The durations in `lines` that start with `key`, in milliseconds.
pub fn durations(lines: &[String], key: &str) -> Vec<Duration> {
    lines
        .iter()
        .filter_map(|line| line.strip_prefix(key)?.trim().parse::<f64>().ok())
        .map(|ms| Duration::from_secs_f64(ms / 1000.0))
        .collect()
}

/// The count after `key` in `lines`, or 0.
pub fn count(lines: &[String], key: &str) -> usize {
    lines
        .iter()
        .find_map(|line| line.strip_prefix(key)?.trim().parse().ok())
        .unwrap_or(0)
}

/// Outside the namespace: carry each connection to the Unix socket `path` on to `server`, until
/// dropped. With [`tcp_to_unix`] inside it, a client in the namespace reaches a server outside,
/// through the namespace's loopback (netem) once each way.
pub fn unix_to_tcp(
    path: &std::path::Path,
    server: std::net::SocketAddr,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path)?;
    Ok(tokio::spawn(async move {
        while let Ok((mut unix, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Ok(mut tcp) = tokio::net::TcpStream::connect(server).await {
                    let _ = tcp.set_nodelay(true);
                    let _ = tokio::io::copy_bidirectional(&mut unix, &mut tcp).await;
                }
            });
        }
    }))
}

/// Inside the namespace: listen on loopback, and carry each connection on to the Unix socket
/// `path`. Its port.
pub async fn tcp_to_unix(path: std::path::PathBuf) -> anyhow::Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let path = path.clone();
            tokio::spawn(async move {
                let _ = tcp.set_nodelay(true);
                if let Ok(mut unix) = tokio::net::UnixStream::connect(&path).await {
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut unix).await;
                }
            });
        }
    });
    Ok(port)
}
