//! `koh ssh` — mosh-style SSH bootstrap over iroh-ssh.
//!
//! This mode uses `iroh-ssh` to authenticate to the remote host and launch a one-shot `koh serve`
//! there. After the remote endpoint id is printed, the local client connects normally over iroh/QUIC.
//! The iroh-ssh process stays alive only as the parent of the remote `koh serve` process.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;

use crate::client::{connect_with_secret, ConnectArgs};
use crate::transport_iroh::{default_key_path, format_endpoint_id, load_or_create_secret_key};

const BOOTSTRAP_MARKER: &str = "KOH_BOOTSTRAP_ENDPOINT_ID=";

/// Arguments for `koh ssh <iroh-ssh-destination>`.
#[derive(Args, Debug)]
pub struct SshArgs {
    /// iroh-ssh destination, e.g. `user@<iroh-ssh-endpoint-id>`.
    destination: String,

    /// Path to the local client's persistent secret key.
    #[arg(long)]
    key_file: Option<PathBuf>,

    /// Local iroh-ssh binary to execute.
    #[arg(long = "iroh-ssh", default_value = "iroh-ssh")]
    iroh_ssh: String,

    /// Remote koh binary to execute on the iroh-ssh host.
    #[arg(long, default_value = "koh")]
    remote_koh: String,

    /// Pass an extra option to iroh-ssh. Repeat for multiple options, e.g.
    /// `--iroh-ssh-option -i --iroh-ssh-option ~/.ssh/id_ed25519`.
    #[arg(
        long = "iroh-ssh-option",
        alias = "ssh-option",
        value_name = "ARG",
        allow_hyphen_values = true
    )]
    iroh_ssh_options: Vec<String>,

    /// Ask the remote koh server to use this relay URL, and dial it locally with the same relay.
    #[arg(long, value_name = "URL")]
    relay_url: Option<String>,

    /// Honor remote OSC-52 clipboard writes.
    #[arg(long)]
    clipboard: bool,

    /// Seconds to wait for the remote koh server to print its endpoint id.
    #[arg(long, default_value_t = 60)]
    bootstrap_timeout_secs: u64,
}

/// Launch `koh serve` on a remote host over iroh-ssh, then attach to it over iroh.
pub async fn run(args: SshArgs) -> Result<Option<u32>> {
    let key_file = match args.key_file.clone() {
        Some(p) => p,
        None => default_key_path("client")?,
    };
    let secret = load_or_create_secret_key(&key_file).with_context(|| {
        format!(
            "loading client key from {} (pass --key-file to use a writable path)",
            key_file.display()
        )
    })?;
    let client_id = format_endpoint_id(&secret.public());

    let remote_command =
        remote_serve_command(&args.remote_koh, &client_id, args.relay_url.as_deref());
    eprintln!(
        "bootstrapping remote koh over iroh-ssh: {}",
        args.destination
    );

    let mut child =
        spawn_iroh_ssh(&args, &remote_command).context("spawning iroh-ssh bootstrap")?;
    let stdout = child
        .stdout
        .take()
        .context("iroh-ssh stdout was not piped for bootstrap parsing")?;

    let (tx, rx) = mpsc::channel::<String>();
    std::thread::Builder::new()
        .name("koh-iroh-ssh-bootstrap-stdout".into())
        .spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Some(id) = line.strip_prefix(BOOTSTRAP_MARKER) {
                    let _ = tx.send(id.trim().to_string());
                } else {
                    eprintln!("remote stdout: {line}");
                }
            }
        })
        .context("spawning ssh stdout reader")?;

    let server_id = wait_for_server_id(
        &mut child,
        &rx,
        Duration::from_secs(args.bootstrap_timeout_secs),
    )?;
    eprintln!("remote koh id: {server_id}");

    let connect_args = ConnectArgs::new(
        server_id,
        args.key_file,
        None,
        args.relay_url,
        args.clipboard,
    );
    let result = connect_with_secret(connect_args, secret).await;

    // The remote `koh serve` was launched for this client session; shut it down when the client exits.
    terminate_child(child);
    result
}

fn spawn_iroh_ssh(args: &SshArgs, remote_command: &str) -> Result<Child> {
    let mut cmd = Command::new(&args.iroh_ssh);
    cmd.args(&args.iroh_ssh_options)
        .arg(&args.destination)
        .arg(remote_command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    Ok(cmd.spawn()?)
}

fn wait_for_server_id(
    child: &mut Child,
    rx: &mpsc::Receiver<String>,
    timeout: Duration,
) -> Result<String> {
    let start = std::time::Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(id) => return Ok(id),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("iroh-ssh bootstrap ended before remote koh printed an endpoint id")
            }
        }
        if let Some(status) = child.try_wait().context("checking ssh bootstrap status")? {
            anyhow::bail!("iroh-ssh bootstrap exited before remote koh was ready: {status}");
        }
        if start.elapsed() >= timeout {
            anyhow::bail!("timed out waiting for remote koh endpoint id");
        }
    }
}

fn remote_serve_command(remote_koh: &str, client_id: &str, relay_url: Option<&str>) -> String {
    let mut parts = vec![
        shell_quote(remote_koh),
        "serve".to_string(),
        "--ephemeral-key".to_string(),
        "--print-id-stdout".to_string(),
        "--no-qr".to_string(),
        "--allow".to_string(),
        shell_quote(client_id),
    ];
    if let Some(url) = relay_url {
        parts.push("--relay-url".to_string());
        parts.push(shell_quote(url));
    }
    format!("exec {}", parts.join(" "))
}

fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.' | ':' | '@'))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn terminate_child(mut child: Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let _ = child.kill();
    let _ = child.wait();
}
