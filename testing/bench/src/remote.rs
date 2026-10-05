//! A remote session under measure: koh, mosh or ssh, its server hosting a program and its client
//! painting into a fux-vt terminal (the user's terminal), over a link that counts what it carries.
//!
//! koh runs as its real server and client loops (`serve_endpoint`, `run_client`) in this process,
//! over the fault link of koh's own tests (`tests/net/link.rs`), whose only path is in-process, so
//! every packet is counted. mosh and ssh run as their own binaries: the server (`mosh-server`, a
//! `sshd` of this user's on loopback) hosts the program, and the client (`mosh-client`, `ssh -tt`)
//! runs on a PTY of koh's whose output this process reads, through a proxy that counts.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use koh::client::{run_client, BackendTerminal, ClientTerminal, IrohConnector, KohBackend};
use koh::predict::{DisplayPreference, Overlay};
use koh::pty::{Launcher, Pty};
use koh::server::cli::{serve_endpoint, Hosting, ServeConfig};
use koh::terminal::{Size, TerminalScreen};
use koh::transport_iroh::generate_secret_key;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::link::{FaultNet, Profile as FaultProfile};
use crate::proxy::{Counts, Profile, Proxy};

/// The system under measure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum System {
    Koh,
    Mosh,
    Ssh,
}

impl System {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Koh => "koh",
            Self::Mosh => "mosh",
            Self::Ssh => "ssh",
        }
    }
}

/// What the measuring needs from outside: koh's binary (the launcher of its PTYs), and for ssh a
/// running `sshd` and the key it accepts.
pub struct Setup {
    pub koh: PathBuf,
    pub sshd: Option<Sshd>,
    /// Whether mosh and ssh connect straight to their servers, with no proxy (and no counts): in
    /// a namespace, where netem is the link and a proxy would put each packet through it twice.
    pub direct: bool,
}

/// The user's terminal: a fux-vt parser reading what the client painted, and how many times it
/// has.
#[derive(Clone)]
pub struct Shown {
    pub parser: Arc<Mutex<fux_vt::Parser>>,
    /// How many times the client painted (koh) or wrote (mosh, ssh) to the terminal.
    pub paints: watch::Receiver<u64>,
    /// The bytes the client wrote to the terminal.
    pub written: Arc<std::sync::atomic::AtomicU64>,
}

impl Shown {
    /// `look` at the screen.
    pub fn with<T>(&self, look: impl FnOnce(&fux_vt::Screen) -> T) -> T {
        look(
            self.parser
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .screen(),
        )
    }
}

/// A connected session.
pub struct Remote {
    pub system: System,
    pub shown: Shown,
    /// koh's synced screen, without its predictions, as the client last painted it.
    pub synced: Option<Arc<Mutex<Option<TerminalScreen>>>>,
    inner: Inner,
}

enum Inner {
    Koh {
        net: FaultNet,
        server_id: iroh::EndpointId,
        client_id: iroh::EndpointId,
        input: mpsc::Sender<Vec<u8>>,
        resize: mpsc::Sender<()>,
        size: Arc<Mutex<Size>>,
        task: JoinHandle<anyhow::Result<Option<u32>>>,
        shutdown: CancellationToken,
        server: JoinHandle<anyhow::Result<()>>,
    },
    Pty {
        pty: Arc<Pty>,
        proxy: Option<Proxy>,
        reader: JoinHandle<()>,
        mosh_pid: Option<i32>,
    },
}

/// koh's client terminal: koh's own `BackendTerminal`, painting into a buffer that goes to the
/// user's terminal after every frame.
struct Readback {
    terminal: BackendTerminal<Buffer>,
    buffer: Buffer,
    written: Arc<std::sync::atomic::AtomicU64>,
    shown: Arc<Mutex<fux_vt::Parser>>,
    synced: Arc<Mutex<Option<TerminalScreen>>>,
    paints: watch::Sender<u64>,
}

#[derive(Clone)]
struct Buffer {
    painted: Arc<Mutex<Vec<u8>>>,
    size: Arc<Mutex<Size>>,
}

impl KohBackend for Buffer {
    fn write_bytes(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.painted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn enter_raw_mode(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn leave_raw_mode(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn size(&self) -> std::io::Result<Size> {
        Ok(*self.size.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl ClientTerminal for Readback {
    fn render(
        &mut self,
        state: &TerminalScreen,
        overlay: &Overlay<'_>,
        status: Option<&str>,
    ) -> std::io::Result<()> {
        self.terminal.render(state, overlay, status)?;
        let painted = std::mem::take(
            &mut *self
                .buffer
                .painted
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        self.written.fetch_add(
            u64::try_from(painted.len()).unwrap_or(0),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.shown
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .process(&painted)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        *self.synced.lock().unwrap_or_else(PoisonError::into_inner) = Some(state.clone());
        self.paints.send_modify(|n| *n = n.wrapping_add(1));
        Ok(())
    }

    fn size(&self) -> std::io::Result<Size> {
        self.buffer.size()
    }

    fn window_resized(&mut self) {
        self.terminal.window_resized();
    }
}

fn parser(rows: u16, cols: u16) -> anyhow::Result<fux_vt::Parser> {
    fux_vt::Parser::new(rows, cols, 0).map_err(|e| anyhow!("{e}"))
}

/// A `sshd` of this user's on loopback, accepting one key, for the life of the run.
pub struct Sshd {
    pub port: u16,
    pub key: PathBuf,
    /// The daemon's pid, if this started it.
    pid: Option<i32>,
}

impl Sshd {
    /// Start one, its keys and configuration in `dir`.
    pub fn start(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let host = dir.join("host_key");
        let key = dir.join("client_key");
        for path in [&host, &key] {
            if !path.exists() {
                let status = std::process::Command::new("ssh-keygen")
                    .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                    .arg(path)
                    .status()?;
                anyhow::ensure!(status.success(), "ssh-keygen failed");
            }
        }
        std::fs::copy(dir.join("client_key.pub"), dir.join("authorized_keys"))?;
        let port = free_tcp_port()?;
        let pidfile = dir.join("sshd.pid");
        let _ = std::fs::remove_file(&pidfile);
        let config = format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\nPidFile {}\n\
             UsePAM no\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n",
            host.display(),
            dir.join("authorized_keys").display(),
            pidfile.display()
        );
        std::fs::write(dir.join("sshd_config"), config)?;
        let sshd = which("sshd").ok_or_else(|| anyhow!("no sshd"))?;
        let status = std::process::Command::new(sshd)
            .arg("-f")
            .arg(dir.join("sshd_config"))
            .arg("-E")
            .arg(dir.join("sshd.log"))
            .status()?;
        anyhow::ensure!(status.success(), "sshd failed to start");
        for _ in 0..100 {
            if let Ok(pid) = std::fs::read_to_string(&pidfile) {
                let pid = pid.trim().parse().context("sshd's pid")?;
                return Ok(Self {
                    port,
                    key,
                    pid: Some(pid),
                });
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err(anyhow!("sshd wrote no pid file"))
    }
}

impl Sshd {
    /// An sshd another process runs, reached at `port` with `key`.
    pub const fn at(port: u16, key: PathBuf) -> Self {
        Self {
            port,
            key,
            pid: None,
        }
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            kill(pid);
        }
    }
}

fn kill(pid: i32) {
    let _ = std::process::Command::new("kill")
        .arg(pid.to_string())
        .status();
}

fn free_tcp_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

fn free_udp_port() -> std::io::Result<u16> {
    Ok(std::net::UdpSocket::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

/// The program `name` on `PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
    })
}

impl Remote {
    /// Connect `system` hosting `program` (argv) at `rows × cols` over `profile`.
    pub async fn connect(
        system: System,
        setup: &Setup,
        program: &[String],
        (rows, cols): (u16, u16),
        profile: Profile,
        seed: u64,
    ) -> anyhow::Result<Self> {
        match system {
            System::Koh => Self::koh(setup, program, (rows, cols), profile, seed).await,
            System::Mosh => Self::mosh(setup, program, (rows, cols), profile, seed).await,
            System::Ssh => Self::ssh(setup, program, (rows, cols), profile).await,
        }
    }

    async fn koh(
        setup: &Setup,
        program: &[String],
        (rows, cols): (u16, u16),
        profile: Profile,
        seed: u64,
    ) -> anyhow::Result<Self> {
        let net = FaultNet::new(
            FaultProfile {
                loss: profile.loss,
                delay: profile.delay,
                rate: profile.rate,
                queue: Duration::from_millis(100),
                ..FaultProfile::default()
            },
            seed,
        );
        let server_secret = generate_secret_key()?;
        let client_secret = generate_secret_key()?;
        let server_id = server_secret.public();
        let client_id = client_secret.public();
        let server_endpoint = net.endpoint(server_secret, true).await?;
        let config = ServeConfig {
            allow: vec![client_id],
            command: program.to_vec(),
            scrollback: 1000,
            launcher: Launcher::new(&setup.koh),
            ..ServeConfig::default()
        };
        let hosting = Hosting::from_config(&config)?;
        let shutdown = CancellationToken::new();
        let server = tokio::spawn(serve_endpoint(server_endpoint, hosting, shutdown.clone()));
        let endpoint = net.endpoint(client_secret, false).await?;
        let connector = IrohConnector::new(endpoint, FaultNet::addr(server_id));
        let channel = connector.connect().await?;
        let start = Size::new(rows, cols);
        let buffer = Buffer {
            painted: Arc::default(),
            size: Arc::new(Mutex::new(start)),
        };
        let shown = Arc::new(Mutex::new(parser(rows, cols)?));
        let synced = Arc::new(Mutex::new(None));
        let (paints_tx, paints) = watch::channel(0u64);
        let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let terminal = Readback {
            terminal: BackendTerminal::enter(buffer.clone(), false)?,
            buffer: buffer.clone(),
            written: written.clone(),
            shown: shown.clone(),
            synced: synced.clone(),
            paints: paints_tx,
        };
        let (input, input_rx) = mpsc::channel(1024);
        let (resize, resize_rx) = mpsc::channel(8);
        let task = tokio::spawn(run_client(
            channel,
            connector,
            DisplayPreference::Always,
            start,
            input_rx,
            resize_rx,
            terminal,
            CancellationToken::new(),
            None,
        ));
        Ok(Self {
            system: System::Koh,
            shown: Shown {
                parser: shown,
                paints,
                written,
            },
            synced: Some(synced),
            inner: Inner::Koh {
                net,
                server_id,
                client_id,
                input,
                resize,
                size: buffer.size,
                task,
                shutdown,
                server,
            },
        })
    }

    /// The client on a PTY of koh's, its output read into the user's terminal; replies to the
    /// terminal's queries go back, as a terminal sends them.
    fn client_on_pty(
        setup: &Setup,
        argv: &[String],
        (rows, cols): (u16, u16),
        proxy: Option<Proxy>,
        mosh_pid: Option<i32>,
    ) -> anyhow::Result<(Shown, Inner)> {
        let (pty, mut output) = Pty::spawn(
            rows,
            cols,
            argv,
            "xterm-256color",
            &Launcher::new(&setup.koh),
        )
        .map_err(|e| anyhow!("{e}"))?;
        let pty = Arc::new(pty);
        let shown = Arc::new(Mutex::new(parser(rows, cols)?));
        let (paints_tx, paints) = watch::channel(0u64);
        let written = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reader = {
            let (shown, pty, written) = (shown.clone(), pty.clone(), written.clone());
            tokio::spawn(async move {
                while let Some(chunk) = output.recv().await {
                    written.fetch_add(
                        u64::try_from(chunk.len()).unwrap_or(0),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    let mut replies = Vec::new();
                    let _ = shown
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .process_with_replies(&chunk, |reply| replies.extend_from_slice(reply));
                    if !replies.is_empty() {
                        let _ = pty.write_input(&replies);
                    }
                    paints_tx.send_modify(|n| *n = n.wrapping_add(1));
                }
            })
        };
        Ok((
            Shown {
                parser: shown,
                paints,
                written,
            },
            Inner::Pty {
                pty,
                proxy,
                reader,
                mosh_pid,
            },
        ))
    }

    async fn mosh(
        setup: &Setup,
        program: &[String],
        size: (u16, u16),
        profile: Profile,
        seed: u64,
    ) -> anyhow::Result<Self> {
        let port = free_udp_port()?;
        let server = std::process::Command::new("mosh-server")
            .args(["new", "-i", "127.0.0.1", "-p", &port.to_string(), "--"])
            .args(program)
            .env("LANG", "en_US.UTF-8")
            .output()
            .context("mosh-server")?;
        let stdout = String::from_utf8_lossy(&server.stdout);
        let stderr = String::from_utf8_lossy(&server.stderr);
        let (port, key) = stdout
            .lines()
            .find_map(|l| l.strip_prefix("MOSH CONNECT "))
            .and_then(|rest| rest.split_once(' '))
            .ok_or_else(|| anyhow!("mosh-server said: {stdout} {stderr}"))?;
        let port: u16 = port.trim().parse()?;
        let pid = stderr.split("pid = ").nth(1).and_then(|rest| {
            rest.trim_end_matches(|c: char| !c.is_ascii_digit())
                .parse()
                .ok()
        });
        let proxy = if setup.direct {
            None
        } else {
            Some(Proxy::udp(([127, 0, 0, 1], port).into(), profile, seed).await?)
        };
        let dial = proxy.as_ref().map_or(port, |p| p.addr.port());
        let argv: Vec<String> = [
            "env".to_owned(),
            "LANG=en_US.UTF-8".to_owned(),
            format!("MOSH_KEY={}", key.trim()),
            "mosh-client".to_owned(),
            "127.0.0.1".to_owned(),
            dial.to_string(),
        ]
        .into();
        let (shown, inner) = Self::client_on_pty(setup, &argv, size, proxy, pid)?;
        Ok(Self {
            system: System::Mosh,
            shown,
            synced: None,
            inner,
        })
    }

    async fn ssh(
        setup: &Setup,
        program: &[String],
        size: (u16, u16),
        profile: Profile,
    ) -> anyhow::Result<Self> {
        let sshd = setup.sshd.as_ref().ok_or_else(|| anyhow!("no sshd"))?;
        let proxy = if setup.direct {
            None
        } else {
            Some(Proxy::tcp(([127, 0, 0, 1], sshd.port).into(), profile.delay).await?)
        };
        let dial = proxy.as_ref().map_or(sshd.port, |p| p.addr.port());
        let mut argv: Vec<String> = [
            "ssh",
            // Not the system's configuration: in a namespace its root-owned files look owned by
            // nobody, which ssh refuses, and the measure should not depend on it anyway.
            "-F",
            "/dev/null",
            "-tt",
            "-p",
            &dial.to_string(),
            "-i",
            &sshd.key.display().to_string(),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "127.0.0.1",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        argv.push(program.join(" "));
        let (shown, inner) = Self::client_on_pty(setup, &argv, size, proxy, None)?;
        Ok(Self {
            system: System::Ssh,
            shown,
            synced: None,
            inner,
        })
    }

    /// What the link has delivered so far.
    pub fn counts(&self) -> Counts {
        match &self.inner {
            Inner::Koh {
                net,
                server_id,
                client_id,
                ..
            } => {
                let count = |c: crate::link::Count| crate::proxy::Count {
                    packets: c.packets,
                    bytes: c.bytes,
                };
                Counts {
                    to_server: count(net.delivered(*server_id)),
                    to_client: count(net.delivered(*client_id)),
                }
            }
            Inner::Pty { proxy, .. } => proxy.as_ref().map(Proxy::counts).unwrap_or_default(),
        }
    }

    /// Type `bytes`.
    pub async fn send(&self, bytes: &[u8]) -> anyhow::Result<()> {
        match &self.inner {
            Inner::Koh { input, .. } => Ok(input.send(bytes.to_vec()).await?),
            Inner::Pty { pty, .. } => Ok(pty.write_input(bytes)?),
        }
    }

    /// The user's terminal is now `rows × cols`.
    pub async fn resize(&self, rows: u16, cols: u16) -> anyhow::Result<()> {
        self.shown
            .parser
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .resize(rows, cols)
            .map_err(|e| anyhow!("{e}"))?;
        match &self.inner {
            Inner::Koh { resize, size, .. } => {
                *size.lock().unwrap_or_else(PoisonError::into_inner) = Size::new(rows, cols);
                Ok(resize.send(()).await?)
            }
            Inner::Pty { pty, .. } => pty.resize(rows, cols).map_err(|e| anyhow!("{e}")),
        }
    }

    /// Wait until the link has carried nothing for `quiet`, up to `cap`. Whether it went quiet.
    pub async fn quiet(&self, quiet: Duration, cap: Duration) -> bool {
        let start = tokio::time::Instant::now();
        let mut last = self.counts();
        let mut since = tokio::time::Instant::now();
        while start.elapsed() < cap {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let now = self.counts();
            if now == last {
                if since.elapsed() >= quiet {
                    return true;
                }
            } else {
                last = now;
                since = tokio::time::Instant::now();
            }
        }
        false
    }

    pub async fn stop(self) {
        match self.inner {
            Inner::Koh {
                input,
                resize,
                task,
                shutdown,
                server,
                ..
            } => {
                drop(input);
                drop(resize);
                let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
                shutdown.cancel();
                let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
            }
            Inner::Pty {
                pty,
                proxy,
                reader,
                mosh_pid,
            } => {
                let _ = pty.kill();
                reader.abort();
                if let Some(pid) = mosh_pid {
                    kill(pid);
                }
                drop(proxy);
                if let Ok(pty) = Arc::try_unwrap(pty) {
                    let _ = tokio::task::spawn_blocking(move || pty.shutdown()).await;
                }
            }
        }
    }
}
