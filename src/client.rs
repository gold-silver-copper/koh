//! Client operations for koh: exec, headless jobs, delta cp/--sync,
//! OSC 133 session queries/wait, local `fux` pane-folder mirroring (`mount`),
//! and interactive `connect` powered directly by embedded `fux::view`.

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, File};
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fux_vt::PICTURE_MAX;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointId, RelayUrl, SecretKey};
use tokio::io::AsyncReadExt as _;
use tokio::sync::watch;

use crate::keys::{Role, Route, load_or_create_key, resolve_server};
use crate::net::{close_error, connect_server, map_conn_err, open_authed_stream};
use crate::pane::write_v1_metadata;
use crate::proto::{
    ClientEvent, ExecClientMsg, ExecServerMsg, JobInfo, LogMsg, MAX_CHUNK, MAX_CTRL, MAX_FRAME,
    PictureKind, Reply, Request, ScreenFrame, ServerEvent, SessionInfo, SyncSummary, WaitResult,
    recv_msg, recv_msg_opt, send_msg, spawn_msg_reader,
};
use crate::sync::{receive_tree, send_tree};
use crate::{Exit, KohError, Result, atomic_write};

const PICTURE_CACHE_MAX_COUNT: usize = 16;
const PICTURE_CACHE_MAX_BYTES: usize = 32 << 20; // 32 MiB (covers fux-vt's 8 x 4 MiB)
const RECONNECT_INPUT_BUFFER_MAX: usize = 64 << 10; // 64 KiB
const CTL_LINE_MAX: usize = 4096;

#[derive(Clone, Debug)]
pub struct DialOptions {
    pub key_file: Option<PathBuf>,
    pub direct: Option<SocketAddr>,
    pub relay: Option<RelayUrl>,
    pub json: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ConnectOptions {
    pub session: Option<u32>,
    pub new: bool,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
}

struct MountSpec {
    session: Option<u32>,
    new: bool,
    argv: Vec<String>,
    cwd: Option<String>,
    cols: u16,
    rows: u16,
    cell_w: u16,
    cell_h: u16,
    initial_stream: Option<(SendStream, RecvStream)>,
    preopened_fifos: Option<(File, File)>,
    view_ctl: Option<PathBuf>,
    view_exited: Option<Arc<AtomicBool>>,
    cancel: watch::Receiver<bool>,
}

pub struct Client {
    secret: SecretKey,
    server_id: EndpointId,
    route: Option<Route>,
    interactive: bool,
    endpoint: Endpoint,
    conn: Connection,
}

impl Client {
    pub async fn connect(target: &str, opts: &DialOptions, interactive: bool) -> Result<Self> {
        let secret = load_or_create_key(Role::Client, opts.key_file.as_deref())?;
        let (server_id, route) = resolve_server(
            target,
            opts.key_file.as_deref(),
            opts.direct,
            opts.relay.clone(),
        )?;
        Self::connect_direct(secret, server_id, route, interactive).await
    }

    pub async fn connect_direct(
        secret: SecretKey,
        server_id: EndpointId,
        route: Option<Route>,
        interactive: bool,
    ) -> Result<Self> {
        let (endpoint, conn) =
            connect_server(secret.clone(), server_id, route.clone(), interactive).await?;
        Ok(Self {
            secret,
            server_id,
            route,
            interactive,
            endpoint,
            conn,
        })
    }

    /// Re-establishes the underlying QUIC endpoint and connection after a network drop or roam.
    pub async fn redial(&mut self) -> Result<()> {
        self.conn.close(0u32.into(), b"redial");
        self.endpoint.close().await;
        let (endpoint, conn) = connect_server(
            self.secret.clone(),
            self.server_id,
            self.route.clone(),
            self.interactive,
        )
        .await?;
        self.endpoint = endpoint;
        self.conn = conn;
        Ok(())
    }

    /// Returns a handle to the active QUIC connection.
    pub fn connection(&self) -> Connection {
        self.conn.clone()
    }

    pub async fn request(&self, req: &Request) -> Result<(SendStream, RecvStream)> {
        let (mut send, mut recv) = open_authed_stream(&self.conn, &self.secret).await?;
        send_msg(&mut send, req, MAX_CTRL)
            .await
            .map_err(|e| close_error(&self.conn).unwrap_or(e))?;
        let reply: Reply = recv_msg(&mut recv, MAX_CTRL)
            .await
            .map_err(|e| map_conn_err(&self.conn, e.message))?;
        reply.into_result()?;
        Ok((send, recv))
    }

    pub async fn close(self) {
        self.conn.close(0u32.into(), b"");
        self.endpoint.close().await;
    }

    /// Raw non-PTY exec with separate stdout/stderr, stdin EOF, and exit code passthrough.
    pub async fn exec(
        &self,
        argv: Vec<String>,
        cwd: Option<String>,
        shell: bool,
        stdin_bytes: Option<Vec<u8>>,
        capture_json: bool,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let (mut send, mut recv) = self.request(&Request::Exec { argv, cwd, shell }).await?;

        let stdin_task = tokio::spawn(async move {
            if let Some(data) = stdin_bytes {
                for chunk in data.chunks(32 << 10) {
                    if send_msg(&mut send, &ExecClientMsg::Stdin(chunk.to_vec()), MAX_CHUNK)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                let _ = send_msg(&mut send, &ExecClientMsg::Eof, MAX_CTRL).await;
            } else if !std::io::stdin().is_terminal() {
                let mut stdin = tokio::io::stdin();
                let mut buf = vec![0u8; 32 << 10];
                loop {
                    match stdin.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Some(slice) = buf.get(..n)
                                && send_msg(
                                    &mut send,
                                    &ExecClientMsg::Stdin(slice.to_vec()),
                                    MAX_CHUNK,
                                )
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = send_msg(&mut send, &ExecClientMsg::Eof, MAX_CTRL).await;
            } else {
                let _ = send_msg(&mut send, &ExecClientMsg::Eof, MAX_CTRL).await;
            }
            let _ = send.finish();
        });

        let mut cap_out = Vec::new();
        let mut cap_err = Vec::new();
        let mut exit_code = 0i32;
        while let Some(msg) = recv_msg_opt::<ExecServerMsg>(&mut recv, MAX_CHUNK).await? {
            match msg {
                ExecServerMsg::Stdout(bytes) => {
                    if capture_json {
                        cap_out.extend_from_slice(&bytes);
                    } else {
                        let _ = std::io::stdout().write_all(&bytes);
                        let _ = std::io::stdout().flush();
                    }
                }
                ExecServerMsg::Stderr(bytes) => {
                    if capture_json {
                        cap_err.extend_from_slice(&bytes);
                    } else {
                        let _ = std::io::stderr().write_all(&bytes);
                        let _ = std::io::stderr().flush();
                    }
                }
                ExecServerMsg::Exit(code) => {
                    exit_code = code;
                    break;
                }
            }
        }
        stdin_task.abort();
        Ok((exit_code, cap_out, cap_err))
    }

    pub async fn run_job(
        &self,
        name: Option<String>,
        argv: Vec<String>,
        cwd: Option<String>,
        shell: bool,
    ) -> Result<JobInfo> {
        let (_, mut recv) = self
            .request(&Request::Run {
                name,
                argv,
                cwd,
                shell,
            })
            .await?;
        recv_msg(&mut recv, MAX_CTRL).await
    }

    pub async fn jobs(&self, name: Option<String>) -> Result<Vec<JobInfo>> {
        let (_, mut recv) = self.request(&Request::Jobs { name }).await?;
        recv_msg(&mut recv, MAX_CTRL).await
    }

    pub async fn logs(
        &self,
        name: String,
        tail: Option<usize>,
        all: bool,
        follow: bool,
    ) -> Result<(Vec<u8>, String, Option<i32>, u64)> {
        let (_, mut recv) = self
            .request(&Request::Logs {
                name,
                tail,
                all,
                follow,
            })
            .await?;
        let mut buf = Vec::new();
        let mut final_state = String::new();
        let mut final_exit = None;
        let mut age = 0u64;
        while let Some(msg) = recv_msg_opt::<LogMsg>(&mut recv, MAX_CHUNK).await? {
            match msg {
                LogMsg::Data(bytes) => {
                    if follow {
                        let _ = std::io::stdout().write_all(&bytes);
                        let _ = std::io::stdout().flush();
                    } else {
                        buf.extend_from_slice(&bytes);
                    }
                }
                LogMsg::Done {
                    state,
                    exit,
                    age_secs,
                } => {
                    final_state = state;
                    final_exit = exit;
                    age = age_secs;
                    break;
                }
            }
        }
        Ok((buf, final_state, final_exit, age))
    }

    pub async fn kill_job(&self, name: String, signal: i32) -> Result<JobInfo> {
        let (_, mut recv) = self.request(&Request::Kill { name, signal }).await?;
        recv_msg(&mut recv, MAX_CTRL).await
    }

    pub async fn wait_job(
        &self,
        name: String,
        text: Option<String>,
        tail: usize,
        timeout_secs: Option<u64>,
    ) -> Result<WaitResult> {
        let (_, mut recv) = self
            .request(&Request::WaitJob {
                name,
                text,
                tail,
                timeout_secs,
            })
            .await?;
        recv_msg(&mut recv, MAX_FRAME).await
    }

    pub async fn cp_push(
        &self,
        local_src: &Path,
        remote_dst: String,
        excludes: Vec<String>,
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
    ) -> Result<SyncSummary> {
        self.cp_push_many(
            &[local_src.to_path_buf()],
            &remote_dst,
            &excludes,
            delete,
            preserve_mtime,
            dry_run,
        )
        .await
    }

    pub async fn cp_push_many(
        &self,
        local_srcs: &[PathBuf],
        remote_dst: &str,
        excludes: &[String],
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
    ) -> Result<SyncSummary> {
        if local_srcs.is_empty() {
            return Err(KohError::usage("cp requires at least one source"));
        }
        if local_srcs.len() > 1 && delete {
            return Err(KohError::usage("--delete requires a single source"));
        }
        let preserve_root = local_srcs.len() > 1;
        let mut total = SyncSummary {
            dry_run,
            ..SyncSummary::default()
        };
        for src in local_srcs {
            let (mut send, mut recv) = self
                .request(&Request::CpPush {
                    dst: remote_dst.to_string(),
                    excludes: excludes.to_vec(),
                    delete,
                    preserve_mtime,
                    dry_run,
                })
                .await?;
            let part = send_tree(src, excludes, preserve_root, &mut send, &mut recv).await?;
            total.merge(part);
        }
        Ok(total)
    }

    pub async fn cp_pull(
        &self,
        remote_src: String,
        local_dst: &Path,
        excludes: Vec<String>,
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
    ) -> Result<SyncSummary> {
        self.cp_pull_many(
            &[remote_src],
            local_dst,
            &excludes,
            delete,
            preserve_mtime,
            dry_run,
        )
        .await
    }

    pub async fn cp_pull_many(
        &self,
        remote_srcs: &[String],
        local_dst: &Path,
        excludes: &[String],
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
    ) -> Result<SyncSummary> {
        if remote_srcs.is_empty() {
            return Err(KohError::usage("cp requires at least one source"));
        }
        if remote_srcs.len() > 1 && delete {
            return Err(KohError::usage("--delete requires a single source"));
        }
        let preserve_root = remote_srcs.len() > 1;
        let mut total = SyncSummary {
            dry_run,
            ..SyncSummary::default()
        };
        for src in remote_srcs {
            let (mut send, mut recv) = self
                .request(&Request::CpPull {
                    src: src.clone(),
                    excludes: excludes.to_vec(),
                    delete,
                    preserve_mtime,
                    dry_run,
                    preserve_root,
                })
                .await?;
            let part = receive_tree(
                local_dst,
                excludes,
                delete,
                preserve_mtime,
                dry_run,
                &mut send,
                &mut recv,
            )
            .await?;
            total.merge(part);
        }
        Ok(total)
    }

    pub async fn sessions(&self) -> Result<Vec<SessionInfo>> {
        let (_, mut recv) = self.request(&Request::Sessions).await?;
        recv_msg(&mut recv, MAX_CTRL).await
    }

    pub async fn output(&self, session: u32, last: bool) -> Result<String> {
        let (_, mut recv) = self.request(&Request::Output { session, last }).await?;
        recv_msg(&mut recv, MAX_FRAME).await
    }

    pub async fn wait_session(
        &self,
        session: u32,
        timeout_secs: Option<u64>,
    ) -> Result<WaitResult> {
        let (_, mut recv) = self
            .request(&Request::WaitSession {
                session,
                timeout_secs,
            })
            .await?;
        recv_msg(&mut recv, MAX_FRAME).await
    }

    /// Attaches an interactive local TTY to a remote `fux`-backed session by mounting it into a
    /// private temporary v1 `fux` session folder and running embedded `fux::view` in-process.
    /// Automatically survives network drops and roaming; detach locally with `Ctrl-]` `.` or `C-b d`.
    pub async fn connect_interactive(mut self, opts: ConnectOptions) -> Result<i32> {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            self.close().await;
            return Err(KohError::usage(
                "`koh connect` requires a terminal (for scripts/agents use `exec`, `run`, `sessions`, `output`, `wait`)",
            ));
        }
        let winsz = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map(fs::File::from)
            .and_then(|f| fuxix::winsize(&f))
            .unwrap_or(fuxix::Winsize {
                rows: 24,
                cols: 80,
                xpixel: 800,
                ypixel: 480,
            });
        let cols = winsz.cols.max(1);
        let rows = winsz.rows.max(1);
        let cell_w = if winsz.xpixel > 0 {
            (winsz.xpixel / cols).clamp(1, 100)
        } else {
            10
        };
        let cell_h = if winsz.ypixel > 0 {
            (winsz.ypixel / rows).clamp(1, 100)
        } else {
            20
        };

        // Validate initial attach BEFORE entering raw mode / alt screen so auth/not-found errors
        // report cleanly on stderr without flashing the terminal.
        let initial_stream = match self
            .request(&Request::Attach {
                session: opts.session,
                new: opts.new,
                cols,
                rows,
                cell_w,
                cell_h,
                argv: opts.argv.clone(),
                cwd: opts.cwd.clone(),
            })
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                self.close().await;
                return Err(err);
            }
        };

        // Prepare private 0700 temp fux session + FIFOs BEFORE spawning `fux::view` so there is
        // zero startup race and any setup failure closes the client without touching the TTY.
        let setup = (|| -> Result<(TempConnectDir, PathBuf, PathBuf, PathBuf, File, File)> {
            let temp = TempConnectDir::create()?;
            let session_dir = temp.0.join("session");
            let ws_dir = session_dir.join("connect");
            let pane_dir = ws_dir.join("remote");
            let keys_dir = temp.0.join("keys");
            fs::create_dir_all(pane_dir.join("main"))
                .map_err(|e| KohError::failed(format!("mkdir connect pane: {e}")))?;
            atomic_write(&ws_dir.join("layout"), b"* remote focus=remote\n")
                .map_err(|e| KohError::failed(format!("write layout: {e}")))?;
            install_detach_keys(&keys_dir)?;
            seed_initial_pane(&pane_dir, cols, rows)
                .map_err(|e| KohError::failed(format!("seed pane: {e}")))?;
            let in_fifo = fuxix::fifo(pane_dir.join("in"))
                .map_err(|e| KohError::failed(format!("mkfifo in: {e}")))?;
            let ctl_fifo = fuxix::fifo(pane_dir.join("ctl"))
                .map_err(|e| KohError::failed(format!("mkfifo ctl: {e}")))?;
            Ok((temp, session_dir, pane_dir, keys_dir, in_fifo, ctl_fifo))
        })();
        let (temp, session_dir, pane_dir, keys_dir, in_fifo, ctl_fifo) = match setup {
            Ok(v) => v,
            Err(err) => {
                self.close().await;
                return Err(err);
            }
        };

        // (The viewer's FIFO, in the folder it makes for itself in the session.)
        let view_ctl = session_dir
            .join(format!(".view.{}", std::process::id()))
            .join("ctl");
        let view_exited = Arc::new(AtomicBool::new(false));
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let mount_pane = pane_dir.clone();
        let mount_view_exited = view_exited.clone();
        let mut mount_task = tokio::spawn(async move {
            let res = self
                .mount_session(
                    &mount_pane,
                    MountSpec {
                        session: opts.session,
                        new: opts.new,
                        argv: opts.argv,
                        cwd: opts.cwd,
                        cols,
                        rows,
                        cell_w,
                        cell_h,
                        initial_stream: Some(initial_stream),
                        preopened_fifos: Some((in_fifo, ctl_fifo)),
                        view_ctl: Some(view_ctl),
                        view_exited: Some(mount_view_exited),
                        cancel: cancel_rx,
                    },
                )
                .await;
            self.close().await;
            res
        });

        let view_join =
            tokio::task::spawn_blocking(move || fux::view(session_dir, "connect".into(), keys_dir))
                .await;

        // Always cancel and reap `mount_task` BEFORE dropping `TempConnectDir`.
        view_exited.store(true, Ordering::Relaxed);
        let _ = cancel_tx.send_replace(true);
        if let Ok(mut ctl) = fuxix::open(pane_dir.join("ctl"), true) {
            let _ = ctl.write_all(b"kill\n");
        }
        let mount_res = match tokio::time::timeout(Duration::from_secs(3), &mut mount_task).await {
            Ok(Ok(res)) => res,
            Ok(Err(e)) => Err(KohError::internal(format!("mount task: {e}"))),
            Err(_) => {
                mount_task.abort();
                let _ = mount_task.await;
                Ok(0)
            }
        };
        drop(temp);

        match view_join {
            Ok(Ok(())) => mount_res,
            Ok(Err(msg)) => Err(KohError::failed(msg)),
            Err(e) => Err(KohError::internal(format!("fux view thread: {e}"))),
        }
    }

    /// Mirrors a remote `fux`-backed session into a local v1 `fux` pane folder (`in` & `ctl` FIFOs +
    /// validated screen/picture/clipboard/notice files) so unmodified local `fux view` renders it
    /// alongside local panes, with automatic reconnect on network drops.
    pub async fn mount_local_pane(
        &mut self,
        session: Option<u32>,
        local_dir: &Path,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        let (_cancel_tx, cancel_rx) = watch::channel(false);
        let _ = self
            .mount_session(
                local_dir,
                MountSpec {
                    session,
                    new: false,
                    argv: Vec::new(),
                    cwd: None,
                    cols,
                    rows,
                    cell_w: 10,
                    cell_h: 20,
                    initial_stream: None,
                    preopened_fifos: None,
                    view_ctl: None,
                    view_exited: None,
                    cancel: cancel_rx,
                },
            )
            .await?;
        Ok(())
    }

    async fn mount_session(&mut self, local_dir: &Path, mut spec: MountSpec) -> Result<i32> {
        let (in_fifo, ctl_fifo) = match spec.preopened_fifos.take() {
            Some(pair) => pair,
            None => {
                if let Err(e) = fs::create_dir_all(local_dir.join("main")) {
                    notify_view_quit(spec.view_ctl.as_deref(), spec.view_exited.as_deref()).await;
                    return Err(KohError::failed(format!(
                        "mkdir {}: {e}",
                        local_dir.display()
                    )));
                }
                let in_fifo = match fuxix::fifo(local_dir.join("in")) {
                    Ok(f) => f,
                    Err(e) => {
                        notify_view_quit(spec.view_ctl.as_deref(), spec.view_exited.as_deref())
                            .await;
                        return Err(KohError::failed(format!("mkfifo in: {e}")));
                    }
                };
                let ctl_fifo = match fuxix::fifo(local_dir.join("ctl")) {
                    Ok(f) => f,
                    Err(e) => {
                        notify_view_quit(spec.view_ctl.as_deref(), spec.view_exited.as_deref())
                            .await;
                        return Err(KohError::failed(format!("mkfifo ctl: {e}")));
                    }
                };
                (in_fifo, ctl_fifo)
            }
        };

        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<ClientEvent>(64);
        let pane_path = local_dir.to_path_buf();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut ctl_buf: Vec<u8> = Vec::new();
            let mut ctl_discard = false;
            loop {
                if !pane_path.join("in").exists() {
                    let _ = ev_tx.blocking_send(ClientEvent::Detach);
                    break;
                }
                let ready = fuxix::wait(
                    [
                        (Some(in_fifo.as_fd()), fuxix::POLLIN),
                        (Some(ctl_fifo.as_fd()), fuxix::POLLIN),
                    ],
                    50,
                );
                let Ok([in_ev, ctl_ev]) = ready else { break };
                if in_ev != 0
                    && let Ok(n @ 1..) = (&in_fifo).read(&mut buf)
                    && let Some(slice) = buf.get(..n)
                    && ev_tx
                        .blocking_send(ClientEvent::Input(slice.to_vec()))
                        .is_err()
                {
                    break;
                }
                if ctl_ev != 0
                    && let Ok(n @ 1..) = (&ctl_fifo).read(&mut buf)
                    && let Some(mut rem) = buf.get(..n)
                {
                    while !rem.is_empty() {
                        if ctl_discard {
                            if let Some(nl) = rem.iter().position(|&b| b == b'\n') {
                                ctl_discard = false;
                                rem = rem.get(nl + 1..).unwrap_or_default();
                            } else {
                                break;
                            }
                            continue;
                        }
                        if let Some(nl) = rem.iter().position(|&b| b == b'\n') {
                            let part = rem.get(..nl).unwrap_or_default();
                            rem = rem.get(nl + 1..).unwrap_or_default();
                            if ctl_buf.len().saturating_add(part.len()) > CTL_LINE_MAX {
                                ctl_buf.clear();
                                continue;
                            }
                            ctl_buf.extend_from_slice(part);
                            let line = String::from_utf8_lossy(&ctl_buf).trim().to_string();
                            ctl_buf.clear();
                            let mut words = line.split_whitespace();
                            if words.next() == Some("resize")
                                && let (Some(c), Some(r)) = (
                                    words.next().and_then(|s| s.parse::<u16>().ok()),
                                    words.next().and_then(|s| s.parse::<u16>().ok()),
                                )
                            {
                                let cw = words
                                    .next()
                                    .and_then(|s| s.parse::<u16>().ok())
                                    .unwrap_or(0);
                                let ch = words
                                    .next()
                                    .and_then(|s| s.parse::<u16>().ok())
                                    .unwrap_or(0);
                                let _ = ev_tx.blocking_send(ClientEvent::Resize {
                                    cols: c,
                                    rows: r,
                                    cell_w: cw,
                                    cell_h: ch,
                                });
                            } else if line == "kill" {
                                let _ = ev_tx.blocking_send(ClientEvent::Detach);
                                return;
                            }
                        } else if ctl_buf.len().saturating_add(rem.len()) > CTL_LINE_MAX {
                            ctl_buf.clear();
                            ctl_discard = true;
                            break;
                        } else {
                            ctl_buf.extend_from_slice(rem);
                            break;
                        }
                    }
                }
            }
        });

        let (mut cur_cols, mut cur_rows, mut cur_cw, mut cur_ch) =
            (spec.cols, spec.rows, spec.cell_w, spec.cell_h);
        let mut active_session = spec.session;
        let mut initial_attach = spec.initial_stream.is_none();
        let mut generation = 2u64;
        let mut written_pics: BTreeMap<u32, (PictureKind, usize)> = BTreeMap::new();
        let mut buffered_input = Vec::new();
        let mut current_frame: Option<ScreenFrame> = None;
        let mut exit_code = 0i32;

        let session_root = local_dir
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf);
        let mut last_colours_stamp: Option<FileStamp> = None;
        let mut last_keyboard_stamp: Option<FileStamp> = None;
        let mut last_colours_text = String::new();
        let mut last_keyboard_flags: Option<u8> = None;

        'mount: loop {
            if *spec.cancel.borrow() {
                break 'mount;
            }
            let (mut send, recv) = if let Some(pair) = spec.initial_stream.take() {
                pair
            } else {
                let attach_req = Request::Attach {
                    session: active_session,
                    new: initial_attach && spec.new,
                    cols: cur_cols,
                    rows: cur_rows,
                    cell_w: cur_cw,
                    cell_h: cur_ch,
                    argv: if initial_attach {
                        spec.argv.clone()
                    } else {
                        Vec::new()
                    },
                    cwd: if initial_attach {
                        spec.cwd.clone()
                    } else {
                        None
                    },
                };
                let req_res = tokio::select! {
                    _ = spec.cancel.changed() => {
                        if *spec.cancel.borrow() {
                            break 'mount;
                        }
                        continue 'mount;
                    }
                    res = self.request(&attach_req) => res,
                };
                match req_res {
                    Ok(pair) => {
                        initial_attach = false;
                        pair
                    }
                    Err(err) if is_fatal_attach_err(&err) || initial_attach => {
                        notify_view_quit(spec.view_ctl.as_deref(), spec.view_exited.as_deref())
                            .await;
                        let _ = fs::remove_file(local_dir.join("in"));
                        let _ = fs::remove_file(local_dir.join("ctl"));
                        return Err(err);
                    }
                    Err(_) => {
                        write_mirrored_state(local_dir, "reconnecting", &mut generation);
                        if !reconnect_wait(
                            self,
                            &mut ev_rx,
                            &mut spec.cancel,
                            &mut cur_cols,
                            &mut cur_rows,
                            &mut cur_cw,
                            &mut cur_ch,
                            &mut buffered_input,
                        )
                        .await?
                        {
                            break 'mount;
                        }
                        continue 'mount;
                    }
                }
            };

            // Forward host colours / Kitty keyboard flags already written by `fux view`.
            sync_viewer_told(
                session_root.as_deref(),
                &mut last_colours_stamp,
                &mut last_keyboard_stamp,
                &mut last_colours_text,
                &mut last_keyboard_flags,
                true,
                &mut send,
            )
            .await;

            // Flush any FIFO input that arrived while reconnecting so writes to `in` are never lost.
            if !buffered_input.is_empty() {
                let bytes = std::mem::take(&mut buffered_input);
                if send_msg(&mut send, &ClientEvent::Input(bytes.clone()), MAX_CHUNK)
                    .await
                    .is_err()
                {
                    push_bounded(&mut buffered_input, &bytes, RECONNECT_INPUT_BUFFER_MAX);
                    write_mirrored_state(local_dir, "reconnecting", &mut generation);
                    if !reconnect_wait(
                        self,
                        &mut ev_rx,
                        &mut spec.cancel,
                        &mut cur_cols,
                        &mut cur_rows,
                        &mut cur_cw,
                        &mut cur_ch,
                        &mut buffered_input,
                    )
                    .await?
                    {
                        break 'mount;
                    }
                    continue 'mount;
                }
            }

            current_frame = None;
            let mut server_rx = spawn_msg_reader::<ServerEvent>(recv, MAX_FRAME);
            let mut told_tick = tokio::time::interval(Duration::from_millis(50));

            loop {
                tokio::select! {
                    _ = spec.cancel.changed() => {
                        if *spec.cancel.borrow() {
                            let _ = tokio::time::timeout(
                                Duration::from_millis(200),
                                send_msg(&mut send, &ClientEvent::Detach, MAX_CTRL),
                            )
                            .await;
                            break 'mount;
                        }
                    }
                    msg = server_rx.recv() => {
                        match msg {
                            Some(Ok(ServerEvent::Picture(blob))) => {
                                if blob.bytes.len() <= PICTURE_MAX {
                                    while written_pics.len() >= PICTURE_CACHE_MAX_COUNT
                                        || written_pics
                                            .values()
                                            .map(|(_, n)| *n)
                                            .sum::<usize>()
                                            .saturating_add(blob.bytes.len())
                                            > PICTURE_CACHE_MAX_BYTES
                                    {
                                        let Some((old_id, (old_kind, _))) = written_pics.pop_first()
                                        else {
                                            break;
                                        };
                                        let _ = fs::remove_file(
                                            local_dir.join(format!("pic-{old_id}.{}", old_kind.ext())),
                                        );
                                    }
                                    let name = format!("pic-{}.{}", blob.id, blob.kind.ext());
                                    let _ = atomic_write(&local_dir.join(name), &blob.bytes);
                                    written_pics.insert(blob.id, (blob.kind, blob.bytes.len()));
                                }
                            }
                            Some(Ok(ServerEvent::Full(mut frame))) => {
                                frame.clamp_bounds();
                                active_session = Some(frame.session_id);
                                let done = frame.state != "running";
                                let done_exit = frame.exit.unwrap_or(0);
                                write_mirrored_pane(local_dir, &frame, &mut generation, &mut written_pics);
                                current_frame = Some(frame);
                                if done {
                                    exit_code = done_exit;
                                    // Brief settle so embedded `fux::view` flushes final frame/clipboard/notice.
                                    if spec.view_ctl.is_some() {
                                        tokio::time::sleep(Duration::from_millis(80)).await;
                                    }
                                    break 'mount;
                                }
                            }
                            Some(Ok(ServerEvent::Delta(delta))) => {
                                if let Some(frame) = current_frame.as_mut() {
                                    let _ = frame.apply_delta(delta);
                                    active_session = Some(frame.session_id);
                                    let done = frame.state != "running";
                                    let done_exit = frame.exit.unwrap_or(0);
                                    write_mirrored_pane(local_dir, frame, &mut generation, &mut written_pics);
                                    if done {
                                        exit_code = done_exit;
                                        if spec.view_ctl.is_some() {
                                            tokio::time::sleep(Duration::from_millis(80)).await;
                                        }
                                        break 'mount;
                                    }
                                }
                            }
                            Some(Err(_)) | None => break,
                        }
                    }
                    ev = ev_rx.recv() => {
                        match ev {
                            Some(ClientEvent::Detach) | None => {
                                let _ = send_msg(&mut send, &ClientEvent::Detach, MAX_CTRL).await;
                                break 'mount;
                            }
                            Some(ClientEvent::Resize { cols, rows, cell_w, cell_h }) => {
                                cur_cols = cols;
                                cur_rows = rows;
                                if cell_w > 0 && cell_h > 0 {
                                    cur_cw = cell_w;
                                    cur_ch = cell_h;
                                }
                                if send_msg(
                                    &mut send,
                                    &ClientEvent::Resize { cols, rows, cell_w, cell_h },
                                    MAX_CHUNK,
                                )
                                .await
                                .is_err()
                                {
                                    break;
                                }
                            }
                            Some(ClientEvent::Input(bytes)) => {
                                if send_msg(&mut send, &ClientEvent::Input(bytes.clone()), MAX_CHUNK)
                                    .await
                                    .is_err()
                                {
                                    push_bounded(&mut buffered_input, &bytes, RECONNECT_INPUT_BUFFER_MAX);
                                    break;
                                }
                            }
                            Some(other) => {
                                if send_msg(&mut send, &other, MAX_CHUNK).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    _ = told_tick.tick() => {
                        sync_viewer_told(
                            session_root.as_deref(),
                            &mut last_colours_stamp,
                            &mut last_keyboard_stamp,
                            &mut last_colours_text,
                            &mut last_keyboard_flags,
                            false,
                            &mut send,
                        )
                        .await;
                    }
                }
            }

            write_mirrored_state(local_dir, "reconnecting", &mut generation);
            if !reconnect_wait(
                self,
                &mut ev_rx,
                &mut spec.cancel,
                &mut cur_cols,
                &mut cur_rows,
                &mut cur_cw,
                &mut cur_ch,
                &mut buffered_input,
            )
            .await?
            {
                break 'mount;
            }
        }
        let _ = current_frame;
        // Always signal embedded `fux::view` to exit on EVERY mount termination path.
        notify_view_quit(spec.view_ctl.as_deref(), spec.view_exited.as_deref()).await;
        let _ = fs::remove_file(local_dir.join("in"));
        let _ = fs::remove_file(local_dir.join("ctl"));
        Ok(exit_code)
    }
}

type FileStamp = (u64, i64, i64, u64);

fn file_stamp(path: &Path) -> Option<FileStamp> {
    let m = fs::metadata(path).ok()?;
    Some((m.ino(), m.mtime(), m.mtime_nsec(), m.len()))
}

async fn sync_viewer_told(
    session_root: Option<&Path>,
    last_colours_stamp: &mut Option<FileStamp>,
    last_keyboard_stamp: &mut Option<FileStamp>,
    last_colours_text: &mut String,
    last_keyboard_flags: &mut Option<u8>,
    force_resend: bool,
    send: &mut SendStream,
) {
    if let Some(root) = session_root {
        let colours_path = root.join("colours");
        let stamp = file_stamp(&colours_path);
        if stamp.is_some() && stamp != *last_colours_stamp {
            *last_colours_stamp = stamp;
            if let Ok(text) = fs::read_to_string(&colours_path)
                && !text.is_empty()
                && text.len() <= (16 << 10)
            {
                *last_colours_text = text;
                let _ = send_msg(
                    send,
                    &ClientEvent::Colours(last_colours_text.clone()),
                    MAX_CTRL,
                )
                .await;
            }
        } else if force_resend && !last_colours_text.is_empty() {
            let _ = send_msg(
                send,
                &ClientEvent::Colours(last_colours_text.clone()),
                MAX_CTRL,
            )
            .await;
        }

        let kb_path = root.join("keyboard");
        let kb_stamp = file_stamp(&kb_path);
        if kb_stamp.is_some() && kb_stamp != *last_keyboard_stamp {
            *last_keyboard_stamp = kb_stamp;
            if let Ok(text) = fs::read_to_string(&kb_path)
                && let Ok(flags) = text.trim().parse::<u8>()
            {
                *last_keyboard_flags = Some(flags);
                let _ = send_msg(send, &ClientEvent::Keyboard(flags), MAX_CTRL).await;
            }
        } else if force_resend && let Some(flags) = *last_keyboard_flags {
            let _ = send_msg(send, &ClientEvent::Keyboard(flags), MAX_CTRL).await;
        }
    }
}

async fn notify_view_quit(view_ctl: Option<&Path>, view_exited: Option<&AtomicBool>) {
    let Some(ctl) = view_ctl else { return };
    for _ in 0..200 {
        if view_exited.is_some_and(|v| v.load(Ordering::Relaxed)) {
            return;
        }
        if let Ok(mut f) = fuxix::open(ctl, true)
            && f.write_all(b"quit\n").is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

struct TempConnectDir(PathBuf);

impl TempConnectDir {
    fn create() -> Result<Self> {
        let base_root = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        fs::create_dir_all(&base_root)
            .map_err(|e| KohError::failed(format!("mkdir {}: {e}", base_root.display())))?;
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for attempt in 0..64u32 {
            let path = base_root.join(format!("koh-connect-{pid}-{nanos}-{attempt}"));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(KohError::failed(format!("mkdir {}: {e}", path.display())));
                }
            }
        }
        Err(KohError::failed(
            "could not allocate unique temp connect directory",
        ))
    }
}

impl Drop for TempConnectDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// koh's keys for its viewer. A key's script runs in a folder the viewer makes for it, where `pane`
/// is a link to the pane that has the keys.
fn install_detach_keys(keys_dir: &Path) -> Result<()> {
    const SCRIPTS: [(&str, &[u8]); 4] = [
        ("C-]/dot", b"#!/bin/sh\n# detach\necho quit\n"),
        (
            "C-]/C-]",
            b"#!/bin/sh\n# send C-]\n[ -p pane/in ] && printf '\\035' 1<>pane/in\n",
        ),
        ("C-b/d", b"#!/bin/sh\n# detach\necho quit\n"),
        (
            "C-b/C-b",
            b"#!/bin/sh\n# send C-b\n[ -p pane/in ] && printf '\\002' 1<>pane/in\n",
        ),
    ];
    for (rel, body) in SCRIPTS {
        let path = keys_dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| KohError::failed(format!("mkdir {}: {e}", parent.display())))?;
        }
        fs::write(&path, body)
            .map_err(|e| KohError::failed(format!("write {}: {e}", path.display())))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|e| KohError::failed(format!("chmod {}: {e}", path.display())))?;
    }
    Ok(())
}

fn seed_initial_pane(pane_dir: &Path, cols: u16, rows: u16) -> std::io::Result<()> {
    let main_dir = pane_dir.join("main");
    fs::create_dir_all(&main_dir)?;
    let empty = "\n".repeat(usize::from(rows));
    atomic_write(&main_dir.join("screen"), empty.as_bytes())?;
    atomic_write(&main_dir.join("screen.styled"), empty.as_bytes())?;
    atomic_write(&main_dir.join("lines"), b"0\n\n")?;
    atomic_write(&main_dir.join("links"), b"")?;
    atomic_write(&main_dir.join("pictures"), b"")?;
    let tmp_link = pane_dir.join(".shown.new");
    let _ = fs::remove_file(&tmp_link);
    symlink("main", &tmp_link)?;
    fs::rename(&tmp_link, pane_dir.join("shown"))?;
    atomic_write(
        &pane_dir.join("size"),
        format!("{cols} {rows}\n").as_bytes(),
    )?;
    atomic_write(&pane_dir.join("cursor"), b"0 0 shown 0\n")?;
    atomic_write(&pane_dir.join("modes"), b"\n")?;
    atomic_write(&pane_dir.join("marks"), b"")?;
    atomic_write(&pane_dir.join("state"), b"running\n")?;
    atomic_write(&pane_dir.join("generation"), b"2\n")?;
    Ok(())
}

fn is_fatal_attach_err(err: &KohError) -> bool {
    matches!(err.code, Exit::REFUSED | Exit::NOT_FOUND | Exit::USAGE)
}

fn reconnect_delay(attempt: u32) -> Duration {
    match attempt {
        0 => Duration::from_millis(200),
        1 => Duration::from_millis(500),
        2 => Duration::from_secs(1),
        3 => Duration::from_secs(2),
        _ => Duration::from_secs(5),
    }
}

fn push_bounded(buf: &mut Vec<u8>, bytes: &[u8], cap: usize) {
    let room = cap.saturating_sub(buf.len());
    if room > 0 {
        let take = bytes.len().min(room);
        if let Some(slice) = bytes.get(..take) {
            buf.extend_from_slice(slice);
        }
    }
}

/// Waits with bounded backoff and redials the server while still handling local Detach/Resize/Input
/// (including cancelling an in-flight redial immediately on Detach or viewer shutdown).
/// Returns `Ok(true)` once reconnected, `Ok(false)` if the user detached locally.
#[allow(clippy::too_many_arguments)]
async fn reconnect_wait(
    client: &mut Client,
    ev_rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>,
    cancel: &mut watch::Receiver<bool>,
    cols: &mut u16,
    rows: &mut u16,
    cell_w: &mut u16,
    cell_h: &mut u16,
    pending_input: &mut Vec<u8>,
) -> Result<bool> {
    let mut attempt = 0u32;
    loop {
        if *cancel.borrow() {
            return Ok(false);
        }
        let delay = reconnect_delay(attempt);
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        return Ok(false);
                    }
                }
                () = &mut sleep => break,
                ev = ev_rx.recv() => {
                    match ev {
                        Some(ClientEvent::Detach) | None => return Ok(false),
                        Some(ClientEvent::Resize { cols: c, rows: r, cell_w: cw, cell_h: ch }) => {
                            *cols = c;
                            *rows = r;
                            if cw > 0 && ch > 0 {
                                *cell_w = cw;
                                *cell_h = ch;
                            }
                        }
                        Some(ClientEvent::Input(bytes)) => {
                            push_bounded(pending_input, &bytes, RECONNECT_INPUT_BUFFER_MAX);
                        }
                        Some(_) => {}
                    }
                }
            }
        }
        let redial_fut = client.redial();
        tokio::pin!(redial_fut);
        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        return Ok(false);
                    }
                }
                res = &mut redial_fut => {
                    if res.is_ok() {
                        return Ok(true);
                    }
                    break;
                }
                ev = ev_rx.recv() => {
                    match ev {
                        Some(ClientEvent::Detach) | None => return Ok(false),
                        Some(ClientEvent::Resize { cols: c, rows: r, cell_w: cw, cell_h: ch }) => {
                            *cols = c;
                            *rows = r;
                            if cw > 0 && ch > 0 {
                                *cell_w = cw;
                                *cell_h = ch;
                            }
                        }
                        Some(ClientEvent::Input(bytes)) => {
                            push_bounded(pending_input, &bytes, RECONNECT_INPUT_BUFFER_MAX);
                        }
                        Some(_) => {}
                    }
                }
            }
        }
        attempt = attempt.saturating_add(1);
    }
}

fn write_mirrored_state(dir: &Path, state: &str, generation: &mut u64) {
    *generation = generation.wrapping_add(1);
    let _ = atomic_write(
        &dir.join("generation"),
        format!("{}\n", *generation).as_bytes(),
    );
    let _ = atomic_write(&dir.join("state"), format!("{state}\n").as_bytes());
    *generation = generation.wrapping_add(1);
    let _ = atomic_write(
        &dir.join("generation"),
        format!("{}\n", *generation).as_bytes(),
    );
}

fn write_mirrored_pane(
    dir: &Path,
    frame: &ScreenFrame,
    generation: &mut u64,
    written_pics: &mut BTreeMap<u32, (PictureKind, usize)>,
) {
    *generation = generation.wrapping_add(1);
    let _ = atomic_write(
        &dir.join("generation"),
        format!("{}\n", *generation).as_bytes(),
    );

    let active = frame.referenced_picture_ids();
    let stale: Vec<(u32, PictureKind)> = written_pics
        .iter()
        .filter(|(id, _)| !active.contains(id))
        .map(|(id, (kind, _))| (*id, *kind))
        .collect();
    for (id, kind) in stale {
        written_pics.remove(&id);
        let _ = fs::remove_file(dir.join(format!("pic-{id}.{}", kind.ext())));
    }

    let folder = if frame.alt { "alt" } else { "main" };
    let screen_dir = dir.join(folder);
    let _ = fs::create_dir_all(&screen_dir);
    let _ = atomic_write(&screen_dir.join("screen"), frame.screen.as_bytes());
    let _ = atomic_write(&screen_dir.join("screen.styled"), frame.styled.as_bytes());
    let _ = atomic_write(&screen_dir.join("lines"), frame.lines.as_bytes());
    let _ = atomic_write(&screen_dir.join("links"), frame.links.as_bytes());
    let _ = atomic_write(&screen_dir.join("pictures"), frame.pictures.as_bytes());

    let tmp_link = dir.join(".shown.new");
    let _ = fs::remove_file(&tmp_link);
    if symlink(folder, &tmp_link).is_ok() {
        let _ = fs::rename(&tmp_link, dir.join("shown"));
    }
    if !frame.alt {
        let _ = fs::remove_dir_all(dir.join("alt"));
    }
    // (No `status`: it names a pane's holder and its program by their numbers on this machine,
    // and a mirror has neither here. The viewer knows a pane by its folder.)
    write_v1_metadata(dir, frame);
    if let Some(bytes) = &frame.clipboard {
        let _ = atomic_write(&dir.join("clipboard"), bytes);
    }
    if let Some(msg) = &frame.notice {
        let line = if msg.is_empty() {
            format!("{}\n", frame.notice_seq)
        } else {
            format!("{} {msg}\n", frame.notice_seq)
        };
        let _ = atomic_write(&dir.join("notice"), line.as_bytes());
    }
    *generation = generation.wrapping_add(1);
    let _ = atomic_write(
        &dir.join("generation"),
        format!("{}\n", *generation).as_bytes(),
    );
}

/// Helper for `--sync DIR` before `exec` or `run`.
pub async fn sync_before_command(
    client: &Client,
    local_dir: &Path,
    cwd: Option<&str>,
    excludes: Vec<String>,
    quiet: bool,
) -> Result<(String, SyncSummary)> {
    let remote_dir = match cwd {
        Some(c) => c.to_string(),
        None => local_dir
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty() && *n != ".")
            .map(String::from)
            .ok_or_else(|| KohError::usage("--sync . requires -C REMOTE_DIR"))?,
    };
    let summary = client
        .cp_push(local_dir, remote_dir.clone(), excludes, false, false, false)
        .await?;
    if !quiet {
        let changed = summary.added.len() + summary.updated.len();
        let _ = writeln!(
            std::io::stderr(),
            "synced {} -> {} ({changed} changed, {} unchanged, {} bytes)",
            local_dir.display(),
            remote_dir,
            summary.unchanged,
            summary.bytes_transferred
        );
    }
    Ok((remote_dir, summary))
}

/// Parses a signal name or number for `koh kill --signal`.
pub fn parse_signal(s: &str) -> Result<i32> {
    if let Ok(n) = s.parse::<i32>() {
        return Ok(n);
    }
    match s.to_ascii_uppercase().trim_start_matches("SIG") {
        "HUP" => Ok(1),
        "INT" => Ok(2),
        "QUIT" => Ok(3),
        "KILL" => Ok(9),
        "TERM" => Ok(15),
        _ => Err(KohError::usage(format!("unknown signal {s:?}"))),
    }
}

/// Wait duration helper used by tests & CLI.
pub fn timeout_duration(secs: Option<u64>) -> Option<Duration> {
    secs.map(Duration::from_secs)
}
