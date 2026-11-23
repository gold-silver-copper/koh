//! Client operations for koh: exec, headless jobs, delta cp/--sync,
//! OSC 133 session queries/wait, direct push interactive `connect`, and
//! local `fux` pane-folder mirroring (`mount`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::fd::AsFd as _;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fux_vt::{Cell, PICTURE_MAX, Style, files, kitty, png, sixel};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointId, RelayUrl, SecretKey};
use tokio::io::AsyncReadExt as _;

use crate::keys::{Role, Route, load_or_create_key, resolve_server};
use crate::net::{connect_server, map_conn_err, open_authed_stream};
use crate::pane::write_v1_metadata;
use crate::proto::{
    ClientEvent, ExecClientMsg, ExecServerMsg, JobInfo, LogMsg, MAX_CHUNK, MAX_CTRL, MAX_FRAME,
    PictureBlob, PictureKind, Reply, Request, ScreenFrame, ServerEvent, SessionInfo, SyncSummary,
    WaitResult, recv_msg, recv_msg_opt, send_msg, spawn_msg_reader,
};
use crate::sync::{receive_tree, send_tree};
use crate::{Exit, KohError, Result, atomic_write};

const PICTURE_CACHE_MAX_COUNT: usize = 16;
const PICTURE_CACHE_MAX_BYTES: usize = 32 << 20; // 32 MiB (covers fux-vt's 8 x 4 MiB)
const RECONNECT_INPUT_BUFFER_MAX: usize = 64 << 10; // 64 KiB

const LEAVING: &[u8] = b"\x1b]8;;\x1b\\\x1b[?2004l\x1b[?1004l\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1l\x1b>\x1b[0 q\x1b]112\x1b\\\x1b[m\x1b[?25h\x1b[?7h\x1b[?1049l";

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
    pub on_bell: Option<String>,
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
        send_msg(&mut send, req, MAX_CTRL).await?;
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

    pub async fn wait_file(&self, path: String, timeout_secs: Option<u64>) -> Result<WaitResult> {
        let (_, mut recv) = self
            .request(&Request::WaitFile { path, timeout_secs })
            .await?;
        recv_msg(&mut recv, MAX_CTRL).await
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
        self.cp_push_one(
            local_src,
            remote_dst,
            excludes,
            delete,
            preserve_mtime,
            dry_run,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn cp_push_one(
        &self,
        local_src: &Path,
        remote_dst: String,
        excludes: Vec<String>,
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
        preserve_root: bool,
    ) -> Result<SyncSummary> {
        let (mut send, mut recv) = self
            .request(&Request::CpPush {
                dst: remote_dst,
                excludes: excludes.clone(),
                delete,
                preserve_mtime,
                dry_run,
            })
            .await?;
        send_tree(local_src, &excludes, preserve_root, &mut send, &mut recv).await
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
            let part = self
                .cp_push_one(
                    src,
                    remote_dst.to_string(),
                    excludes.to_vec(),
                    delete,
                    preserve_mtime,
                    dry_run,
                    preserve_root,
                )
                .await?;
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
        self.cp_pull_one(
            remote_src,
            local_dst,
            excludes,
            delete,
            preserve_mtime,
            dry_run,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn cp_pull_one(
        &self,
        remote_src: String,
        local_dst: &Path,
        excludes: Vec<String>,
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
        preserve_root: bool,
    ) -> Result<SyncSummary> {
        let (mut send, mut recv) = self
            .request(&Request::CpPull {
                src: remote_src,
                excludes: excludes.clone(),
                delete,
                preserve_mtime,
                dry_run,
                preserve_root,
            })
            .await?;
        receive_tree(
            local_dst,
            &excludes,
            delete,
            preserve_mtime,
            dry_run,
            &mut send,
            &mut recv,
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
            let part = self
                .cp_pull_one(
                    src.clone(),
                    local_dst,
                    excludes.to_vec(),
                    delete,
                    preserve_mtime,
                    dry_run,
                    preserve_root,
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

    /// Attaches an interactive local TTY to a remote `fux`-backed session, automatically
    /// reconnecting after network drops or roaming. Detach locally with `Ctrl-]` then `.`.
    pub async fn connect_interactive(&mut self, opts: ConnectOptions) -> Result<i32> {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            return Err(KohError::usage(
                "`koh connect` requires a terminal (for scripts/agents use `exec`, `run`, `sessions`, `output`, `wait`)",
            ));
        }
        let tty = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|e| KohError::failed(format!("open /dev/tty: {e}")))?;
        let winsz = fuxix::winsize(&tty).unwrap_or(fuxix::Winsize {
            rows: 24,
            cols: 80,
            xpixel: 800,
            ypixel: 480,
        });
        let (mut cur_cols, mut cur_rows, mut cur_cw, mut cur_ch) = winsize_cells(winsz);

        let _raw = fuxix::raw_mode(
            tty.try_clone()
                .map_err(|e| KohError::failed(format!("clone tty: {e}")))?,
            LEAVING,
        )
        .map_err(|e| KohError::failed(format!("raw mode: {e}")))?;
        let mut tty_out = tty
            .try_clone()
            .map_err(|e| KohError::failed(format!("clone tty: {e}")))?;
        let _ = tty_out.write_all(b"\x1b]8;;\x1b\\\x1b[?1049h\x1b[2J\x1b[?7l");
        let _ = tty_out.flush();

        let mut caps = probe_terminal(&tty, &mut tty_out);
        let initial_leftover = std::mem::take(&mut caps.leftover);

        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<ClientEvent>(64);
        let tty_in = tty;
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut last_size = winsz;
            let mut escape_armed = false;
            loop {
                if let Ok(cur) = fuxix::winsize(&tty_in)
                    && (cur.cols, cur.rows, cur.xpixel, cur.ypixel)
                        != (
                            last_size.cols,
                            last_size.rows,
                            last_size.xpixel,
                            last_size.ypixel,
                        )
                {
                    last_size = cur;
                    let (cols, rows, cell_w, cell_h) = winsize_cells(cur);
                    if ev_tx
                        .blocking_send(ClientEvent::Resize {
                            cols,
                            rows,
                            cell_w,
                            cell_h,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                let ready = fuxix::wait([(Some(tty_in.as_fd()), fuxix::POLLIN)], 30);
                if matches!(ready, Ok([ev]) if ev != 0) {
                    match (&tty_in).read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let bytes = buf.get(..n).unwrap_or_default();
                            // Local detach chord: Ctrl-] (0x1d) followed by '.'
                            if escape_armed {
                                escape_armed = false;
                                if bytes.first() == Some(&b'.') {
                                    let _ = ev_tx.blocking_send(ClientEvent::Detach);
                                    break;
                                }
                                let mut combined = vec![0x1d];
                                combined.extend_from_slice(bytes);
                                if ev_tx.blocking_send(ClientEvent::Input(combined)).is_err() {
                                    break;
                                }
                                continue;
                            }
                            if bytes == [0x1d] {
                                escape_armed = true;
                                continue;
                            }
                            if ev_tx
                                .blocking_send(ClientEvent::Input(bytes.to_vec()))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        });

        let mut painter = TermPainter::new(caps, opts.on_bell);
        let mut active_session = opts.session;
        let mut initial_attach = true;
        let mut pending_leftover = initial_leftover;
        let mut current_frame: Option<ScreenFrame> = None;
        let mut exit_code = 0i32;

        'outer: loop {
            let attach_req = Request::Attach {
                session: active_session,
                new: initial_attach && opts.new,
                cols: cur_cols,
                rows: cur_rows,
                cell_w: cur_cw,
                cell_h: cur_ch,
                argv: if initial_attach {
                    opts.argv.clone()
                } else {
                    Vec::new()
                },
                cwd: if initial_attach {
                    opts.cwd.clone()
                } else {
                    None
                },
            };
            let (mut send, recv) = match self.request(&attach_req).await {
                Ok(pair) => {
                    initial_attach = false;
                    pair
                }
                Err(err) if is_fatal_attach_err(&err) || initial_attach => {
                    painter.cleanup(&mut tty_out);
                    return Err(err);
                }
                Err(_) => {
                    if !reconnect_wait(
                        self,
                        &mut ev_rx,
                        &mut cur_cols,
                        &mut cur_rows,
                        &mut cur_cw,
                        &mut cur_ch,
                        None,
                        |c, r, attempt| paint_reconnecting(&mut tty_out, r, c, attempt),
                    )
                    .await?
                    {
                        break 'outer;
                    }
                    continue 'outer;
                }
            };

            if !painter.caps.colours.is_empty() {
                let _ = send_msg(
                    &mut send,
                    &ClientEvent::Colours(painter.caps.colours.clone()),
                    MAX_CTRL,
                )
                .await;
            }
            if !pending_leftover.is_empty() {
                let bytes = std::mem::take(&mut pending_leftover);
                let _ = send_msg(&mut send, &ClientEvent::Input(bytes), MAX_CHUNK).await;
            }

            current_frame = None;
            painter.reset_for_full_repaint();
            let mut server_rx = spawn_msg_reader::<ServerEvent>(recv, MAX_FRAME);

            loop {
                tokio::select! {
                    msg = server_rx.recv() => {
                        match msg {
                            Some(Ok(ServerEvent::Picture(blob))) => {
                                painter.store_picture(blob);
                            }
                            Some(Ok(ServerEvent::Full(mut frame))) => {
                                frame.clamp_bounds();
                                active_session = Some(frame.session_id);
                                let done = frame.state != "running";
                                let done_exit = frame.exit.unwrap_or(0);
                                painter.paint(
                                    &mut tty_out,
                                    &frame,
                                    None,
                                    (usize::from(cur_cw), usize::from(cur_ch)),
                                );
                                current_frame = Some(frame);
                                if done {
                                    exit_code = done_exit;
                                    break 'outer;
                                }
                            }
                            Some(Ok(ServerEvent::Delta(delta))) => {
                                if let Some(frame) = current_frame.as_mut() {
                                    let changed = frame.apply_delta(delta);
                                    active_session = Some(frame.session_id);
                                    let done = frame.state != "running";
                                    let done_exit = frame.exit.unwrap_or(0);
                                    painter.paint(
                                        &mut tty_out,
                                        frame,
                                        Some(&changed),
                                        (usize::from(cur_cw), usize::from(cur_ch)),
                                    );
                                    if done {
                                        exit_code = done_exit;
                                        break 'outer;
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
                                break 'outer;
                            }
                            Some(ClientEvent::Resize { cols, rows, cell_w, cell_h }) => {
                                (cur_cols, cur_rows, cur_cw, cur_ch) = (cols, rows, cell_w, cell_h);
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
                            Some(other) => {
                                if send_msg(&mut send, &other, MAX_CHUNK).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if !reconnect_wait(
                self,
                &mut ev_rx,
                &mut cur_cols,
                &mut cur_rows,
                &mut cur_cw,
                &mut cur_ch,
                None,
                |c, r, attempt| paint_reconnecting(&mut tty_out, r, c, attempt),
            )
            .await?
            {
                break 'outer;
            }
        }
        let _ = current_frame;
        painter.cleanup(&mut tty_out);
        Ok(exit_code)
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
        fs::create_dir_all(local_dir.join("main"))
            .map_err(|e| KohError::failed(format!("mkdir {}: {e}", local_dir.display())))?;
        let in_fifo = fuxix::fifo(local_dir.join("in"))
            .map_err(|e| KohError::failed(format!("mkfifo in: {e}")))?;
        let ctl_fifo = fuxix::fifo(local_dir.join("ctl"))
            .map_err(|e| KohError::failed(format!("mkfifo ctl: {e}")))?;

        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<ClientEvent>(64);
        let pane_path = local_dir.to_path_buf();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut ctl_buf = String::new();
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
                    && let Some(slice) = buf.get(..n)
                {
                    ctl_buf.push_str(&String::from_utf8_lossy(slice));
                    while let Some(nl) = ctl_buf.find('\n') {
                        let line = ctl_buf.get(..nl).unwrap_or_default().trim().to_string();
                        ctl_buf.drain(..=nl);
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
                    }
                }
            }
        });

        let (mut cur_cols, mut cur_rows, mut cur_cw, mut cur_ch) = (cols, rows, 10u16, 20u16);
        let mut active_session = session;
        let mut initial_attach = true;
        let mut generation = 0u64;
        let mut written_pics: BTreeMap<u32, (PictureKind, usize)> = BTreeMap::new();
        let mut buffered_input = Vec::new();
        let mut current_frame: Option<ScreenFrame> = None;

        'mount: loop {
            let attach_req = Request::Attach {
                session: active_session,
                new: false,
                cols: cur_cols,
                rows: cur_rows,
                cell_w: cur_cw,
                cell_h: cur_ch,
                argv: Vec::new(),
                cwd: None,
            };
            let (mut send, recv) = match self.request(&attach_req).await {
                Ok(pair) => {
                    initial_attach = false;
                    pair
                }
                Err(err) if is_fatal_attach_err(&err) || initial_attach => {
                    let _ = fs::remove_file(local_dir.join("in"));
                    let _ = fs::remove_file(local_dir.join("ctl"));
                    return Err(err);
                }
                Err(_) => {
                    write_mirrored_state(local_dir, "reconnecting", &mut generation);
                    if !reconnect_wait(
                        self,
                        &mut ev_rx,
                        &mut cur_cols,
                        &mut cur_rows,
                        &mut cur_cw,
                        &mut cur_ch,
                        Some(&mut buffered_input),
                        |_, _, _| {},
                    )
                    .await?
                    {
                        break 'mount;
                    }
                    continue 'mount;
                }
            };

            // Forward local fux session's `colours` file if present two folders up.
            if let Some(session_root) = local_dir.parent().and_then(Path::parent)
                && let Ok(colours) = fs::read_to_string(session_root.join("colours"))
                && !colours.is_empty()
            {
                let _ = send_msg(&mut send, &ClientEvent::Colours(colours), MAX_CTRL).await;
            }
            // Flush any FIFO input that arrived while reconnecting so writes to `in` are never lost.
            if !buffered_input.is_empty() {
                let bytes = std::mem::take(&mut buffered_input);
                if send_msg(&mut send, &ClientEvent::Input(bytes.clone()), MAX_CHUNK)
                    .await
                    .is_err()
                {
                    push_bounded(&mut buffered_input, &bytes, RECONNECT_INPUT_BUFFER_MAX);
                    continue 'mount;
                }
            }

            current_frame = None;
            let mut server_rx = spawn_msg_reader::<ServerEvent>(recv, MAX_FRAME);

            loop {
                tokio::select! {
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
                                write_mirrored_pane(local_dir, &frame, &mut generation, &mut written_pics);
                                current_frame = Some(frame);
                                if done {
                                    break 'mount;
                                }
                            }
                            Some(Ok(ServerEvent::Delta(delta))) => {
                                if let Some(frame) = current_frame.as_mut() {
                                    let _ = frame.apply_delta(delta);
                                    active_session = Some(frame.session_id);
                                    let done = frame.state != "running";
                                    write_mirrored_pane(local_dir, frame, &mut generation, &mut written_pics);
                                    if done {
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
                }
            }

            write_mirrored_state(local_dir, "reconnecting", &mut generation);
            if !reconnect_wait(
                self,
                &mut ev_rx,
                &mut cur_cols,
                &mut cur_rows,
                &mut cur_cw,
                &mut cur_ch,
                Some(&mut buffered_input),
                |_, _, _| {},
            )
            .await?
            {
                break 'mount;
            }
        }
        let _ = current_frame;
        let _ = fs::remove_file(local_dir.join("in"));
        let _ = fs::remove_file(local_dir.join("ctl"));
        Ok(())
    }
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

/// Waits with bounded backoff and redials the server while still handling local Detach/Resize
/// (including cancelling an in-flight redial immediately on Detach).
/// Returns `Ok(true)` once reconnected, `Ok(false)` if the user detached locally.
#[allow(clippy::too_many_arguments)]
async fn reconnect_wait(
    client: &mut Client,
    ev_rx: &mut tokio::sync::mpsc::Receiver<ClientEvent>,
    cols: &mut u16,
    rows: &mut u16,
    cell_w: &mut u16,
    cell_h: &mut u16,
    mut pending_input: Option<&mut Vec<u8>>,
    mut on_attempt: impl FnMut(u16, u16, u32),
) -> Result<bool> {
    let mut attempt = 0u32;
    loop {
        on_attempt(*cols, *rows, attempt);
        let delay = reconnect_delay(attempt);
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
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
                            if let Some(buf) = pending_input.as_deref_mut() {
                                push_bounded(buf, &bytes, RECONNECT_INPUT_BUFFER_MAX);
                            }
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
                            if let Some(buf) = pending_input.as_deref_mut() {
                                push_bounded(buf, &bytes, RECONNECT_INPUT_BUFFER_MAX);
                            }
                        }
                        Some(_) => {}
                    }
                }
            }
        }
        attempt = attempt.saturating_add(1);
    }
}

fn winsize_cells(w: fuxix::Winsize) -> (u16, u16, u16, u16) {
    let cols = w.cols.max(1);
    let rows = w.rows.max(1);
    let cw = if w.xpixel > 0 {
        (w.xpixel / cols).max(1)
    } else {
        10
    };
    let ch = if w.ypixel > 0 {
        (w.ypixel / rows).max(1)
    } else {
        20
    };
    (cols, rows, cw, ch)
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct TerminalCaps {
    colours: String,
    kitty: bool,
    sixel: bool,
    leftover: Vec<u8>,
}

/// Probes the outer terminal once for host colours (OSC 4/10/11/12), Kitty graphics, and sixel (DA1).
fn probe_terminal(tty_in: &File, tty_out: &mut File) -> TerminalCaps {
    let mut query = String::from("\x1b]10;?\x1b\\\x1b]11;?\x1b\\\x1b]12;?\x1b\\");
    for n in 0..=255u16 {
        let _ = write!(query, "\x1b]4;{n};?\x1b\\");
    }
    query.push_str("\x1b_Gi=31,s=1,v=1,a=q,t=d,f=24;AAAA\x1b\\\x1b[c");
    let _ = tty_out.write_all(query.as_bytes());
    let _ = tty_out.flush();

    let deadline = Instant::now() + Duration::from_millis(150);
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline && raw.len() < (64 << 10) {
        let rem = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, 150) as i32;
        let ready = fuxix::wait([(Some(tty_in.as_fd()), fuxix::POLLIN)], rem);
        if !matches!(ready, Ok([ev]) if ev != 0) {
            continue;
        }
        match (&*tty_in).read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if let Some(slice) = buf.get(..n) {
                    raw.extend_from_slice(slice);
                }
                if has_da1_reply(&raw) {
                    break;
                }
            }
        }
    }
    parse_terminal_probe(&raw)
}

fn has_da1_reply(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes.get(i..i + 3) == Some(b"\x1b[?") {
            let mut j = i + 3;
            while let Some(&b) = bytes.get(j) {
                if b == b'c' {
                    return true;
                }
                if !(b.is_ascii_digit() || b == b';') {
                    break;
                }
                j += 1;
            }
        }
        i += 1;
    }
    false
}

/// Pure parser for terminal startup query responses (OSC 4/10/11/12, Kitty graphics APC, DA1 CSI).
/// Preserves any unrecognized bytes in `leftover` so early user keystrokes are never dropped.
fn parse_terminal_probe(bytes: &[u8]) -> TerminalCaps {
    let mut caps = TerminalCaps::default();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes.get(i) != Some(&0x1b) {
            if let Some(&b) = bytes.get(i) {
                caps.leftover.push(b);
            }
            i += 1;
            continue;
        }
        match bytes.get(i + 1) {
            Some(b']') => {
                // OSC ... (BEL or ST)
                if let Some((body_end, next_i)) = find_str_end(bytes, i + 2, true)
                    && let Some(body) = bytes
                        .get(i + 2..body_end)
                        .and_then(|s| std::str::from_utf8(s).ok())
                    && let Some(line) = parse_osc_colour_reply(body)
                {
                    if caps.colours.len() < (16 << 10) {
                        caps.colours.push_str(&line);
                    }
                    i = next_i;
                    continue;
                }
            }
            Some(b'_') => {
                // APC ... ST (Kitty graphics probe reply)
                if let Some((body_end, next_i)) = find_str_end(bytes, i + 2, false) {
                    if bytes.get(i + 2..body_end) == Some(b"Gi=31;OK") {
                        caps.kitty = true;
                        i = next_i;
                        continue;
                    }
                    if bytes
                        .get(i + 2..body_end)
                        .is_some_and(|b| b.starts_with(b"Gi=31;"))
                    {
                        i = next_i;
                        continue;
                    }
                }
            }
            Some(b'[') if bytes.get(i + 2) == Some(&b'?') => {
                // CSI ? ... c (DA1)
                let mut j = i + 3;
                while let Some(&b) = bytes.get(j) {
                    if b == b'c' {
                        if let Some(params) = bytes
                            .get(i + 3..j)
                            .and_then(|s| std::str::from_utf8(s).ok())
                        {
                            caps.sixel |= params.split(';').any(|p| p == "4");
                        }
                        i = j + 1;
                        j = usize::MAX;
                        break;
                    }
                    if !(b.is_ascii_digit() || b == b';') {
                        break;
                    }
                    j += 1;
                }
                if j == usize::MAX {
                    continue;
                }
            }
            _ => {}
        }
        if let Some(&b) = bytes.get(i) {
            caps.leftover.push(b);
        }
        i += 1;
    }
    caps
}

fn find_str_end(bytes: &[u8], start: usize, allow_bel: bool) -> Option<(usize, usize)> {
    let mut j = start;
    while j < bytes.len() {
        let b = bytes.get(j).copied()?;
        if allow_bel && b == 0x07 {
            return Some((j, j + 1));
        }
        if b == 0x1b && bytes.get(j + 1) == Some(&b'\\') {
            return Some((j, j + 2));
        }
        j += 1;
    }
    None
}

fn parse_osc_colour_reply(body: &str) -> Option<String> {
    let (which, value) = body.split_once(";rgb:")?;
    let name = match which.split_once(';') {
        None if which == "10" => "foreground".to_string(),
        None if which == "11" => "background".to_string(),
        None if which == "12" => "cursor".to_string(),
        Some(("4", idx)) if idx.parse::<u8>().is_ok_and(|n| n.to_string() == idx) => {
            idx.to_string()
        }
        _ => return None,
    };
    let [r, g, b] = fux_vt::colour(&format!("rgb:{value}"))?;
    Some(format!("{name} #{r:02x}{g:02x}{b:02x}\n"))
}

struct BellRunner {
    cmd: Option<String>,
    last_fired: Option<Instant>,
    count: u64,
    last_child: Option<Child>,
}

impl BellRunner {
    fn new(cmd: Option<String>) -> Self {
        Self {
            cmd,
            last_fired: None,
            count: 0,
            last_child: None,
        }
    }

    fn fire(&mut self, notice: &str, title: &str) {
        self.count = self.count.saturating_add(1);
        if let Some(child) = self.last_child.as_mut() {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => self.last_child = None,
                Ok(None) => return, // Skip overlapping hook while previous hook is still running.
            }
        }
        let Some(cmd) = self.cmd.as_deref() else {
            return;
        };
        if self
            .last_fired
            .is_some_and(|at| at.elapsed() < Duration::from_secs(1))
        {
            return;
        }
        self.last_fired = Some(Instant::now());
        if let Ok(child) = Command::new("/bin/sh")
            .args(["-c", cmd])
            .env("KOH_BELL_COUNT", self.count.to_string())
            .env("KOH_TITLE", title)
            .env("KOH_NOTICE", notice)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            self.last_child = Some(child);
        }
    }
}

impl Drop for BellRunner {
    fn drop(&mut self) {
        if let Some(child) = self.last_child.as_mut() {
            let _ = child.try_wait();
        }
    }
}

struct TermPainter {
    caps: TerminalCaps,
    last_modes: String,
    last_title: Option<String>,
    last_cursor_colour: Option<[u8; 3]>,
    last_pictures: String,
    last_links: String,
    last_lines: String,
    pictures: BTreeMap<u32, PictureBlob>,
    bell: BellRunner,
}

impl TermPainter {
    fn new(caps: TerminalCaps, on_bell: Option<String>) -> Self {
        Self {
            caps,
            last_modes: String::new(),
            last_title: None,
            last_cursor_colour: None,
            last_pictures: String::new(),
            last_links: String::new(),
            last_lines: String::new(),
            pictures: BTreeMap::new(),
            bell: BellRunner::new(on_bell),
        }
    }

    fn store_picture(&mut self, blob: PictureBlob) {
        if blob.bytes.len() > PICTURE_MAX {
            return;
        }
        while self.pictures.len() >= PICTURE_CACHE_MAX_COUNT
            || self
                .pictures
                .values()
                .map(|b| b.bytes.len())
                .sum::<usize>()
                .saturating_add(blob.bytes.len())
                > PICTURE_CACHE_MAX_BYTES
        {
            if self.pictures.pop_first().is_none() {
                break;
            }
        }
        self.pictures.insert(blob.id, blob);
    }

    fn reset_for_full_repaint(&mut self) {
        self.last_modes.clear();
        self.last_title = None;
        self.last_links.clear();
        self.last_lines.clear();
        self.pictures.clear();
    }

    fn cleanup(&mut self, out: &mut File) {
        if self.caps.kitty {
            let _ = out.write_all(b"\x1b_Ga=d,d=A,q=2\x1b\\");
            let _ = out.flush();
        }
    }

    /// Paints a pushed `fux` `ScreenFrame` (full or incremental delta) onto the local terminal.
    fn paint(
        &mut self,
        out: &mut File,
        frame: &ScreenFrame,
        changed_rows: Option<&[usize]>,
        cell: (usize, usize),
    ) {
        let mut buf = String::with_capacity(frame.styled.len().min(4096) + 256);
        buf.push_str("\x1b[?2026h\x1b[?25l");

        let full_repaint = changed_rows.is_none();
        let pictures_changed = frame.pictures != self.last_pictures || full_repaint;
        let links_changed = frame.links != self.last_links
            || (!frame.links.is_empty() && frame.lines != self.last_lines);
        let sixel_active = self.caps.sixel && !self.caps.kitty;
        let sixel_needs_redraw = sixel_active && (pictures_changed || !frame.pictures.is_empty());

        // Clear previous Kitty images on any full repaint (including post-reconnect) or picture change.
        if self.caps.kitty && (full_repaint || (pictures_changed && !self.last_pictures.is_empty()))
        {
            buf.push_str("\x1b_Ga=d,d=A,q=2\x1b\\");
        }

        let effective_changed = if full_repaint || links_changed || sixel_needs_redraw {
            None
        } else {
            changed_rows
        };

        if !frame.links.is_empty() {
            render_linked_rows(&mut buf, frame, effective_changed);
        } else {
            let styled_lines: Vec<&str> = frame.styled.lines().collect();
            match effective_changed {
                Some(indices) => {
                    for &row in indices {
                        if row >= frame.rows {
                            continue;
                        }
                        let raw = styled_lines.get(row).copied().unwrap_or_default();
                        let safe = sanitize_styled_line(raw);
                        let _ = write!(
                            buf,
                            "\x1b[{};1H\x1b[0m{safe}\x1b[0m\x1b[K",
                            row.saturating_add(1)
                        );
                    }
                }
                None => {
                    for row in 0..frame.rows {
                        let raw = styled_lines.get(row).copied().unwrap_or_default();
                        let safe = sanitize_styled_line(raw);
                        let _ = write!(
                            buf,
                            "\x1b[{};1H\x1b[0m{safe}\x1b[0m\x1b[K",
                            row.saturating_add(1)
                        );
                    }
                }
            }
        }
        self.last_links = frame.links.clone();
        self.last_lines = frame.lines.clone();

        if pictures_changed || sixel_needs_redraw {
            if self.caps.kitty || self.caps.sixel {
                for line in frame.pictures.lines() {
                    if let Some((vis_row, col, seq)) = render_picture_line(
                        &self.pictures,
                        self.caps.kitty,
                        frame.cols,
                        frame.rows,
                        cell,
                        line,
                    ) {
                        let _ = write!(
                            buf,
                            "\x1b[{};{}H{seq}",
                            vis_row.saturating_add(1),
                            col.saturating_add(1)
                        );
                    }
                }
            }
            self.last_pictures = frame.pictures.clone();
            let active = frame.referenced_picture_ids();
            self.pictures.retain(|id, _| active.contains(id));
        }

        if let Some(bytes) = &frame.clipboard {
            let _ = write!(buf, "\x1b]52;c;{}\x07", fux_vt::base64_encode(bytes));
        }
        if let Some(msg) = &frame.notice {
            if msg.is_empty() {
                buf.push('\x07');
            } else {
                let safe: String = msg.chars().filter(|c| !c.is_control()).take(200).collect();
                let _ = write!(buf, "\x1b]9;{safe}\x1b\\");
            }
            self.bell.fire(msg, &frame.title);
        }

        if frame.cursor_colour != self.last_cursor_colour {
            match frame.cursor_colour {
                Some([r, g, b]) => {
                    let _ = write!(buf, "\x1b]12;#{r:02x}{g:02x}{b:02x}\x1b\\");
                }
                None => buf.push_str("\x1b]112\x1b\\"),
            }
            self.last_cursor_colour = frame.cursor_colour;
        }
        if self.last_title.as_deref() != Some(frame.title.as_str()) {
            let safe: String = frame.title.chars().filter(|c| !c.is_control()).collect();
            let _ = write!(buf, "\x1b]2;{safe}\x07");
            self.last_title = Some(frame.title.clone());
        }
        if frame.modes != *self.last_modes {
            apply_modes(&mut buf, &frame.modes);
            self.last_modes = frame.modes.clone();
        }
        let _ = write!(buf, "\x1b[{} q", frame.cursor_shape);
        let _ = write!(
            buf,
            "\x1b[{};{}H",
            frame.cursor_row.saturating_add(1),
            frame.cursor_col.saturating_add(1)
        );
        if frame.cursor_shown {
            buf.push_str("\x1b[?25h");
        }
        buf.push_str("\x1b[?2026l");
        let _ = out.write_all(buf.as_bytes());
        let _ = out.flush();
    }
}

/// Allows only printable text and SGR (`\x1b[...m`) escapes in a peer-supplied styled row.
/// Any other control sequence (e.g. OSC 52, CSI cursor/title/mode injection) is replaced with `?`.
fn sanitize_styled_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(at) = rest.find(|c: char| c.is_control()) {
        let (before, after) = rest.split_at(at);
        out.push_str(before);
        let sgr_len = after.strip_prefix("\x1b[").and_then(|sgr| {
            let end = sgr.find(|c: char| !(c.is_ascii_digit() || c == ';' || c == ':'))?;
            sgr.get(end..)?.starts_with('m').then_some(2 + end + 1)
        });
        if let Some(len) = sgr_len
            && let Some(seq) = after.get(..len)
        {
            out.push_str(seq);
            rest = after.get(len..).unwrap_or_default();
        } else {
            out.push('?');
            let skip = after.chars().next().map_or(1, char::len_utf8);
            rest = after.get(skip..).unwrap_or_default();
        }
    }
    out.push_str(rest);
    out
}

fn paint_reconnecting(out: &mut File, rows: u16, cols: u16, attempt: u32) {
    let msg = format!(
        " koh: reconnecting (attempt {}) — Ctrl-] . to detach ",
        attempt.saturating_add(1)
    );
    let max_len = usize::from(cols).saturating_sub(1);
    let shown: String = msg.chars().take(max_len).collect();
    let row = rows.max(1);
    let mut buf = String::new();
    buf.push_str("\x1b[?2026h\x1b[?25l\x1b]2;koh: reconnecting...\x07");
    let _ = write!(
        buf,
        "\x1b[{row};1H\x1b[0;30;43m{shown}\x1b[0m\x1b[K\x1b[?2026l"
    );
    let _ = out.write_all(buf.as_bytes());
    let _ = out.flush();
}

/// Renders rows with OSC 8 hyperlinks reconstructed from frozen v1 `links` + `lines` + `styled`.
fn render_linked_rows(out: &mut String, frame: &ScreenFrame, changed_rows: Option<&[usize]>) {
    let mut screen = files::read_screen(&frame.styled, frame.cols);
    let mut lines_iter = frame.lines.lines();
    let top: usize = lines_iter
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let wrapped: BTreeSet<usize> = lines_iter
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|w| w.parse::<usize>().ok())
        .collect();

    // Map logical line number -> list of screen row indices belonging to it.
    let mut line_rows: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut logical = top;
    for row in 0..screen.rows {
        if row > 0 && !wrapped.contains(&row) {
            logical = logical.saturating_add(1);
        }
        line_rows.entry(logical).or_default().push(row);
    }

    let mut urls: Vec<String> = Vec::new();
    for entry in frame.links.lines() {
        let mut parts = entry.splitn(4, ' ');
        let (Some(line_s), Some(col_s), Some(len_s), Some(url)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let (Ok(line_no), Ok(col_start), Ok(span_len)) = (
            line_s.parse::<usize>(),
            col_s.parse::<usize>(),
            len_s.parse::<usize>(),
        ) else {
            continue;
        };
        let Some(rows_for_line) = line_rows.get(&line_no) else {
            continue;
        };
        let Ok(link_id) = u16::try_from(urls.len() + 1) else {
            break;
        };
        urls.push(url.to_string());
        let max_cells = rows_for_line.len().saturating_mul(screen.cols.max(1));
        let clamped_len = span_len.min(max_cells.saturating_sub(col_start));
        for offset in 0..clamped_len {
            let abs_col = col_start.saturating_add(offset);
            let sub_row = abs_col / screen.cols.max(1);
            let col = abs_col % screen.cols.max(1);
            if let Some(&r) = rows_for_line.get(sub_row) {
                files::set_link(&mut screen, r, col, link_id);
            }
        }
    }

    let row_indices: Vec<usize> = match changed_rows {
        Some(idx) => idx.iter().copied().filter(|&r| r < frame.rows).collect(),
        None => (0..frame.rows).collect(),
    };
    for row in row_indices {
        let _ = write!(out, "\x1b[{};1H\x1b[0m", row + 1);
        if let Some(cells) = screen.row(row) {
            emit_cells_with_links(out, cells, &urls);
        }
        out.push_str("\x1b[0m\x1b[K");
    }
}

fn emit_cells_with_links(out: &mut String, cells: &[Cell], urls: &[String]) {
    let mut style = Style::default();
    let mut open_link: u16 = 0;
    for cell in cells {
        if cell.ch == '\0' {
            continue;
        }
        if cell.link != open_link {
            if open_link != 0 {
                out.push_str("\x1b]8;;\x1b\\");
            }
            if cell.link != 0
                && let Some(url) = urls.get(usize::from(cell.link).saturating_sub(1))
            {
                let safe: String = url.chars().filter(|c| !c.is_control()).collect();
                let _ = write!(out, "\x1b]8;;{safe}\x1b\\");
                open_link = cell.link;
            } else {
                open_link = 0;
            }
        }
        if cell.style != style {
            style = cell.style;
            style.sgr(out);
        }
        out.extend(cell.chars());
    }
    if open_link != 0 {
        out.push_str("\x1b]8;;\x1b\\");
    }
}

/// Renders one frozen v1 `pictures` entry line for a Kitty-capable or sixel-capable outer terminal.
fn render_picture_line(
    cache: &BTreeMap<u32, PictureBlob>,
    kitty_out: bool,
    screen_cols: usize,
    screen_rows: usize,
    (cell_w, cell_h): (usize, usize),
    line: &str,
) -> Option<(usize, usize, String)> {
    if cell_w == 0 || cell_h == 0 {
        return None;
    }
    let mut w = line.split_whitespace();
    let file = w.next()?;
    let id = file
        .strip_prefix("pic-")?
        .split_once('.')?
        .0
        .parse::<u32>()
        .ok()?;
    let row_signed: isize = w.next()?.parse().ok()?;
    let col: usize = w.next()?.parse().ok()?;
    let total_cols: usize = w.next()?.parse().ok()?;
    let total_rows: usize = w.next()?.parse().ok()?;
    let laid_w: usize = w.next()?.parse().ok()?;
    let laid_h: usize = w.next()?.parse().ok()?;
    let (vis_row, off_rows) = if row_signed < 0 {
        (0usize, row_signed.unsigned_abs())
    } else {
        (row_signed as usize, 0usize)
    };
    if vis_row >= screen_rows || col >= screen_cols {
        return None;
    }
    let beside = screen_cols.saturating_sub(col);
    let below = screen_rows.saturating_sub(vis_row);
    let above_px = off_rows.saturating_mul(laid_h);
    let (avail_w, avail_h) = (beside.saturating_mul(cell_w), below.saturating_mul(cell_h));
    let blob = cache.get(&id)?;

    let seq = match (blob.kind, kitty_out) {
        (PictureKind::Sixel, false) => {
            let inside = blob
                .bytes
                .strip_prefix(b"\x1bP")
                .and_then(|r| r.strip_suffix(b"\x1b\\"))
                .filter(|b| fux_vt::Term::is_sixel(b))?;
            let (pw, ph, square) = sixel::size(inside);
            let (wide, high) = (pw.min(avail_w), ph.saturating_sub(above_px).min(avail_h));
            if wide == 0 || high == 0 {
                return None;
            }
            let body = if square && (above_px, wide, high) == (0, pw, ph) {
                std::str::from_utf8(inside).ok()?.to_string()
            } else {
                sixel::cut(inside, [0, above_px, wide, high], PICTURE_MAX).ok()?
            };
            format!("\x1bP{body}\x1b\\")
        }
        (PictureKind::Sixel, true) => {
            let inside = blob
                .bytes
                .strip_prefix(b"\x1bP")
                .and_then(|r| r.strip_suffix(b"\x1b\\"))
                .filter(|b| fux_vt::Term::is_sixel(b))?;
            let (pw, ph, _) = sixel::size(inside);
            let (wide, high) = (pw.min(avail_w), ph.saturating_sub(above_px).min(avail_h));
            if wide == 0 || high == 0 {
                return None;
            }
            let decoded = sixel::read(inside, [0, above_px, wide, high]).ok()?;
            let rgba = kitty::sixel_to_rgba(&decoded);
            kitty::encode_rgba(decoded.w, decoded.h, &rgba, None, PICTURE_MAX).ok()?
        }
        (PictureKind::Png, true) => {
            let (pw, ph) = png::dimensions(&blob.bytes)?;
            let (pw, ph) = (pw as usize, ph as usize);
            let native = laid_w > 0
                && laid_h > 0
                && total_cols == pw.div_ceil(laid_w)
                && total_rows == ph.div_ceil(laid_h);
            if native {
                let (wide, high) = (pw.min(avail_w), ph.saturating_sub(above_px).min(avail_h));
                if wide == 0 || high == 0 {
                    return None;
                }
                let crop = (above_px != 0 || wide != pw || high != ph)
                    .then_some([0, above_px, wide, high]);
                kitty::encode_png(&blob.bytes, crop, None, PICTURE_MAX).ok()?
            } else {
                let vis_cols = total_cols.min(beside);
                let vis_rows = total_rows.saturating_sub(off_rows).min(below);
                if vis_cols == 0 || vis_rows == 0 || total_cols == 0 || total_rows == 0 {
                    return None;
                }
                let crop = if off_rows == 0 && vis_cols == total_cols && vis_rows == total_rows {
                    None
                } else {
                    let sy = ph.saturating_mul(off_rows) / total_rows;
                    let sw = (pw.saturating_mul(vis_cols) / total_cols).max(1).min(pw);
                    let sh = (ph.saturating_mul(vis_rows) / total_rows)
                        .max(1)
                        .min(ph.saturating_sub(sy));
                    Some([0, sy, sw, sh])
                };
                kitty::encode_png(&blob.bytes, crop, Some((vis_cols, vis_rows)), PICTURE_MAX)
                    .ok()?
            }
        }
        (PictureKind::Png, false) => {
            let (pw, ph, rgba) = png::decode(&blob.bytes, sixel::PIXELS_MAX).ok()?;
            let (pw, ph) = (pw as usize, ph as usize);
            let (wide, high) = (pw.min(avail_w), ph.saturating_sub(above_px).min(avail_h));
            if wide == 0 || high == 0 {
                return None;
            }
            let body =
                kitty::rgba_to_sixel(pw, ph, &rgba, [0, above_px, wide, high], PICTURE_MAX).ok()?;
            format!("\x1bP{body}\x1b\\")
        }
    };
    (!seq.is_empty()).then_some((vis_row, col, seq))
}

fn apply_modes(out: &mut String, words: &str) {
    let has = |w: &str| words.split_whitespace().any(|m| m == w);
    let set = |out: &mut String, code: &str, on: bool| {
        out.push_str("\x1b[");
        out.push_str(code);
        out.push(if on { 'h' } else { 'l' });
    };
    set(out, "?1", has("appcursor"));
    out.push_str(if has("keypad") { "\x1b=" } else { "\x1b>" });
    set(out, "?2004", has("paste"));
    set(out, "?1004", has("focus"));
    set(out, "?1000", has("mouse1000"));
    set(out, "?1002", has("mouse1002"));
    set(out, "?1003", has("mouse1003"));
    set(out, "?1006", has("mousesgr"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_terminal_probe_extracts_colours_kitty_sixel_and_leftover() {
        let raw = concat!(
            "\x1b]10;rgb:eeee/dddd/cccc\x1b\\",
            "\x1b]11;rgb:1111/2222/3333\x07",
            "\x1b]4;1;rgb:cc/00/11\x1b\\",
            "hi",
            "\x1b_Gi=31;OK\x1b\\",
            "\x1b[?62;4;22c",
            "!"
        );
        let caps = parse_terminal_probe(raw.as_bytes());
        assert!(caps.kitty);
        assert!(caps.sixel);
        assert_eq!(caps.leftover, b"hi!");
        assert!(caps.colours.contains("foreground #eeddcc\n"));
        assert!(caps.colours.contains("background #112233\n"));
        assert!(caps.colours.contains("1 #cc0011\n"));
    }

    #[test]
    fn render_linked_rows_emits_osc8_spans_and_clamps_huge_lengths() {
        let frame = ScreenFrame {
            cols: 20,
            rows: 1,
            screen: "visit example now\n".into(),
            styled: "visit example now\n".into(),
            lines: "0\n\n".into(),
            links: "0 6 7 https://example.com\n0 0 999999999999 https://huge.test\n".into(),
            ..ScreenFrame::default()
        };
        let mut buf = String::new();
        render_linked_rows(&mut buf, &frame, None);
        assert!(buf.contains("https://huge.test"));
    }

    #[test]
    fn sanitize_styled_line_preserves_sgr_and_strips_control_injection() {
        let hostile = "\x1b[38;2;255;0;0mhi\x1b]52;c;ZWF2aWw=\x07\x1b[m";
        let clean = sanitize_styled_line(hostile);
        assert!(clean.starts_with("\x1b[38;2;255;0;0mhi?"));
        assert!(!clean.contains("\x1b]52"));
        assert!(clean.ends_with("\x1b[m"));
    }
}
