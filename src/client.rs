//! Client operations for koh: exec, headless jobs, delta cp/--sync,
//! OSC 133 session queries/wait, direct push interactive `connect`, and
//! local `fux` pane-folder mirroring (`mount`).

use std::fs::{self, File};
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::fd::AsFd as _;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointId, RelayUrl, SecretKey};
use tokio::io::AsyncReadExt as _;

use crate::keys::{Role, Route, load_or_create_key, resolve_server};
use crate::net::{connect_server, map_conn_err, open_authed_stream};
use crate::proto::{
    ClientEvent, ExecClientMsg, ExecServerMsg, JobInfo, LogMsg, MAX_CHUNK, MAX_CTRL, MAX_FRAME,
    Reply, Request, ScreenFrame, SessionInfo, SyncSummary, WaitResult, recv_msg, recv_msg_opt,
    send_msg,
};
use crate::sync::{receive_tree, send_tree};
use crate::{KohError, Result, atomic_write};

const LEAVING: &[u8] = b"\x1b[?2004l\x1b[?1004l\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1l\x1b>\x1b[0 q\x1b[m\x1b[?25h\x1b[?7h\x1b[?1049l";

#[derive(Clone, Debug)]
pub struct DialOptions {
    pub key_file: Option<PathBuf>,
    pub direct: Option<SocketAddr>,
    pub relay: Option<RelayUrl>,
    pub json: bool,
}

pub struct Client {
    secret: SecretKey,
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
            connect_server(secret.clone(), server_id, route, interactive).await?;
        Ok(Self {
            secret,
            endpoint,
            conn,
        })
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
        let (mut send, mut recv) = self
            .request(&Request::CpPush {
                dst: remote_dst,
                excludes: excludes.clone(),
                delete,
                preserve_mtime,
                dry_run,
            })
            .await?;
        send_tree(local_src, &excludes, &mut send, &mut recv).await
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
        let (mut send, mut recv) = self
            .request(&Request::CpPull {
                src: remote_src,
                excludes: excludes.clone(),
                delete,
                preserve_mtime,
                dry_run,
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

    /// Attaches an interactive local TTY to a remote `fux`-backed session.
    /// Detach locally with `Ctrl-]` then `.`.
    pub async fn connect_interactive(
        &self,
        session: Option<u32>,
        new: bool,
        argv: Vec<String>,
        cwd: Option<String>,
    ) -> Result<i32> {
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
        let (mut send, mut recv) = self
            .request(&Request::Attach {
                session,
                new,
                cols: winsz.cols,
                rows: winsz.rows,
                argv,
                cwd,
            })
            .await?;

        let _raw = fuxix::raw_mode(
            tty.try_clone()
                .map_err(|e| KohError::failed(format!("clone tty: {e}")))?,
            LEAVING,
        )
        .map_err(|e| KohError::failed(format!("raw mode: {e}")))?;
        let mut tty_out = tty
            .try_clone()
            .map_err(|e| KohError::failed(format!("clone tty: {e}")))?;
        let _ = tty_out.write_all(b"\x1b[?1049h\x1b[2J\x1b[?7l");
        let _ = tty_out.flush();

        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<ClientEvent>(64);
        let tty_in = tty;
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut last_size = winsz;
            let mut escape_armed = false;
            loop {
                if let Ok(cur) = fuxix::winsize(&tty_in)
                    && (cur.cols, cur.rows) != (last_size.cols, last_size.rows)
                {
                    last_size = cur;
                    if ev_tx
                        .blocking_send(ClientEvent::Resize {
                            cols: cur.cols,
                            rows: cur.rows,
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

        let mut last_modes = String::new();
        let mut last_title = String::new();
        let mut exit_code = 0i32;

        loop {
            tokio::select! {
                frame = recv_msg_opt::<ScreenFrame>(&mut recv, MAX_FRAME) => {
                    match frame? {
                        Some(frame) => {
                            paint_frame(&mut tty_out, &frame, &mut last_modes, &mut last_title);
                            if frame.state != "running" {
                                exit_code = frame.exit.unwrap_or(0);
                                break;
                            }
                        }
                        None => break,
                    }
                }
                ev = ev_rx.recv() => {
                    match ev {
                        Some(ClientEvent::Detach) | None => {
                            let _ = send_msg(&mut send, &ClientEvent::Detach, MAX_CTRL).await;
                            break;
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
        Ok(exit_code)
    }

    /// Mirrors a remote `fux`-backed session into a local v1 `fux` pane folder (`in` & `ctl` FIFOs +
    /// validated screen files) so unmodified local `fux view` renders it alongside local panes.
    pub async fn mount_local_pane(
        &self,
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

        let (mut send, mut recv) = self
            .request(&Request::Attach {
                session,
                new: false,
                cols,
                rows,
                argv: Vec::new(),
                cwd: None,
            })
            .await?;

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
                            let _ = ev_tx.blocking_send(ClientEvent::Resize { cols: c, rows: r });
                        } else if line == "kill" {
                            let _ = ev_tx.blocking_send(ClientEvent::Detach);
                            return;
                        }
                    }
                }
            }
        });

        let mut generation = 0u64;
        loop {
            tokio::select! {
                frame = recv_msg_opt::<ScreenFrame>(&mut recv, MAX_FRAME) => {
                    match frame? {
                        Some(frame) => {
                            write_mirrored_pane(local_dir, &frame, &mut generation);
                            if frame.state != "running" {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                ev = ev_rx.recv() => {
                    match ev {
                        Some(ClientEvent::Detach) | None => {
                            let _ = send_msg(&mut send, &ClientEvent::Detach, MAX_CTRL).await;
                            break;
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
        let _ = fs::remove_file(local_dir.join("in"));
        let _ = fs::remove_file(local_dir.join("ctl"));
        Ok(())
    }
}

/// Paints a pushed `fux` `ScreenFrame` cleanly onto the local terminal using synchronized output.
fn paint_frame(
    out: &mut File,
    frame: &ScreenFrame,
    last_modes: &mut String,
    last_title: &mut String,
) {
    let mut buf = String::with_capacity(frame.styled.len() + 256);
    buf.push_str("\x1b[?2026h\x1b[?25l");
    for (row, line) in frame.styled.lines().enumerate().take(frame.rows) {
        buf.push_str(&format!("\x1b[{};1H\x1b[0m{line}\x1b[0m\x1b[K", row + 1));
    }
    let drawn = frame.styled.lines().count();
    for row in drawn..frame.rows {
        buf.push_str(&format!("\x1b[{};1H\x1b[0m\x1b[K", row + 1));
    }
    if frame.title != *last_title {
        let safe: String = frame.title.chars().filter(|c| !c.is_control()).collect();
        buf.push_str(&format!("\x1b]2;{safe}\x07"));
        *last_title = frame.title.clone();
    }
    if frame.modes != *last_modes {
        apply_modes(&mut buf, &frame.modes);
        *last_modes = frame.modes.clone();
    }
    buf.push_str(&format!("\x1b[{} q", frame.cursor_shape));
    buf.push_str(&format!(
        "\x1b[{};{}H",
        frame.cursor_row + 1,
        frame.cursor_col + 1
    ));
    if frame.cursor_shown {
        buf.push_str("\x1b[?25h");
    }
    buf.push_str("\x1b[?2026l");
    let _ = out.write_all(buf.as_bytes());
    let _ = out.flush();
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

fn write_mirrored_pane(dir: &Path, frame: &ScreenFrame, generation: &mut u64) {
    *generation = generation.wrapping_add(1);
    let _ = atomic_write(
        &dir.join("generation"),
        format!("{}\n", *generation).as_bytes(),
    );

    let folder = if frame.alt { "alt" } else { "main" };
    let screen_dir = dir.join(folder);
    let _ = fs::create_dir_all(&screen_dir);
    let _ = atomic_write(&screen_dir.join("screen"), frame.screen.as_bytes());
    let _ = atomic_write(&screen_dir.join("screen.styled"), frame.styled.as_bytes());
    let _ = atomic_write(&screen_dir.join("lines"), frame.lines.as_bytes());
    let _ = atomic_write(&screen_dir.join("links"), frame.links.as_bytes());
    let _ = atomic_write(&screen_dir.join("pictures"), b"");

    let tmp_link = dir.join(".shown.new");
    let _ = fs::remove_file(&tmp_link);
    if symlink(folder, &tmp_link).is_ok() {
        let _ = fs::rename(&tmp_link, dir.join("shown"));
    }
    let shown_word = if frame.cursor_shown {
        "shown"
    } else {
        "hidden"
    };
    let _ = atomic_write(
        &dir.join("size"),
        format!("{} {}\n", frame.cols, frame.rows).as_bytes(),
    );
    let _ = atomic_write(
        &dir.join("cursor"),
        format!(
            "{} {} {shown_word} {}\n",
            frame.cursor_row, frame.cursor_col, frame.cursor_shape
        )
        .as_bytes(),
    );
    let _ = atomic_write(&dir.join("modes"), format!("{}\n", frame.modes).as_bytes());
    let _ = atomic_write(&dir.join("marks"), frame.marks.as_bytes());
    let _ = atomic_write(&dir.join("state"), format!("{}\n", frame.state).as_bytes());
    if !frame.title.is_empty() {
        let _ = atomic_write(&dir.join("title"), format!("{}\n", frame.title).as_bytes());
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
