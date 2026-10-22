//! Sessions with real programs behind them: the registry's lifecycle, and connections to it over
//! loopback iroh with a minimal koh/16 client.
#![forbid(clippy::disallowed_methods)]

use std::time::Duration;

use anyhow::Context as _;
use koh::proto::{encode_client, ClientMsg, Close, InputSeq, Shown, ShownDecoder, SHOWN_TAG};
use koh::pty::Home;
use koh::request::{Attached, Pick, Request, MAX_REPLY, MAX_REQUEST};
use koh::server::cli::{serve_endpoint, Hosting, ServeConfig};
use koh::server::session::{AttachKind, Event, Launch, SessionClient, Start};
use koh::server::{Registry, SessionSpec};
use koh::terminal::{clamp_dims, Activity, Size, TtyModes};
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key, loopback_addr, ALPN};
use tokio_util::sync::CancellationToken;

/// The window every client here has.
const WINDOW: Size = Size::new(24, 80);

/// What a client of a session holds of what it showed: its terminal, as a fux-vt parser fed
/// the output, and what came beside it.
struct Shownness {
    term: fux_vt::Parser,
    exit: Option<u32>,
    /// The input its program read all of as it exited, as the exit says.
    read: Option<InputSeq>,
    tty: Option<TtyModes>,
    /// The PTY's modes when each text first showed: `(text, modes)`.
    reports: Vec<Activity>,
    /// The marks, and how many reports had come when each did.
    marks: Vec<(Vec<u8>, usize)>,
    /// Each report's input, and the screen when it came.
    reported: Vec<(InputSeq, String)>,
    echo: InputSeq,
}

impl Shownness {
    fn new() -> anyhow::Result<Self> {
        let size = fux_vt::Size::new(WINDOW.rows, WINDOW.cols).context("a size")?;
        Ok(Self {
            term: fux_vt::Parser::new(size, 0)?,
            exit: None,
            read: None,
            tty: None,
            reports: Vec::new(),
            marks: Vec::new(),
            reported: Vec::new(),
            echo: InputSeq(0),
        })
    }

    fn take(&mut self, shown: &Shown) -> anyhow::Result<()> {
        match shown {
            Shown::Out(bytes) => self.term.process(bytes)?,
            Shown::Mark(mark) => self
                .marks
                .push((mark.as_bytes().to_vec(), self.reports.len())),
            Shown::Report { activity, input } => {
                self.reports.push(*activity);
                self.reported.push((*input, self.text()));
            }
            Shown::Tty(tty) => self.tty = Some(*tty),
            Shown::Echo(seq) => self.echo = self.echo.max(*seq),
            Shown::Exit { code, read } => (self.exit, self.read) = (Some(*code), *read),
            Shown::Bell(_) | Shown::Title(_) | Shown::Beat => {}
        }
        Ok(())
    }

    /// The screen's rows, their trailing blanks dropped, a line each.
    fn text(&self) -> String {
        let screen = self.term.screen();
        let rows: Vec<String> = screen
            .rows()
            .skip(screen.history_len())
            .map(|row| row.cells_text().trim_end().to_owned())
            .collect();
        rows.join("\n")
    }
}

/// A connection's handle to a session, in process, with what it was shown.
struct Watched {
    client: SessionClient,
    events: tokio::sync::broadcast::Receiver<Event>,
    shown: Shownness,
}

impl Watched {
    fn new((client, start): (SessionClient, Start)) -> anyhow::Result<Self> {
        let mut shown = Shownness::new()?;
        for s in &start.shown {
            shown.take(s)?;
        }
        Ok(Self {
            client,
            events: start.events,
            shown,
        })
    }

    /// Take the next event; `false` once the session ended.
    async fn next(&mut self) -> anyhow::Result<bool> {
        match self.events.recv().await {
            Ok(Event::Show(shown)) => self.shown.take(&shown)?,
            Ok(Event::Top(_)) => {}
            Ok(Event::Echo { attach, seq }) => {
                if attach == self.client.attachment() {
                    self.shown.echo = self.shown.echo.max(seq);
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                let start = self.client.redraw(None).await.context("a redraw")?;
                self.shown = Shownness::new()?;
                for s in &start.shown {
                    self.shown.take(s)?;
                }
                self.events = start.events;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(false),
        }
        Ok(true)
    }

    /// Take events until `done`, for at most 5 s.
    async fn until(&mut self, done: impl Fn(&Shownness) -> bool + Sync) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !done(&self.shown) {
                anyhow::ensure!(self.next().await?, "the session ended");
            }
            anyhow::Ok(())
        })
        .await
        .context("it never showed")?
    }

    /// Take events until the session ends.
    async fn drain(&mut self) -> anyhow::Result<()> {
        while self.next().await? {}
        Ok(())
    }
}

/// The accept loop on a loopback endpoint, allowing `client` and hosting `command`: its address,
/// the token that stops it, and its task.
async fn loopback_serve(
    client: iroh::EndpointId,
    command: &[&str],
) -> anyhow::Result<(
    iroh::EndpointAddr,
    CancellationToken,
    tokio::task::JoinHandle<anyhow::Result<()>>,
)> {
    let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
    let addr = loopback_addr(&server_ep);
    let config = ServeConfig {
        allow: vec![client],
        command: command.iter().map(|arg| (*arg).to_owned()).collect(),
        home: home(),
        ..ServeConfig::default()
    };
    let shutdown = CancellationToken::new();
    let task = koh_testkit::spawn(serve_endpoint(
        server_ep,
        Hosting::from_config(&config)?,
        shutdown.clone(),
    ));
    Ok((addr, shutdown, task))
}

/// The home every session in these tests gets.
fn home() -> Home {
    Home::isolated(koh_testkit::home!())
}

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    koh_testkit::multi_thread(2)
}

/// A registry attaching the peers `allows` allows.
fn registry(
    command: &[&str],
    max_sessions: usize,
    ttl: Duration,
    allows: impl Fn(&iroh::EndpointId) -> bool + Send + 'static,
) -> std::io::Result<Registry> {
    let spec = SessionSpec {
        command: command.iter().map(|arg| (*arg).to_owned()).collect(),
        scrollback_bytes: 0,
        max_sessions,
        ttl,
        home: home(),
        marks: None,
    };
    Registry::spawn(spec, allows)
}

/// Attach `peer` and say how.
async fn attach_kind(reg: &Registry, peer: iroh::EndpointId) -> Option<AttachKind> {
    reg.attach(peer, Pick::Latest, WINDOW, Launch::default())
        .await
        .ok()
        .map(|(_, _, kind)| kind)
}

/// Attach `peer`, and watch what it is shown.
async fn watch(reg: &Registry, peer: iroh::EndpointId) -> anyhow::Result<(Watched, AttachKind)> {
    let (client, start, kind) = reg
        .attach(peer, Pick::Latest, WINDOW, Launch::default())
        .await
        .map_err(|close| anyhow::anyhow!("refused: {close}"))?;
    Ok((Watched::new((client, start))?, kind))
}

fn peer() -> std::io::Result<iroh::EndpointId> {
    Ok(generate_secret_key()?.public())
}

#[test]
fn attach_creates_then_reattaches_the_same_peer() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let reg = registry(&["sleep", "30"], 4, Duration::from_secs(30), |_| true)?;
        let peer = peer()?;
        let (client, kind) = watch(&reg, peer).await.context("first attach")?;
        anyhow::ensure!(kind == AttachKind::Created, "first attach: {kind:?}");
        let (_c2, kind) = watch(&reg, peer).await.context("second attach")?;
        anyhow::ensure!(
            matches!(kind, AttachKind::Reattached),
            "same peer reattaches: {kind:?}"
        );
        drop(client);
        reg.shutdown().await;
        Ok(())
    })
}

#[test]
fn max_sessions_refuses_a_new_peer_but_allows_a_reattach() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let reg = registry(&["sleep", "30"], 1, Duration::from_secs(30), |_| true)?;
        let (a, b) = (peer()?, peer()?);
        let (a_client, _) = watch(&reg, a)
            .await
            .context("A creates the one allowed session")?;
        anyhow::ensure!(
            matches!(
                reg.attach(b, Pick::Latest, WINDOW, Launch::default()).await,
                Err(Close::AtCapacity)
            ),
            "a second distinct peer is refused at the cap, for now"
        );
        anyhow::ensure!(
            matches!(attach_kind(&reg, a).await, Some(AttachKind::Reattached)),
            "the existing peer still reattaches at the cap"
        );
        drop(a_client);
        reg.shutdown().await;
        Ok(())
    })
}

/// The last client to leave a session starts its TTL, and only the last: a session one client
/// still holds outlives it, and one every client left is reaped after it (the next attach creates
/// a new one), however many left at once (more than the session's control queue holds), and
/// whether or not its program had exited before any client saw it end.
#[test]
fn the_last_detach_starts_the_ttl_a_concurrent_one_does_not() -> anyhow::Result<()> {
    const TTL: Duration = Duration::from_millis(200);
    koh_testkit::current_thread()?.block_on(async {
        // (case, its program, clients attached, of them still attached, whether it is reaped)
        let cases = [
            ("one of two left", &["sleep", "30"][..], 2, 1, false),
            ("both of two left", &["sleep", "30"], 2, 0, true),
            ("a burst of 20 left", &["sleep", "30"], 20, 0, true),
            ("its program exited unseen", &["true"], 1, 0, true),
        ];
        let mut sessions = Vec::new();
        let mut held = Vec::new();
        for (case, command, attached, kept, reaped) in cases {
            let reg = registry(command, 4, TTL, |_| true)?;
            let peer = peer()?;
            let mut clients = Vec::new();
            for _ in 0..attached {
                clients.push(watch(&reg, peer).await.context(case)?.0);
            }
            if let Some(client) = clients.first_mut().filter(|_| command == ["true"]) {
                client.until(|s| s.exit.is_some()).await?;
            }
            held.extend(clients.drain(..kept));
            drop(clients);
            sessions.push((case, reg, peer, reaped));
        }
        // The TTL is what passes here: polling would attach, which restarts it.
        tokio::time::sleep(TTL * 5).await;
        for (case, reg, peer, reaped) in sessions {
            let kind = attach_kind(&reg, peer).await;
            reg.shutdown().await;
            anyhow::ensure!(
                (kind == Some(AttachKind::Created)) == reaped,
                "{case}: {kind:?}"
            );
        }
        drop(held);
        Ok(())
    })
}

/// A bare koh/16 client: writes messages, and reads what the server shows on its newest epoch.
struct RawClient {
    conn: iroh::endpoint::Connection,
    send: iroh::endpoint::SendStream,
    shown_rx: tokio::sync::mpsc::Receiver<Shown>,
    shown: Shownness,
    last_seq: InputSeq,
    _endpoint: iroh::Endpoint,
}

impl RawClient {
    /// Connect to `addr` as `secret`, and wait for the server to admit it.
    async fn connect(addr: iroh::EndpointAddr, secret: iroh::SecretKey) -> anyhow::Result<Self> {
        let endpoint = bind_endpoint_local(generate_secret_key()?, false).await?;
        let conn = endpoint.connect(addr, ALPN).await?;
        // Its control stream, opened with its key's proof and its request: its bytes go before the
        // input stream's, as the client's do.
        let mut send = conn.open_uni().await?;
        send.set_priority(1)?;
        let request = Request::Shell {
            pick: Pick::Latest,
            size: WINDOW,
            program: None,
            cwd: None,
        };
        let mut opening = koh::transport_iroh::prove(&conn, &secret)?;
        opening.extend(koh::request::encode(&request, MAX_REQUEST)?);
        send.write_all(&opening).await?;
        let mut first = tokio::time::timeout(Duration::from_secs(10), conn.accept_uni())
            .await
            .context("no admission came")??;
        let attached = first.read_to_end(MAX_REPLY.saturating_add(4)).await?;
        koh::request::decode_framed::<Attached>(&attached, MAX_REPLY)?;
        let (tx, shown_rx) = tokio::sync::mpsc::channel(256);
        let reader = conn.clone();
        koh_testkit::spawn(async move {
            while let Ok(mut recv) = reader.accept_uni().await {
                let mut header = [0u8; 5];
                if recv.read_exact(&mut header).await.is_err() || header[0] != SHOWN_TAG {
                    continue;
                }
                let tx = tx.clone();
                koh_testkit::spawn(async move {
                    let mut decoder = ShownDecoder::default();
                    while let Ok(Some(chunk)) = recv.read_chunk(64 * 1024).await {
                        decoder.push(&chunk);
                        while let Ok(Some(shown)) = decoder.next_shown() {
                            if tx.send(shown).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        Ok(Self {
            conn,
            send,
            shown_rx,
            shown: Shownness::new()?,
            last_seq: InputSeq(0),
            _endpoint: endpoint,
        })
    }

    async fn write(&mut self, msg: &ClientMsg) -> anyhow::Result<()> {
        self.send.write_all(&encode_client(msg)?).await?;
        Ok(())
    }

    async fn type_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.last_seq = self.last_seq.next();
        let mut decoder = fux_vt::keys::decode::Decoder::default();
        let mut inputs = Vec::new();
        decoder.bytes(bytes, &mut inputs);
        decoder.timeout(&mut inputs);
        let events = inputs
            .into_iter()
            .filter_map(|input| match input {
                fux_vt::keys::decode::Input::Key(key) => {
                    Some(koh::events::InputEvent::Key(key.into()))
                }
                fux_vt::keys::decode::Input::Paste(_)
                | fux_vt::keys::decode::Input::PasteTooLong
                | fux_vt::keys::decode::Input::FocusIn
                | fux_vt::keys::decode::Input::FocusOut
                | fux_vt::keys::decode::Input::Mouse(_)
                | fux_vt::keys::decode::Input::Reply(_) => None,
            })
            .collect();
        let msg = ClientMsg::Keys {
            seq: self.last_seq,
            events,
        };
        self.write(&msg).await
    }

    /// Take what is shown for `ms`.
    async fn pump(&mut self, ms: u64) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(ms))
            .context("deadline within range")?;
        while let Ok(Some(shown)) = tokio::time::timeout_at(deadline, self.shown_rx.recv()).await {
            self.shown.take(&shown)?;
        }
        Ok(())
    }

    /// Pump until `done` holds of what was shown, for at most 5 s.
    async fn until(&mut self, done: impl Fn(&Shownness) -> bool + Sync) -> anyhow::Result<()> {
        for _ in 0..100 {
            if done(&self.shown) {
                return Ok(());
            }
            self.pump(50).await?;
        }
        anyhow::bail!("no such screen came: {:?}", self.shown.text())
    }
}

#[test]
fn a_session_takes_keys_and_clamped_resizes_then_ends_with_the_server() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let secret = generate_secret_key()?;
        // The program sees the clamped size too, on its terminal.
        let program = ["sh", "-c", "read l; stty size; cat"];
        let (addr, shutdown, serve) = loopback_serve(secret.public(), &program).await?;
        let mut client = RawClient::connect(addr, secret).await?;
        client
            .write(&ClientMsg::Resize {
                n: 1,
                size: Size::new(65000, 1),
            })
            .await?;
        client.type_bytes(b"xy\r").await?;
        let clamped = clamp_dims(Size::new(65000, 1));
        let size = format!("{} {}", clamped.rows, clamped.cols);
        // The client's own terminal is 80 columns wide: the program's lines wrap in it.
        client
            .until(|s| {
                let shown: String = s.text().split_whitespace().collect();
                shown.contains("xy")
                    && shown.contains(&size.replace(' ', ""))
                    && s.echo >= InputSeq(1)
            })
            .await?;
        anyhow::ensure!(
            client.shown.echo == InputSeq(1),
            "the input is acknowledged as echoed: {:?}",
            client.shown.echo
        );
        client.conn.close(0u32.into(), b"done");
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), serve)
            .await
            .context("the server ends its session and returns")???;
        Ok(())
    })
}

/// A report says which input it came after, and never goes before the output the program wrote
/// before it: one saying `reading` after a key has what the program wrote for it on the screen,
/// though that came too late after the key to go out with its echo. Only where the system says a
/// program reads (macOS says only busy or idle).
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn a_report_follows_the_input_and_output_before_it() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let secret = generate_secret_key()?;
        let program = [
            "sh",
            "-c",
            "stty -echo; i=1; while read x; do sleep 0.03; printf \"got$i \"; i=$((i+1)); done",
        ];
        let (addr, shutdown, serve) = loopback_serve(secret.public(), &program).await?;
        let mut client = RawClient::connect(addr, secret).await?;
        client
            .until(|s| s.reports.last() == Some(&Activity::Reading))
            .await?;
        for n in 1..=10 {
            let before = client.shown.reports.len();
            client.type_bytes(b"k\r").await?;
            let seq = client.last_seq;
            let reading = |s: &Shownness| {
                (before..s.reports.len())
                    .find(|&i| s.reports[i] == Activity::Reading && s.reported[i].0 >= seq)
            };
            client.until(|s| reading(s).is_some()).await?;
            let at = reading(&client.shown).context("a report")?;
            let (input, screen) = &client.shown.reported[at];
            anyhow::ensure!(*input == seq, "{input:?} for {seq:?}");
            let last = screen.split_whitespace().last();
            anyhow::ensure!(last == Some(&*format!("got{n}")), "{n}: {screen:?}");
        }
        client.conn.close(0u32.into(), b"done");
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), serve)
            .await
            .context("the server ends its session and returns")???;
        Ok(())
    })
}

/// An exit says whether its program read every key written to it: one that read them all and
/// ended, the input up to the last; one that ended with keys left in its terminal, none. A
/// terminal driving the client knows so whether its last keys reached the program. Only where the
/// keys a program left in a terminal it closed can be counted (macOS empties the queue).
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn an_exit_says_whether_its_program_read_every_key() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        for (program, all) in [
            ("sleep 0.5; head -c 4 >/dev/null", true),
            ("sleep 0.5", false),
        ] {
            let secret = generate_secret_key()?;
            let (addr, shutdown, serve) =
                loopback_serve(secret.public(), &["sh", "-c", program]).await?;
            let mut client = RawClient::connect(addr, secret).await?;
            client.type_bytes(b"abc\r").await?;
            let seq = client.last_seq;
            client.until(|s| s.exit.is_some()).await?;
            let read = client.shown.read;
            anyhow::ensure!(read == all.then_some(seq), "{program}: {read:?}");
            client.conn.close(0u32.into(), b"done");
            shutdown.cancel();
            tokio::time::timeout(Duration::from_secs(5), serve)
                .await
                .context("the server ends its session and returns")???;
        }
        Ok(())
    })
}

/// The session reports what its program is doing: after a command's end, and after each input,
/// though nothing changed.
#[test]
fn a_report_comes_with_a_commands_end_and_after_every_input() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let secret = generate_secret_key()?;
        let program = [
            "sh",
            "-c",
            r"sleep 1; printf '\033]133;C\007ran\033]133;D;0\007'; exec cat",
        ];
        let (addr, shutdown, serve) = loopback_serve(secret.public(), &program).await?;
        let mut client = RawClient::connect(addr, secret).await?;
        client.until(|s| !s.reports.is_empty()).await?;
        // A program that is no marked shell: its marks are relayed, and a report follows the end.
        client
            .until(|s| {
                s.marks
                    .iter()
                    .any(|(mark, before)| mark == b"D;0" && s.reports.len() > *before)
            })
            .await?;
        for key in [&b"a"[..], b"b"] {
            let before = client.shown.reports.len();
            client.type_bytes(key).await?;
            // A report after the key; and, where the system tells it, one saying `cat` waits for
            // the next (it may be caught at work on this one first).
            client.until(|s| s.reports.len() > before).await?;
            if cfg!(any(target_os = "linux", target_os = "android")) {
                client
                    .until(|s| {
                        s.reports.len() > before && s.reports.last() == Some(&Activity::Reading)
                    })
                    .await?;
            }
        }
        client.conn.close(0u32.into(), b"done");
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), serve)
            .await
            .context("the server ends its session and returns")???;
        Ok(())
    })
}

#[test]
fn echo_ack_is_tracked_per_connection_and_only_the_newest_ones_input_reaches_the_program(
) -> anyhow::Result<()> {
    runtime()?.block_on(async {
        // Two connections on ONE session (a peer's reconnect racing its old connection). A types
        // many times, B once. Neither is ever acked for input it did not send, and only B's, the
        // newest attachment's, reaches the program: A's is an old connection's, sent late.
        let secret = generate_secret_key()?;
        let (addr, shutdown, server) = loopback_serve(secret.public(), &["cat"]).await?;
        // Both connections share one client identity, so they land on ONE session.
        let mut a = RawClient::connect(addr.clone(), secret.clone()).await?;
        a.pump(200).await?;
        let mut b = RawClient::connect(addr, secret).await?;
        for _ in 0..30 {
            a.type_bytes(b"a").await?;
            a.pump(20).await?;
            b.pump(20).await?;
            anyhow::ensure!(
                a.shown.echo <= a.last_seq,
                "A was acked for input it never sent"
            );
            anyhow::ensure!(b.shown.echo == InputSeq(0), "B was handed A's echo-ack");
        }
        b.type_bytes(b"b").await?;
        b.until(|s| s.text().contains('b') && s.echo == InputSeq(1))
            .await?;
        let shown = b.shown.text();
        anyhow::ensure!(
            shown.contains('b') && !shown.contains('a'),
            "only the newest attachment types: {shown:?}"
        );
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
        Ok(())
    })
}

/// A reconnect after the program exited (the link dropped before the end was delivered) finds its
/// end and status, not a new shell, and the session holds its slot. Once a client has that end
/// the session ends, and the next attach starts a new one, which stays registered while it lives.
#[test]
fn a_reconnect_after_exit_sees_the_exit_until_a_client_has_it() -> anyhow::Result<()> {
    // The first session's program leaves `marker` and exits 3 at once; its replacement's lives.
    // The path reaches `sh` as `$1`, never spliced into the script.
    let dir = koh_testkit::scratch!("reconnect-after-exit")?;
    let marker = dir.join("marker");
    let path = marker.to_str().context("a UTF-8 scratch dir")?;
    let script = r#"[ -e "$1" ] && exec sleep 30; : > "$1"; exit 3"#;
    koh_testkit::current_thread()?.block_on(async {
        let reg = registry(
            &["sh", "-c", script, "sh", path],
            1,
            Duration::from_secs(30),
            |_| true,
        )?;
        let a = peer()?;
        let (mut c1, kind) = watch(&reg, a).await.context("first attach")?;
        anyhow::ensure!(kind == AttachKind::Created, "first attach: {kind:?}");
        c1.until(|s| s.exit.is_some()).await?;
        drop(c1);
        let (mut c2, kind) = watch(&reg, a).await.context("reconnect")?;
        anyhow::ensure!(
            matches!(kind, AttachKind::Reattached),
            "reconnect: {kind:?}"
        );
        anyhow::ensure!(
            c2.shown.exit == Some(3),
            "the exit is seen: {:?}",
            c2.shown.exit
        );
        anyhow::ensure!(
            attach_kind(&reg, peer()?).await.is_none(),
            "the exited session holds its slot"
        );
        // The client has the end: the session ends.
        c2.client.ended().await;
        c2.drain().await?;
        let (c3, kind) = watch(&reg, a).await.context("after the end")?;
        anyhow::ensure!(kind == AttachKind::Created, "after the end: {kind:?}");
        // c3 is still attached to its live session, so this must reattach to it.
        let again = attach_kind(&reg, a).await;
        let other = attach_kind(&reg, peer()?).await;
        drop(c3);
        reg.shutdown().await;
        anyhow::ensure!(
            matches!(again, Some(AttachKind::Reattached)),
            "c3's session stays registered, got {again:?}"
        );
        anyhow::ensure!(other.is_none(), "and holds the one slot, got {other:?}");
        Ok(())
    })
}

/// A reconnect that lands as a session whose program exited is ending, however the session and
/// registry tasks interleave across worker threads, is answered: by that session, still showing
/// the exit, or by a new one. A client that left without the end always finds it.
#[test]
fn a_reconnect_racing_the_end_of_an_exited_session_is_answered() -> anyhow::Result<()> {
    koh_testkit::multi_thread(4)?.block_on(async {
        let reg = registry(&["true"], 4, Duration::from_secs(30), |_| true)?;
        let a = peer()?;
        let mut client = watch(&reg, a).await.context("first attach")?.0;
        // An end the reconnect overtook ends the session it reattached to, once the reconnect was
        // shown the exit: the next reconnect finds a new session.
        let mut ending = false;
        for round in 0..100 {
            client
                .until(|s| s.exit.is_some())
                .await
                .with_context(|| format!("round {round}: exits"))?;
            // Every other round the client has the end just as the reconnect is asked.
            let acknowledged = round % 2 == 0;
            let ended = async {
                if acknowledged {
                    client.client.ended().await;
                }
            };
            let (attached, ()) = tokio::join!(
                tokio::time::timeout(Duration::from_secs(5), watch(&reg, a)),
                ended
            );
            drop(client);
            let (next, kind) = attached
                .with_context(|| format!("round {round}: the reconnect is answered"))?
                .context("reconnect")?;
            let shown = next.shown.exit;
            anyhow::ensure!(
                match kind {
                    AttachKind::Created => acknowledged || ending,
                    AttachKind::Reattached => shown == Some(0),
                },
                "round {round}: acknowledged {acknowledged}, got {kind:?} showing exit {shown:?}"
            );
            ending = acknowledged && kind != AttachKind::Created;
            client = next;
        }
        drop(client);
        reg.shutdown().await;
        Ok(())
    })
}

/// A program that never reads its input holds up no resize: the client's input stream stalls
/// behind typing it has not taken, its control stream does not.
#[test]
fn a_resize_waits_for_no_typing_the_program_has_not_read() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let secret = generate_secret_key()?;
        let (addr, shutdown, serve) = loopback_serve(
            secret.public(),
            &[
                "sh",
                "-c",
                "stty raw -echo; while :; do stty size; sleep 0.1; done",
            ],
        )
        .await?;
        let mut client = RawClient::connect(addr, secret).await?;
        // Far more than the PTY's writer, the session and the connection take, on the input
        // stream, by a task of its own: its writes stall once the server stops reading it. That is
        // the client's first stream, which the server already reads; the control stream, with
        // the resize, is its second.
        let control = client.conn.open_uni().await?;
        control.set_priority(1)?;
        let mut input = std::mem::replace(&mut client.send, control);
        let written = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let typing = koh_testkit::spawn({
            let written = std::sync::Arc::clone(&written);
            async move {
                for seq in 1..=1010 {
                    let event = if (3..=1000).contains(&seq) {
                        koh::events::InputEvent::Paste("k".to_owned())
                    } else {
                        koh::events::InputEvent::Paste("x".repeat(1000 * 1024))
                    };
                    let mut bytes = encode_client(&ClientMsg::Keys {
                        seq: InputSeq(seq),
                        events: vec![event],
                    })?;
                    bytes.extend(encode_client(&ClientMsg::Colours(
                        koh::events::WireColours::default(),
                    ))?);
                    for chunk in bytes.chunks(16 * 1024) {
                        if input.write_all(chunk).await.is_err() {
                            return anyhow::Ok(());
                        }
                        written.fetch_add(chunk.len(), std::sync::atomic::Ordering::Relaxed);
                    }
                }
                anyhow::Ok(())
            }
        });
        // The resize goes once the input stream has stalled, its writes held up with more to go:
        // the server no longer reads it.
        let mut seen = usize::MAX;
        loop {
            client.pump(200).await?;
            let now = written.load(std::sync::atomic::Ordering::Relaxed);
            anyhow::ensure!(!typing.is_finished(), "the input stream never stalled");
            if now == seen {
                break;
            }
            seen = now;
        }
        client
            .write(&ClientMsg::Resize {
                n: 1,
                size: Size::new(30, 100),
            })
            .await?;
        let shown = client.until(|s| s.text().contains("30 100")).await;
        typing.abort();
        client.conn.close(0u32.into(), b"done");
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), serve).await;
        shown.context("the resize waited behind typing the program never read")
    })
}

/// A peer removed from the allowlist has its session ended, its program hung up, and starts no
/// other: an attach the registry takes once the list no longer allows it is refused, even one on its
/// way as the peer was removed. Allowed again, it gets a new session.
#[test]
fn ending_a_peers_session_ends_it_at_once() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
    runtime()?.block_on(async {
        let allowed = std::sync::Arc::new(AtomicBool::new(true));
        let allows = std::sync::Arc::clone(&allowed);
        let reg = registry(&["sleep", "30"], 4, Duration::from_secs(30), move |_| {
            allows.load(Relaxed)
        })?;
        let a = peer()?;
        let (mut client, _) = watch(&reg, a).await.context("attach")?;
        allowed.store(false, Relaxed);
        let refused = reg
            .attach(a, Pick::Latest, WINDOW, Launch::default())
            .await
            .err();
        anyhow::ensure!(refused == Some(Close::NotAuthorized), "{refused:?}");
        reg.end(a).await;
        allowed.store(true, Relaxed);
        tokio::time::timeout(Duration::from_secs(5), client.drain())
            .await
            .context("the session ends")??;
        let kind = attach_kind(&reg, a).await;
        reg.shutdown().await;
        anyhow::ensure!(kind == Some(AttachKind::Created), "{kind:?}");
        Ok(())
    })
}

/// A program that prints its prompt and then turns echo off, as PAM does, in the same moment, is
/// never told with its prompt and echo on: the client would trust that echo and show what is typed
/// at the prompt.
#[test]
fn a_prompt_printed_before_echo_goes_off_is_never_told_with_echo_on() -> anyhow::Result<()> {
    // How long the server waits after output that is no echo before it sends it, with the PTY's
    // modes read again (`TTY_SETTLE`): a program that takes longer to turn echo off after its
    // prompt (a loaded machine can stall it) is past the promise.
    const SETTLE: Duration = Duration::from_millis(10);
    runtime()?.block_on(async {
        let program = [
            "perl",
            "-e",
            // A fifth of a millisecond between the prompt and echo going off, then how long that
            // took in all, which the test reads.
            "use POSIX; use Time::HiRes qw(time); $| = 1; my $t0 = time; print 'pw: '; \
             select(undef, undef, undef, 0.0002); my $t = POSIX::Termios->new; $t->getattr(0); \
             $t->setlflag($t->getlflag & ~POSIX::ECHO()); $t->setattr(0, POSIX::TCSANOW()); \
             printf(\"took %d us\\r\\n\", (time - $t0) * 1e6); sleep 30",
        ];
        for round in 0..20 {
            let reg = registry(&program, 1, Duration::from_secs(30), |_| true)?;
            let (mut client, _) = watch(&reg, peer()?).await.context("attach")?;
            let told = tokio::time::timeout(Duration::from_secs(5), async {
                let mut prompted = None;
                loop {
                    let shown = client.shown.text();
                    if shown.contains("pw:") {
                        prompted = prompted.or(Some(client.shown.tty));
                    }
                    let took = shown.split("took ").nth(1).and_then(|rest| {
                        rest.split(" us")
                            .next()
                            .and_then(|us| us.parse::<u64>().ok())
                    });
                    if let (Some(tty), Some(took)) = (prompted, took) {
                        return Some((tty, Duration::from_micros(took)));
                    }
                    if !client.next().await.ok()? {
                        return None;
                    }
                }
            })
            .await;
            drop(client);
            reg.shutdown().await;
            let (tty, took) = told.ok().flatten().context("the prompt never came")?;
            anyhow::ensure!(
                !tty.is_some_and(|tty| tty.echo) || took >= SETTLE,
                "round {round}: the prompt was told with echo on, {took:?} before it went off"
            );
        }
        Ok(())
    })
}

/// Shutdown ends every session, even one a connection is still attached to, and waits for it.
#[test]
fn shutdown_ends_a_session_that_still_has_a_client() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let reg = registry(&["sleep", "30"], 4, Duration::from_secs(30), |_| true)?;
        let (mut client, _) = watch(&reg, peer()?).await.context("attach")?;
        tokio::time::timeout(Duration::from_secs(5), reg.shutdown())
            .await
            .context("shutdown returns")?;
        let drained = tokio::time::timeout(Duration::from_secs(1), client.drain()).await;
        anyhow::ensure!(
            drained.is_ok(),
            "after shutdown the held client's session has ended"
        );
        Ok(())
    })
}

#[test]
fn a_session_ends_when_its_program_does_whatever_holds_its_terminal() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        // A job left in the background keeps the terminal open after the shell exited; a program
        // that closed its terminal runs on with none. Either way the session ends, with a status.
        // On macOS the terminal stays open while its session leader runs, whatever it closed, so
        // the session rightly stays: only Linux reports the terminal closed.
        let closed = cfg!(any(target_os = "linux", target_os = "android"))
            .then_some(("exec </dev/null >/dev/null 2>&1; sleep 3600", 129));
        for (script, code) in std::iter::once(("sleep 3600 & exit 7", 7)).chain(closed) {
            let reg = registry(&["sh", "-c", script], 4, Duration::from_secs(30), |_| true)?;
            let (mut client, _) = watch(&reg, peer()?).await.context("attach")?;
            client.until(|s| s.exit.is_some()).await.context(script)?;
            anyhow::ensure!(
                client.shown.exit == Some(code),
                "{script}: {:?}",
                client.shown.exit
            );
            drop(client);
            tokio::time::timeout(Duration::from_secs(5), reg.shutdown())
                .await
                .context("shutdown waits only for the hang-up")?;
        }
        Ok(())
    })
}

/// A connection whose session has already exited when it attaches is told so, and closed as
/// ended, rather than waiting for output that never comes.
#[test]
fn a_connection_attached_to_an_already_exited_session_is_told_it_ended() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        // `true` has exited by the time the connection's loop first looks.
        let secret = generate_secret_key()?;
        let (addr, shutdown, serve) = loopback_serve(secret.public(), &["true"]).await?;
        let mut raw = RawClient::connect(addr, secret).await?;
        raw.until(|s| s.exit == Some(0)).await?;
        let mut close = None;
        for _ in 0..30 {
            let _ = raw.pump(100).await;
            close = raw.conn.close_reason();
            if close.is_some() {
                break;
            }
        }
        shutdown.cancel();
        let _ = serve.await;
        let ended = koh::transport_iroh::closed_because(&raw.conn) == Some(Close::SessionEnded);
        anyhow::ensure!(
            ended,
            "the connection is closed as ended within 3s: {close:?}"
        );
        Ok(())
    })
}

/// A session's bash, started plainly, reads the user's `~/.bashrc` (their prompt and their
/// `PROMPT_COMMAND` run as always) and then marks its commands: a command's end and its status
/// reach the client, and a mark a program prints is not the shell's. With `--no-shell-marks` it
/// sends no marks, and a program's mark counts.
#[test]
fn a_sessions_bash_marks_its_commands_after_the_users_bashrc() -> anyhow::Result<()> {
    let home = koh_testkit::scratch!("marks-home")?;
    std::fs::write(
        home.join(".bashrc"),
        "PROMPT_COMMAND='__mine=$((__mine + 1))'\nPS1='rc$__mine> '\n",
    )?;
    runtime()?.block_on(async {
        for marks in [true, false] {
            let secret = generate_secret_key()?;
            let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
            let addr = loopback_addr(&server_ep);
            let config = ServeConfig {
                allow: vec![secret.public()],
                command: vec!["bash".to_owned()],
                home: Home::isolated(home.path()),
                shell_marks: marks,
                ..ServeConfig::default()
            };
            let shutdown = CancellationToken::new();
            let server = koh_testkit::spawn(serve_endpoint(
                server_ep,
                Hosting::from_config(&config)?,
                shutdown.clone(),
            ));
            let mut client = RawClient::connect(addr, secret).await?;
            client.until(|s| s.text().contains("rc1>")).await?;
            client
                .type_bytes(b"printf '\\033]133;D;7\\007'; echo hi; false\r")
                .await?;
            // The second prompt: the command has ended, and the user's hook ran twice.
            let came = client.until(|s| s.text().contains("\nhi\nrc2>")).await;
            let ends: Vec<Vec<u8>> = client
                .shown
                .marks
                .iter()
                .map(|(mark, _)| mark.clone())
                .filter(|mark| mark.starts_with(b"D"))
                .collect();
            shutdown.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
            came.with_context(|| format!("marks {marks}: the user's prompt and hook"))?;
            let has = |mark: &[u8]| ends.iter().any(|end| end == mark);
            if marks {
                anyhow::ensure!(
                    ends.last().map(Vec::as_slice) == Some(b"D;1") && !has(b"D;7"),
                    "the shell's mark ends the command, not the program's: {ends:?}"
                );
            } else {
                anyhow::ensure!(
                    ends == [b"D;7".to_vec()],
                    "no marks from the shell, the program's relayed: {ends:?}"
                );
            }
        }
        Ok(())
    })
}

/// A program that cannot start is not reported as the server being full, nor as a refusal for
/// good: the connection is closed saying the session could not start.
#[test]
fn a_program_that_cannot_start_is_refused_as_such() -> anyhow::Result<()> {
    runtime()?.block_on(async {
        let secret = generate_secret_key()?;
        let (addr, shutdown, server) =
            loopback_serve(secret.public(), &["/nonexistent/koh-test-program"]).await?;
        let endpoint = bind_endpoint_local(secret.clone(), false).await?;
        let dialed = tokio::time::timeout(
            Duration::from_secs(10),
            koh::client::IrohConnector::new(endpoint, addr, secret).connect(
                Pick::Latest,
                WINDOW,
                (None, None),
            ),
        )
        .await;
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
        let Err(error) = dialed.context("the server answers")? else {
            anyhow::bail!("admitted with no session");
        };
        anyhow::ensure!(
            error.downcast_ref::<Close>() == Some(&Close::CouldNotStart),
            "{error:#}"
        );
        Ok(())
    })
}

/// A UDP relay on loopback to `server`, from a socket of its own: each datagram waits `delay` (the
/// link's latency, which is what is tested), and the server's are dropped unless `answers`, so a
/// handshake through it stalls. Its address.
async fn relay(
    server: std::net::SocketAddr,
    delay: Duration,
    answers: bool,
) -> std::io::Result<std::net::SocketAddr> {
    use std::sync::{Arc, OnceLock};
    let bind = || tokio::net::UdpSocket::bind("127.0.0.1:0");
    let (near, far) = (Arc::new(bind().await?), Arc::new(bind().await?));
    let (at, client) = (near.local_addr()?, Arc::new(OnceLock::new()));
    for (from, out, outward) in [
        (Arc::clone(&near), Arc::clone(&far), true),
        (far, near, false),
    ] {
        let client = Arc::clone(&client);
        koh_testkit::spawn(async move {
            let mut buf = vec![0; 65_536];
            while let Ok((n, sender)) = from.recv_from(&mut buf).await {
                let to = if outward {
                    let _ = client.set(sender);
                    Some(server)
                } else {
                    client.get().copied().filter(|_| answers)
                };
                let (out, bytes) = (Arc::clone(&out), buf.get(..n).unwrap_or_default().to_vec());
                koh_testkit::spawn(async move {
                    tokio::time::sleep(delay).await;
                    if let Some(to) = to {
                        let _ = out.send_to(&bytes, to).await;
                    }
                });
            }
        });
    }
    Ok(at)
}

/// A flood of handshakes that never finish, from the allowed client's own address, takes neither
/// the one connection a server allows (`--max-connections 1`) nor the room for the client's own
/// handshake, which takes several round trips of 100 ms: the flood is asked to show it gets the
/// server's answers (a QUIC retry), and it never does, as a spoofed address could not.
#[test]
fn an_allowed_client_far_away_gets_in_through_a_flood_of_stalled_handshakes() -> anyhow::Result<()>
{
    koh_testkit::multi_thread(3)?.block_on(async {
        let good = generate_secret_key()?;
        let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
        let addr = loopback_addr(&server_ep);
        let config = ServeConfig {
            allow: vec![good.public()],
            command: vec!["sleep".to_owned(), "30".to_owned()],
            home: home(),
            max_connections: std::num::NonZeroU32::MIN,
            ..ServeConfig::default()
        };
        let shutdown = CancellationToken::new();
        let serving = koh_testkit::spawn(serve_endpoint(
            server_ep,
            Hosting::from_config(&config)?,
            shutdown.clone(),
        ));
        let server = *addr.ip_addrs().next().context("a loopback address")?;
        let at = move |relayed| koh::transport_iroh::direct_addr(addr.id, relayed);
        let stalled = bind_endpoint_local(generate_secret_key()?, false).await?;
        let black_hole = at(relay(server, Duration::ZERO, false).await?);
        // Some 200 dials a second, each stalled: the flood's rate, which is what is tested.
        let flood = || {
            let (stalled, black_hole) = (stalled.clone(), black_hole.clone());
            async move {
                for _ in 0..10_000 {
                    let (endpoint, to) = (stalled.clone(), black_hole.clone());
                    koh_testkit::spawn(async move { endpoint.connect(to, ALPN).await });
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }
        };
        // Under way before the client dials, and while it does.
        let _ = tokio::time::timeout(Duration::from_millis(500), flood()).await;
        let flood = koh_testkit::spawn(flood());
        let near = bind_endpoint_local(generate_secret_key()?, false).await?;
        let far = at(relay(server, Duration::from_millis(50), true).await?);
        let admitted = tokio::time::timeout(Duration::from_secs(20), async {
            for _ in 0..3 {
                // Its first stream, after its request, admits it.
                if let Ok(conn) = near.connect(far.clone(), ALPN).await {
                    let Ok(mut opening) = koh::transport_iroh::prove(&conn, &good) else {
                        return false;
                    };
                    let request = koh::request::encode(
                        &Request::Shell {
                            pick: Pick::Latest,
                            size: WINDOW,
                            program: None,
                            cwd: None,
                        },
                        MAX_REQUEST,
                    );
                    let Ok(request) = request else { return false };
                    opening.extend(request);
                    let Ok(mut send) = conn.open_uni().await else {
                        return false;
                    };
                    if send.write_all(&opening).await.is_err() {
                        return false;
                    }
                    let admitted = conn.accept_uni().await.is_ok();
                    drop(send);
                    return admitted;
                }
            }
            false
        });
        let admitted = admitted.await;
        flood.abort();
        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), serving).await;
        anyhow::ensure!(admitted == Ok(true), "the allowed client never got in");
        Ok(())
    })
}
