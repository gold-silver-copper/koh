//! End-to-end over a real loopback iroh connection with a **non-terminal** host and state (KH-01,
//! KH-02, KC-01): a `SharedHost<EchoHost>` serving `GridState`, a client over `connect_with`-style
//! wiring (`run_client` + a `ClientTerminal<GridState>`), the exit code riding the shutdown frame,
//! and the ALPN routing / rejection cases.

// Integration test: a failed unwrap/expect/assert IS the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::items_after_statements,
    clippy::default_trait_access,
    clippy::unwrap_in_result,
    clippy::significant_drop_in_scrutinee,
    clippy::match_wild_err_arm,
    reason = "integration test code; panics are assertion failures"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use koh::client::{run_client, ClientTerminal, IrohConnector};
use koh::predict::{DisplayPreference, Overlay};
use koh::server::cli::Hosts;
use koh::server::session::{SessionHost, SharedHost};
use koh::server::{ClientId, PtyHosts};
use koh::ssp::testkit::GridState;
use koh::transport_iroh::{
    bind_endpoint_local, bind_endpoint_local_alpns, generate_secret_key, loopback_addr,
    TERMINAL_ALPN,
};
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;

/// The test ALPN for the grid state (KH-02).
const GRID_ALPN: &[u8] = b"test/grid/1";

/// A host that appends every input byte into cell 0 of a [`GridState`] and exits on demand.
struct EchoHost {
    state: GridState,
    alive: bool,
    /// Shared with the test so it can end the host from outside.
    exit_request: Arc<Mutex<Option<u32>>>,
    /// Shared with the test so it can wake the attached loops after requesting the exit (what a
    /// real host does from its own task).
    notify: Arc<Mutex<Option<Arc<Notify>>>>,
    resizes: Arc<Mutex<Vec<(ClientId, u16, u16)>>>,
}

impl EchoHost {
    fn new(
        exit_request: Arc<Mutex<Option<u32>>>,
        resizes: Arc<Mutex<Vec<(ClientId, u16, u16)>>>,
        notify: Arc<Mutex<Option<Arc<Notify>>>>,
    ) -> Self {
        Self {
            state: GridState::default(),
            alive: true,
            exit_request,
            notify,
            resizes,
        }
    }
}

impl SessionHost for EchoHost {
    type State = GridState;

    fn snapshot(&mut self) -> GridState {
        if let Some(code) = *self.exit_request.lock().unwrap() {
            self.alive = false;
            self.state.exit_code = Some(code);
        }
        self.state.clone()
    }

    fn stamp_echo_ack(state: &mut GridState, echo_ack: u64) {
        state.echo_ack = echo_ack;
    }

    fn input(&mut self, bytes: &[u8]) {
        self.state
            .cells
            .entry(0)
            .or_default()
            .extend_from_slice(bytes);
        if let Some(n) = self.notify.lock().unwrap().as_ref() {
            n.notify_one();
        }
    }

    fn resize(&mut self, client: ClientId, rows: u16, cols: u16) {
        self.state.rows = rows;
        self.state.cols = cols;
        self.resizes.lock().unwrap().push((client, rows, cols));
    }

    fn alive(&self) -> bool {
        self.alive && self.exit_request.lock().unwrap().is_none()
    }

    fn attach_notify(&mut self, changed: Arc<Notify>) {
        *self.notify.lock().unwrap() = Some(changed);
    }
}

/// Request the shared host's exit with `code` and wake the attached loops, as a real host's own
/// task would.
fn request_exit(
    exit_request: &Arc<Mutex<Option<u32>>>,
    notify: &Arc<Mutex<Option<Arc<Notify>>>>,
    code: u32,
) {
    *exit_request.lock().unwrap() = Some(code);
    if let Some(n) = notify.lock().unwrap().as_ref() {
        n.notify_one();
    }
}

/// A client terminal that keeps the latest replica of the grid state.
struct GridTerminal {
    latest: Arc<Mutex<GridState>>,
}

impl ClientTerminal<GridState> for GridTerminal {
    fn render(
        &mut self,
        state: &GridState,
        _overlay: &Overlay,
        _status: Option<&str>,
    ) -> std::io::Result<()> {
        *self.latest.lock().unwrap() = state.clone();
        Ok(())
    }

    fn size(&self) -> std::io::Result<(u16, u16)> {
        Ok((30, 100))
    }
}

/// Accept every connection on `ep` and hand it to `hosts` (admission + attach + drive), as the
/// binary's accept loop does after its allowlist check. Returns the accept task.
fn accept_loop(ep: iroh::Endpoint, hosts: Arc<Hosts>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let hosts = hosts.clone();
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                hosts.serve_connection(conn).await;
            });
        }
    })
}

/// Poll `latest` until `pred` holds or `tries` × 100 ms elapse.
async fn wait_for<T>(latest: &Arc<Mutex<T>>, tries: usize, pred: impl Fn(&T) -> bool) -> bool {
    for _ in 0..tries {
        if pred(&latest.lock().unwrap()) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generic_state_round_trips_over_loopback_and_carries_the_exit_code() {
    // KH-01 / KC-01: a shared non-terminal host; a typed marker shows up in the client's replica;
    // ending the host delivers its exit code through the shutdown frame to `run_client`.
    let exit_request = Arc::new(Mutex::new(None));
    let resizes = Arc::new(Mutex::new(Vec::new()));
    let notify = Arc::new(Mutex::new(None));
    let (er, rs, nf) = (exit_request.clone(), resizes.clone(), notify.clone());
    let provider = SharedHost::new(move || Ok(EchoHost::new(er.clone(), rs.clone(), nf.clone())));
    let hosts = Arc::new(Hosts::new().with(GRID_ALPN, provider));

    let server_ep = bind_endpoint_local_alpns(generate_secret_key(), hosts.alpns())
        .await
        .expect("bind server");
    let addr = loopback_addr(&server_ep);
    let accept = accept_loop(server_ep, hosts);

    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let connector = IrohConnector::with_alpn(client_ep, addr, GRID_ALPN);
    let channel = connector
        .connect()
        .await
        .expect("connect over the grid alpn");

    let latest = Arc::new(Mutex::new(GridState::default()));
    let term = GridTerminal {
        latest: latest.clone(),
    };
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(8);
    let (_resize_tx, resize_rx) = mpsc::channel::<()>(1);
    let shutdown = CancellationToken::new();
    let client = tokio::spawn(run_client(
        channel,
        connector,
        DisplayPreference::Always,
        (30, 100),
        input_rx,
        resize_rx,
        term,
        shutdown,
    ));

    input_tx
        .send(b"GRID_MARKER_77".to_vec())
        .await
        .expect("send");
    assert!(
        wait_for(&latest, 100, |g| g.contents().contains("GRID_MARKER_77")).await,
        "the typed marker must appear in the client's replica of the grid state"
    );
    // The client's initial resize reached the host with a ClientId (KH-01).
    assert!(
        resizes
            .lock()
            .unwrap()
            .iter()
            .any(|(_, r, c)| (*r, *c) == (30, 100)),
        "the client's geometry reaches the host's resize()"
    );

    request_exit(&exit_request, &notify, 7);
    let code = tokio::time::timeout(Duration::from_secs(10), client)
        .await
        .expect("client must return after the host exits")
        .expect("client task")
        .expect("run_client ok");
    assert_eq!(
        code,
        Some(7),
        "the host's exit code rides the shutdown frame to run_client"
    );
    accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dialing_an_alpn_the_server_does_not_serve_fails_at_the_handshake() {
    // KH-02: the server only binds the grid ALPN; a terminal-ALPN dial never gets a session.
    let provider = SharedHost::new(|| {
        Ok(EchoHost::new(
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(None)),
        ))
    });
    let hosts = Arc::new(Hosts::new().with(GRID_ALPN, provider));
    let server_ep = bind_endpoint_local_alpns(generate_secret_key(), hosts.alpns())
        .await
        .expect("bind server");
    let addr = loopback_addr(&server_ep);
    let accept = accept_loop(server_ep, hosts);

    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let connector = IrohConnector::with_alpn(client_ep, addr, TERMINAL_ALPN);
    let err = match tokio::time::timeout(Duration::from_secs(10), connector.connect()).await {
        Ok(Ok(_)) => panic!("a terminal-ALPN dial to a grid-only server must fail"),
        Ok(Err(e)) => e,
        Err(_) => panic!("the dial must fail promptly, not hang"),
    };
    let msg = format!("{err:#}");
    assert!(
        msg.contains("koh/iroh/1"),
        "the error names the ALPN that was dialed: {msg}"
    );
    accept.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_endpoint_routes_each_alpn_to_its_own_host() {
    // KH-02: an endpoint bound with both ALPNs, a PTY provider on the terminal ALPN and a grid
    // provider on the grid ALPN. A marker typed on each connection reads back from the matching
    // state type.
    let grid_provider = SharedHost::new(|| {
        Ok(EchoHost::new(
            Arc::new(Mutex::new(None)),
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(None)),
        ))
    });
    let pty_provider = PtyHosts::new(vec!["sh".to_owned()], 0, 4);
    let hosts = Arc::new(
        Hosts::new()
            .with(GRID_ALPN, grid_provider)
            .with(TERMINAL_ALPN, pty_provider),
    );
    let server_ep = bind_endpoint_local_alpns(generate_secret_key(), hosts.alpns())
        .await
        .expect("bind server");
    let addr = loopback_addr(&server_ep);
    let accept = accept_loop(server_ep, hosts);

    let clock = koh::transport_iroh::MonoClock::new();
    // Terminal connection on the SAME server endpoint (from a fresh client endpoint, so the two
    // connections are unambiguously distinct peers): a shell echoes a marker onto a TerminalScreen.
    let client_ep2 = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client 2");
    let term_connector = IrohConnector::with_alpn(client_ep2, addr.clone(), TERMINAL_ALPN);
    let chan = term_connector.connect().await.expect("terminal connect");
    let mut t = koh::ssp::Transport::<koh::input::UserInput, koh::terminal::TerminalScreen>::new(
        clock.now_ms(),
        chan.max_datagram_size(),
    );
    t.set_connected(true);
    t.observe_rtt(10.0);
    t.current_mut().push_bytes(b"echo ROUTE_PTY_OK\r");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut seen = false;
    while std::time::Instant::now() < deadline {
        for dg in t.tick(clock.now_ms()) {
            chan.send(&dg);
        }
        tokio::select! {
            r = chan.recv() => { if let Ok(b) = r { t.recv(clock.now_ms(), &b); } }
            () = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
        if t.remote_state()
            .screen()
            .contents()
            .contains("ROUTE_PTY_OK")
        {
            seen = true;
            break;
        }
    }
    assert!(
        seen,
        "the terminal ALPN connection is served by the PTY host"
    );
    chan.close(0, b"done");

    // Grid connection.
    let client_ep = bind_endpoint_local(generate_secret_key(), false)
        .await
        .expect("bind client");
    let grid_connector = IrohConnector::with_alpn(client_ep, addr, GRID_ALPN);
    let chan = grid_connector.connect().await.expect("grid connect");
    let mut t = koh::ssp::Transport::<koh::input::UserInput, GridState>::new(
        clock.now_ms(),
        chan.max_datagram_size(),
    );
    t.set_connected(true);
    t.observe_rtt(10.0);
    t.current_mut().push_bytes(b"ROUTE_GRID");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut seen = false;
    while std::time::Instant::now() < deadline {
        for dg in t.tick(clock.now_ms()) {
            chan.send(&dg);
        }
        tokio::select! {
            r = chan.recv() => { if let Ok(b) = r { t.recv(clock.now_ms(), &b); } }
            () = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
        if t.remote_state().contents().contains("ROUTE_GRID") {
            seen = true;
            break;
        }
    }
    assert!(seen, "the grid ALPN connection is served by the grid host");
    chan.close(0, b"done");

    chan.close(0, b"done");
    accept.abort();
}
