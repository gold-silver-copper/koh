//! In-process harnesses that exercise the full koh stack *without* iroh or a real terminal, by
//! wiring the client and server transports through the deterministic chaotic link in
//! [`crate::ssp::testkit`]. This is the integration + chaos coverage: it proves the screen and
//! input states converge end-to-end under loss, that the predictor confirms/suppresses against
//! real frames, and (via the harness's own guard) that superseded screens are never delivered
//! late. Driven by `tests/integration.rs` (automated) and the `chaos` example (manual).

use crate::input::{UserInput, WireEvent};
use crate::predict::{DisplayPreference, PredictionEngine};
use crate::ssp::testkit::{LinkParams, SimHarness};
use crate::terminal::{ServerTerminal, TerminalScreen};

/// The outcome of one driven client↔server session over the chaotic link.
pub struct SessionResult {
    pub converge_steps: usize,
    pub sim_ms: u64,
    pub client_text: String,
    pub client_echo_ack: u64,
    pub expected_frame: u64,
}

impl SessionResult {
    pub fn assert_ok(&self) -> anyhow::Result<()> {
        if !self.client_text.contains("hello koh") {
            anyhow::bail!(
                "client screen missing expected output; got:\n{}",
                self.client_text
            );
        }
        if self.client_echo_ack != self.expected_frame {
            anyhow::bail!(
                "echo_ack mismatch: client={} expected={}",
                self.client_echo_ack,
                self.expected_frame
            );
        }
        Ok(())
    }
}

/// Drive a full client↔server session over the lossy link to convergence.
///
/// Wires client (A: `Transport<UserInput, TerminalScreen>`) to server
/// (B: `Transport<TerminalScreen, UserInput>`), types a command, has a fake shell echo it, and
/// drives everything to convergence — including the server's echo-ack.
pub fn run_session(loss: f64, seed: u64) -> SessionResult {
    let params = LinkParams {
        loss,
        min_delay_ms: 10,
        max_delay_ms: 60,
        dup: 0.02,
    };
    let mut h = SimHarness::<UserInput, TerminalScreen>::new(params, seed, 1200);

    // The server's authoritative emulator with an initial prompt.
    let mut emu = ServerTerminal::new(24, 80, 0);
    emu.process(b"$ ");
    *h.b_mut() = emu.snapshot();

    // Initial sync: client receives the prompt.
    h.run_until(5_000, |h| {
        h.a.remote_state().screen().contents().contains('$')
    });

    // Client types a command (with the trailing CR a shell would see).
    let cmd = b"echo hello koh\r";
    h.a_mut().push_bytes(cmd);

    // Drive until the server has received the whole command.
    h.run_until(20_000, |h| h.b.remote_state().events().len() >= cmd.len());

    // The fake shell: drain the input, echo each byte, and on CR emit the command output.
    let frame = h.b.remote_num();
    let arrival = h.now();
    emu.register_input_frame(frame, arrival);
    for w in h.b.get_remote_diff() {
        if let WireEvent::Keys(bytes) = w {
            for b in bytes {
                if b == b'\r' {
                    emu.process(b"\r\nhello koh\r\n$ ");
                } else {
                    emu.process(&[b]);
                }
            }
        }
    }
    // Past the echo-ack debounce: the input is now reflected on screen.
    emu.set_echo_ack(arrival + 1_000);
    *h.b_mut() = emu.snapshot();

    let target = emu.snapshot();
    let converge_steps = h.run_until(40_000, |h| *h.a.remote_state() == target);

    SessionResult {
        converge_steps,
        sim_ms: h.now(),
        client_text: h.a.remote_state().screen().contents(),
        client_echo_ack: h.a.remote_state().echo_ack(),
        expected_frame: frame,
    }
}

/// Drive a client-side predictor against authoritative frames to confirm the epoch gate:
/// a keystroke stays hidden until the server confirms it echoes, then is confirmed-and-cleared.
pub fn run_predictor_reconciliation() -> anyhow::Result<()> {
    let mut pe = PredictionEngine::new(DisplayPreference::Always);
    pe.set_local_frame_sent(0);

    // SECURITY: the first keystroke is epoch-gated and must NOT be shown before confirmation.
    let blank = TerminalScreen::default();
    pe.new_user_byte(100, b'h', blank.screen());
    if !pe.overlay(blank.screen()).is_empty() {
        anyhow::bail!("predictor leaked a keystroke before the server confirmed it echoes");
    }

    // Server echoes 'h' and acks frame 1 -> prediction confirmed and cleared.
    let echoed = TerminalScreen::from_bytes(24, 80, b"h");
    pe.set_local_frame_late_acked(1);
    pe.cull(200, echoed.screen());
    if !pe.overlay(echoed.screen()).is_empty() {
        anyhow::bail!("confirmed prediction should be cleared");
    }
    Ok(())
}
