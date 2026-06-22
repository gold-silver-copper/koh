//! # xtask — rmosh dev drivers
//!
//! In-process harnesses that exercise the full rmosh stack *without* iroh or a real terminal,
//! by wiring the client and server transports through the deterministic chaotic link in
//! [`rmosh_ssp::testkit`]. This is the §11 integration + chaos coverage: it proves the screen
//! and input states converge end-to-end under loss, that the predictor confirms/suppresses
//! against real frames, and (via the harness's own guard) that superseded screens are never
//! delivered late.
//!
//! Run: `cargo run -p xtask -- chaos --loss 0.3` or `cargo run -p xtask -- integration`.
//! The same scenarios run under `cargo test -p xtask`.

use clap::{Parser, Subcommand};
use rmosh_input::{UserInput, WireEvent};
use rmosh_predict::{DisplayPreference, PredictionEngine};
use rmosh_ssp::testkit::{LinkParams, SimHarness};
use rmosh_terminal::{ServerTerminal, TerminalScreen};

#[derive(Parser)]
#[command(name = "xtask", about = "rmosh in-process integration / chaos drivers")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a full client↔server session over a chaotic link and report convergence.
    Chaos {
        /// Datagram loss probability [0,1].
        #[arg(long, default_value_t = 0.3)]
        loss: f64,
        /// RNG seed.
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
    /// Run the deterministic end-to-end integration scenario and assert it converges.
    Integration {
        #[arg(long, default_value_t = 0.2)]
        loss: f64,
        #[arg(long, default_value_t = 7)]
        seed: u64,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Chaos { loss, seed } => {
            let r = run_session(loss, seed);
            println!(
                "chaos: loss={loss} seed={seed} -> CONVERGED in {} steps ({} simulated ms); \
                 echo_ack={}",
                r.converge_steps, r.sim_ms, r.client_echo_ack
            );
            run_predictor_reconciliation()?;
            println!("predictor reconciliation: OK");
        }
        Cmd::Integration { loss, seed } => {
            let r = run_session(loss, seed);
            r.assert_ok()?;
            run_predictor_reconciliation()?;
            println!("integration: PASS (loss={loss}, seed={seed})");
        }
    }
    Ok(())
}

struct SessionResult {
    converge_steps: usize,
    sim_ms: u64,
    client_text: String,
    client_echo_ack: u64,
    expected_frame: u64,
}

impl SessionResult {
    fn assert_ok(&self) -> anyhow::Result<()> {
        if !self.client_text.contains("hello rmosh") {
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

/// Wire client (A: `Transport<UserInput, TerminalScreen>`) to server
/// (B: `Transport<TerminalScreen, UserInput>`) through a lossy link, type a command, have a
/// fake shell echo it, and drive everything to convergence — including the server's echo-ack.
fn run_session(loss: f64, seed: u64) -> SessionResult {
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
    let cmd = b"echo hello rmosh\r";
    h.a_mut().push_bytes(cmd);

    // Drive until the server has received the whole command.
    h.run_until(20_000, |h| h.b.remote_state().len() >= cmd.len());

    // The fake shell: drain the input, echo each byte, and on CR emit the command output.
    let frame = h.b.remote_num();
    let arrival = h.now();
    emu.register_input_frame(frame, arrival);
    for w in h.b.get_remote_diff() {
        if let WireEvent::Keys(bytes) = w {
            for b in bytes {
                if b == b'\r' {
                    emu.process(b"\r\nhello rmosh\r\n$ ");
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
fn run_predictor_reconciliation() -> anyhow::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integration_converges_clean_link() {
        run_session(0.0, 1).assert_ok().unwrap();
    }

    #[test]
    fn integration_converges_lossy_link() {
        for seed in 1..6 {
            run_session(0.3, seed)
                .assert_ok()
                .unwrap_or_else(|e| panic!("seed {seed}: {e}"));
        }
    }

    #[test]
    fn predictor_reconciles_against_real_screen() {
        run_predictor_reconciliation().unwrap();
    }
}
