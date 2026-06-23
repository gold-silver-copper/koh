//! Manual in-process chaos / integration driver (formerly `xtask`).
//!
//! Run a full client↔server session over a deterministic lossy link and report convergence:
//!   `cargo run --example chaos -- chaos --loss 0.3`
//!   `cargo run --example chaos -- integration`
//! The same scenarios run automatically under `cargo test --test integration`.

use clap::{Parser, Subcommand};
use koh::sim::{run_predictor_reconciliation, run_session};

#[derive(Parser)]
#[command(name = "chaos", about = "koh in-process integration / chaos drivers")]
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
