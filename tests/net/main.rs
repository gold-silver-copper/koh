//! koh over a faulty network: real servers and clients on real iroh endpoints, connected only
//! through the fault-injecting link in [`link`].
//!
//! One test binary, so every test shares the harness.

mod baseline;
mod bell;
mod convergence;
mod harness;
mod hostile_peer;
mod link;
mod predict;
mod session;
