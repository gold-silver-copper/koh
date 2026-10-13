//! koh over a faulty network: real servers and clients on real iroh endpoints, connected only
//! through the fault-injecting link in [`link`].
//!
//! One test binary, so every test shares the harness.
#![forbid(clippy::disallowed_methods)]

mod bell;
mod convergence;
mod corpus;
mod harness;
mod hostile_peer;
mod keys;
mod link;
mod predict;
mod session;
mod slow_link;
