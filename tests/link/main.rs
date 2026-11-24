//! koh on a bad link: a real server, real holders and real mirrors, whose only path to each
//! other is the fault link of `net`, below QUIC, in this process.
//!
//! `faults` tests the link itself; `sessions` is what a user would notice of a session on it.
//! Two more are no tests and are run by hand (`-- --ignored --nocapture`): `measure` prints
//! what a key's echo and a build cost on each link, and `frozen` stops a real `koh mount` for
//! forty seconds.
// (A test reads files of its own making.)
#![allow(clippy::disallowed_methods)]

mod faults;
mod frozen;
mod measure;
mod net;
mod rig;
mod sessions;
