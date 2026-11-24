//! koh on a bad link: a real server, real holders and real mirrors, whose only path to each
//! other is the fault link of `net`, below QUIC, in this process.
//!
//! `faults` tests the link itself; `sessions` is what a user would notice of a session on it.

mod faults;
mod net;
mod rig;
mod sessions;
