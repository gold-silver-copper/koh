//! koh on a bad link: a real server, real holders and real mirrors, whose only path to each
//! other is the fault link of `net`, below QUIC, in this process.
//!
//! `faults` tests the link itself; `sessions` is what a user would notice of a session on it.
//! `measure` is no test and is run by hand (`-- --ignored --nocapture`): it prints what a key's
//! echo and a build cost on each link.

mod faults;
mod measure;
mod net;
mod rig;
mod sessions;
