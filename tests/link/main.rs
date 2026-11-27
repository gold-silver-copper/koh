//! koh on a bad link: a real server, real holders and real `koh connect` PTY clients, whose only
//! path to each other is the fault link of `net`, below QUIC, in this process. `sessions` is
//! what a user would notice of a session on it.
// (A test reads files of its own making.)
#![allow(clippy::disallowed_methods)]

mod net;
mod rig;
mod sessions;
