//! Transport-independent embedding boundary. Applications own state, terminal I/O and workspace
//! lifetime. koh owns prepared identities, authenticated connections and bounded network tasks.
mod client;
mod server;
pub use client::Connection;
pub use server::{NetworkProfile, Server};
