//! Runtimes for async unit tests. `#[tokio::test]` is not used: its expansion `allow`s
//! `clippy::expect_used`, which this crate forbids, and a `forbid` rejects that `allow`.

use tokio::runtime::{Builder, Runtime};

pub fn current_thread() -> Runtime {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}
