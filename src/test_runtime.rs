//! What unit tests share with the integration tests, through `koh_testkit`: their runtime, and
//! scratch directories under `target/`, never the system temp dir.

use tokio::runtime::Runtime;

pub fn current_thread() -> Runtime {
    koh_testkit::current_thread().expect("tokio runtime")
}

/// A private directory of the test's own under `target/tmp`, removed when dropped.
pub fn scratch(name: &str) -> koh_testkit::Scratch {
    koh_testkit::Scratch::new(concat!(env!("CARGO_MANIFEST_DIR"), "/target/tmp"), name)
        .expect("a scratch directory")
}
