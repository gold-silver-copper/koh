//! Real-PTY / real-shell tests for [`koh::pty::Pty`].
//!
//! These live in their own integration-test binary (rather than inline `#[cfg(test)]`) on purpose:
//! each spawns a real child + PTY + two pump threads, and running them alongside the ~100 inline
//! unit/property tests in one massively-parallel binary starved the PTY reader thread under load
//! (a flaky timeout). A dedicated binary runs only these few in parallel, so they stay reliable.

// Integration test: a failed unwrap/expect/assert/timeout IS the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code; panics are assertion failures"
)]

use std::time::Duration;

use koh::pty::Pty;

#[tokio::test]
#[allow(
    clippy::match_wild_err_arm,
    reason = "a timeout in this test IS the test failing; panicking on the `Err(_)` deadline arm is the intended assertion"
)]
async fn spawns_and_streams_output() {
    // Run a one-shot command in the PTY and confirm we receive its output + reap it.
    let (mut pty, mut rx) = Pty::spawn(24, 80, Some("echo"), "xterm-256color").expect("spawn echo");
    // `echo` with no args prints just a newline; assert we get *something* and EOF.
    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(chunk)) => collected.extend_from_slice(&chunk),
            Ok(None) => break, // channel closed: child exited and reader finished
            Err(_) => panic!("timed out waiting for pty output"),
        }
    }
    // `echo` prints a newline (CR/LF in a pty).
    assert!(
        collected.contains(&b'\n'),
        "expected a newline from echo, got {collected:?}"
    );
    // Child should be reapable. After EOF there's a benign race between the reader closing the
    // channel and the exit status becoming collectible, so poll `try_wait` (the same pattern the
    // reap test below uses) rather than a single blocking call.
    let mut status = None;
    for _ in 0..200 {
        if let Ok(Some(s)) = pty.try_wait() {
            status = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let status = status.expect("the one-shot child must exit and be reaped");
    assert!(status.success() || status.exit_code() == 0);
}

#[tokio::test]
#[allow(
    clippy::match_same_arms,
    reason = "channel-close (`Ok(None)`) and deadline (`Err(_)`) are conceptually distinct outcomes kept as separate arms for readability, even though both set `found = false`"
)]
async fn interactive_shell_echoes_input() {
    // Spawn the default shell, send a command, and verify the echoed output comes back.
    let (mut pty, mut rx) = Pty::spawn(24, 80, None, "xterm-256color").expect("spawn shell");
    // Give the shell a moment to start, then type a command that prints a marker.
    tokio::time::sleep(Duration::from_millis(300)).await;
    pty.write_input(b"printf KOH_MARKER_OK\n").expect("write");

    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let found = loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(chunk)) => {
                collected.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&collected).contains("KOH_MARKER_OK") {
                    break true;
                }
            }
            Ok(None) => break false,
            Err(_) => break false,
        }
    };
    // Resize should not error while the shell is live.
    let _ = pty.resize(40, 120);
    let _ = pty.kill();
    assert!(
        found,
        "did not observe the marker in shell output: {}",
        String::from_utf8_lossy(&collected)
    );
}

#[tokio::test]
#[allow(
    clippy::match_same_arms,
    reason = "channel-close (`Ok(None)`) and deadline (`Err(_)`) are conceptually distinct outcomes kept as separate arms for readability, even though both set `in_order = false`"
)]
async fn write_input_takes_shared_ref_and_preserves_order() {
    // `pty` is bound WITHOUT `mut`, proving write_input takes `&self`. Two separate enqueues must
    // reach the child in FIFO order: the concatenated marker only appears if the second chunk did
    // not overtake the first.
    let (pty, mut rx) = Pty::spawn(24, 80, None, "xterm-256color").expect("spawn shell");
    tokio::time::sleep(Duration::from_millis(300)).await;
    pty.write_input(b"printf ORDER_").expect("first enqueue");
    pty.write_input(b"AB_CD\n").expect("second enqueue");

    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let in_order = loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(chunk)) => {
                collected.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&collected).contains("ORDER_AB_CD") {
                    break true;
                }
            }
            Ok(None) => break false,
            Err(_) => break false,
        }
    };
    drop(pty);
    assert!(
        in_order,
        "FIFO ordering of two enqueues should yield ORDER_AB_CD; got: {}",
        String::from_utf8_lossy(&collected)
    );
}

#[tokio::test]
#[allow(
    clippy::needless_continue,
    clippy::match_wild_err_arm,
    reason = "the explicit `continue` documents the drain-and-keep-reading intent; the `Err(_)` deadline arm panics because a timeout here IS the test failing"
)]
async fn dropping_pty_eofs_child_and_stops_writer() {
    // `cat` blocks reading stdin. Dropping the Pty drops the writer-thread sender; the writer thread
    // then finishes and drops the PTY write handle, on which portable-pty sends EOT — so the child
    // sees EOF, exits, the slave closes, and the output channel ends. If the writer thread were
    // stuck (or never dropped its handle), the channel would never close.
    let (pty, mut rx) = Pty::spawn(24, 80, Some("cat"), "xterm-256color").expect("spawn cat");
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(pty); // no kill(): EOF must come purely from the writer handle being dropped

    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(_)) => continue, // drain any echoed bytes
            Ok(None) => break,       // channel closed: child EOF'd + exited; writer thread ended
            Err(_) => panic!("dropping Pty did not EOF the child (writer stuck?)"),
        }
    }
}

#[tokio::test]
async fn shutdown_joins_both_io_threads_without_deadlock() {
    // Graceful teardown: shutdown() kills the child (so the reader's blocking read returns EOF) and
    // drops the writer sender (so the writer's recv returns), then joins BOTH pump threads. It must
    // return promptly — a hang would mean a thread never unblocked.
    let (pty, mut rx) = Pty::spawn(24, 80, Some("sh"), "xterm-256color").expect("spawn shell");
    // Keep the output channel drained so the reader thread never blocks on a full channel.
    let drain = tokio::spawn(async move { while rx.recv().await.is_some() {} });
    tokio::time::sleep(Duration::from_millis(200)).await;

    tokio::time::timeout(
        Duration::from_secs(20),
        tokio::task::spawn_blocking(move || pty.shutdown()),
    )
    .await
    .expect("shutdown must not deadlock (both threads must unblock and join)")
    .expect("shutdown task panicked");
    let _ = drain.await;
}

#[tokio::test]
#[allow(
    clippy::match_wild_err_arm,
    reason = "a timeout in this test IS the test failing; panicking on the `Err(_)` deadline arm is the intended assertion"
)]
async fn reaped_child_is_not_signaled_again() {
    // KR-02: once the child is reaped (try_wait/wait returned Some), every kill path must be a
    // no-op so it can't signal a recycled PID. We can't force PID reuse in a test, but we exercise
    // the reaped-gate: a one-shot `echo` exits and is reaped, after which kill()/kill_hard()/
    // shutdown() must be safe no-ops (no error, no panic).
    let (mut pty, mut rx) = Pty::spawn(24, 80, Some("echo"), "xterm-256color").expect("spawn echo");
    // Drain output to EOF so the child has exited.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(_)) => {}
            Ok(None) => break, // child exited, reader finished
            Err(_) => panic!("timed out waiting for echo to exit"),
        }
    }
    // Reap the child, setting the internal `reaped` flag (it may take a moment after EOF).
    let mut reaped = false;
    for _ in 0..200 {
        if matches!(pty.try_wait(), Ok(Some(_))) {
            reaped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(reaped, "the one-shot child must exit and be reaped");
    // After reaping, every kill path is gated and must be a safe no-op (never signaling a PID we no
    // longer own).
    assert!(pty.kill().is_ok(), "kill() after reap is a gated no-op");
    pty.kill_hard(); // must not signal a (possibly recycled) PID, must not panic
    pty.shutdown(); // consumes; Drop is reaped-gated; must not panic
}
