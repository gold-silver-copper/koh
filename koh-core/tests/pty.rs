//! Real-PTY / real-shell tests for [`koh_core::pty::Pty`].
//!
//! These live in their own integration-test binary (rather than inline `#[cfg(test)]`) on purpose:
//! each spawns a real child + PTY + two pump threads, and running them alongside the ~100 inline
//! unit/property tests in one massively-parallel binary starved the PTY reader thread under load
//! (a flaky timeout). A dedicated binary runs only these few in parallel, so they stay reliable.

use std::time::Duration;

#[cfg(unix)]
#[test]
fn external_signal_retains_shell_style_exit_status() {
    current_thread().expect("tokio runtime").block_on(async {
        use fuxix::process::{kill, Pid, Signal};

        // The shell prints its own pid, so the test can signal it from outside like any other process.
        let (mut pty, mut rx) = Pty::spawn(
            24,
            80,
            &[
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo PID=$$; while :; do sleep 1; done".to_owned(),
            ],
            "xterm-256color",
            &launcher(),
        )
        .expect("spawn signal fixture");
        let mut output = String::new();
        let pid = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let chunk = rx.recv().await.expect("output before the pid line");
                output.push_str(&String::from_utf8_lossy(&chunk));
                let pid = output
                    .split_once("PID=")
                    .and_then(|(_, rest)| rest.split_once(['\r', '\n']))
                    .and_then(|(digits, _)| digits.parse::<i32>().ok());
                if let Some(pid) = pid {
                    break pid;
                }
            }
        })
        .await
        .expect("pid line deadline");
        let pid = Pid::from_raw(pid).expect("a positive pid");
        kill(pid, Signal::Kill).expect("signal child");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = pty.try_wait().expect("wait child") {
                assert_eq!(status.exit_code(), 137);
                assert_eq!(status.signal(), Some(fuxix::process::Signal::Kill.raw()));
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "signal status deadline"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
}

use koh_core::pty::Pty;

#[test]
#[expect(
    clippy::match_wild_err_arm,
    reason = "a timeout in this test IS the test failing; panicking on the `Err(_)` deadline arm is the intended assertion"
)]
fn spawns_and_streams_output() {
    current_thread().expect("tokio runtime").block_on(async {
        // Run a one-shot command in the PTY and confirm we receive its output + reap it.
        let (mut pty, mut rx) =
            Pty::spawn(24, 80, &["echo".to_owned()], "xterm-256color", &launcher())
                .expect("spawn echo");
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
    });
}

#[test]
#[expect(
    clippy::match_same_arms,
    reason = "channel-close (`Ok(None)`) and deadline (`Err(_)`) are conceptually distinct outcomes kept as separate arms for readability, even though both set `found = false`"
)]
fn interactive_shell_echoes_input() {
    current_thread().expect("tokio runtime").block_on(async {
        // Spawn the default shell, send a command, and verify the echoed output comes back.
        let (mut pty, mut rx) =
            Pty::spawn(24, 80, &[], "xterm-256color", &launcher()).expect("spawn shell");
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
    });
}

#[test]
#[expect(
    clippy::match_same_arms,
    reason = "channel-close (`Ok(None)`) and deadline (`Err(_)`) are conceptually distinct outcomes kept as separate arms for readability, even though both set `in_order = false`"
)]
fn write_input_takes_shared_ref_and_preserves_order() {
    current_thread().expect("tokio runtime").block_on(async {
        // `pty` is bound WITHOUT `mut`, proving write_input takes `&self`. Two separate enqueues must
        // reach the child in FIFO order: the concatenated marker only appears if the second chunk did
        // not overtake the first.
        let (pty, mut rx) =
            Pty::spawn(24, 80, &[], "xterm-256color", &launcher()).expect("spawn shell");
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
    });
}

#[test]
#[expect(
    clippy::needless_continue,
    clippy::match_wild_err_arm,
    reason = "the explicit `continue` documents the drain-and-keep-reading intent; the `Err(_)` deadline arm panics because a timeout here IS the test failing"
)]
fn dropping_pty_eofs_child_and_stops_writer() {
    current_thread().expect("tokio runtime").block_on(async {
        // `cat` blocks reading stdin. Dropping the Pty drops the writer-thread sender; the writer thread
        // then writes EOT and finishes — so the child sees EOF, exits, the slave closes, and the
        // output channel ends. If the writer thread were stuck (or never let go of its handle), the
        // channel would never close.
        let (pty, mut rx) = Pty::spawn(24, 80, &["cat".to_owned()], "xterm-256color", &launcher())
            .expect("spawn cat");
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(pty); // no kill(): EOF must come purely from the writer handle being dropped

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(_)) => continue, // drain any echoed bytes
                Ok(None) => break, // channel closed: child EOF'd + exited; writer thread ended
                Err(_) => panic!("dropping Pty did not EOF the child (writer stuck?)"),
            }
        }
    });
}

#[test]
fn shutdown_joins_both_io_threads_without_deadlock() {
    current_thread().expect("tokio runtime").block_on(async {
        // Graceful teardown: shutdown() kills the child (so the reader's blocking read returns EOF) and
        // drops the writer sender (so the writer's recv returns), then joins BOTH pump threads. It must
        // return promptly — a hang would mean a thread never unblocked.
        let (pty, mut rx) = Pty::spawn(24, 80, &["sh".to_owned()], "xterm-256color", &launcher())
            .expect("spawn shell");
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
    });
}

#[test]
#[expect(
    clippy::match_wild_err_arm,
    reason = "a timeout in this test IS the test failing; panicking on the `Err(_)` deadline arm is the intended assertion"
)]
fn reaped_child_is_not_signaled_again() {
    current_thread().expect("tokio runtime").block_on(async {
        // Once the child is reaped (try_wait/wait returned Some), every kill path must be a
        // no-op so it can't signal a recycled PID. We can't force PID reuse in a test, but we exercise
        // the reaped-gate: a one-shot `echo` exits and is reaped, after which kill()/kill_hard()/
        // shutdown() must be safe no-ops (no error, no panic).
        let (mut pty, mut rx) =
            Pty::spawn(24, 80, &["echo".to_owned()], "xterm-256color", &launcher())
                .expect("spawn echo");
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
    });
}

#[test]
#[expect(
    clippy::match_wild_err_arm,
    reason = "a timeout in this test IS the test failing; panicking on the `Err(_)` deadline arm is the intended assertion"
)]
fn argv_tail_reaches_the_child() {
    current_thread().expect("tokio runtime").block_on(async {
        // The argument tail must reach the program verbatim: `sh -c "exit 7"` exits 7 only if both
        // `-c` and the script arrived as separate argv entries.
        let argv: Vec<String> = ["sh", "-c", "exit 7"]
            .into_iter()
            .map(String::from)
            .collect();
        let (mut pty, mut rx) =
            Pty::spawn(24, 80, &argv, "xterm-256color", &launcher()).expect("spawn sh -c");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => panic!("timed out waiting for the child to exit"),
            }
        }
        let mut status = None;
        for _ in 0..200 {
            if let Ok(Some(s)) = pty.try_wait() {
                status = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let status = status.expect("the child must exit and be reaped");
        assert_eq!(
            status.exit_code(),
            7,
            "the `-c \"exit 7\"` tail must have reached sh"
        );
    });
}

#[test]
fn short_lived_children_never_lose_their_output() {
    multi_thread().expect("tokio runtime").block_on(async {
        // A child that writes and exits before anything reads the master loses ALL of its output
        // on macOS (a closed slave with nobody reading discards the queue), so the reader must be
        // running before the spawn. A reader started late loses about 3 outputs in 1000 under
        // load; spawning many at once is the load, and every one must deliver its marker.
        // 16 at a time stays well under macOS's PTY cap (`kern.tty.ptmx_max`, 511) even when several
        // PTY tests run at once; 128 rounds reproduce a late reader on every run.
        const CHILDREN: usize = 16;
        const ROUNDS: usize = 128;
        for round in 0..ROUNDS {
            // Spawn every child before awaiting any, so they all run concurrently.
            let mut runs = Vec::with_capacity(CHILDREN);
            for i in 0..CHILDREN {
                runs.push(tokio::spawn(async move {
                    let marker = format!("koh_short_{round}_{i}");
                    let (mut pty, mut rx) = Pty::spawn(
                        24,
                        80,
                        &["/bin/echo".to_owned(), marker.clone()],
                        "xterm-256color",
                        &launcher(),
                    )
                    .expect("spawn short-lived child");
                    let mut out = Vec::new();
                    tokio::time::timeout(Duration::from_secs(20), async {
                        while let Some(chunk) = rx.recv().await {
                            out.extend_from_slice(&chunk);
                        }
                    })
                    .await
                    .expect("output EOF deadline");
                    // Reap the child (as the session drain task does in production), so thousands of
                    // runs don't pile up zombies and exhaust the process table.
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                    while pty.try_wait().expect("wait child").is_none() {
                        assert!(tokio::time::Instant::now() < deadline, "reap deadline");
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    pty.shutdown();
                    (marker, out)
                }));
            }
            for run in runs {
                let (marker, out) = run.await.expect("child task");
                assert!(
                    String::from_utf8_lossy(&out).contains(&marker),
                    "a short-lived child's output was lost: expected {marker}, got {out:?}"
                );
            }
        }
    });
}

/// Runtimes for the tests. `#[tokio::test]` is not used: its expansion `allow`s
/// `clippy::expect_used`, which koh-core forbids, and a `forbid` rejects that `allow`.
fn current_thread() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

fn multi_thread() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
}

/// Everything the program writes, until it exits and the PTY closes (or 20 s pass).
async fn all_output(mut rx: tokio::sync::mpsc::Receiver<Vec<u8>>) -> String {
    let mut collected = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(chunk) = rx.recv().await {
            collected.extend_from_slice(&chunk);
        }
    })
    .await;
    String::from_utf8_lossy(&collected).into_owned()
}

#[test]
fn a_program_that_cannot_start_fails_the_spawn_and_is_named() {
    let missing = "/nonexistent/koh-no-such-program";
    let result = Pty::spawn(24, 80, &[missing.to_owned()], "xterm-256color", &launcher());
    let Err(error) = result else {
        panic!("a missing program must fail the spawn, not yield a dead session");
    };
    assert!(
        matches!(error, koh_core::pty::PtyError::Spawn(_)),
        "{error:?}"
    );
    assert!(error.to_string().contains(missing), "{error}");
}

#[test]
fn a_descriptor_the_server_holds_without_close_on_exec_does_not_reach_the_shell() {
    current_thread().expect("tokio runtime").block_on(async {
        use std::os::fd::AsRawFd;
        // Any descriptor koh serve inherited or opened without close-on-exec, standing in for one
        // a racing thread had not yet marked.
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        let leaked = fuxix::io::duplicate_inheritable(&file).expect("an inheritable copy");
        let fd = leaked.as_raw_fd();
        let script = format!("if [ -e /dev/fd/{fd} ]; then echo HAS_FD; else echo NO_FD; fi");
        let (_pty, rx) = Pty::spawn(
            24,
            80,
            &["/bin/sh".to_owned(), "-c".to_owned(), script],
            "xterm-256color",
            &launcher(),
        )
        .expect("spawn sh");
        let out = all_output(rx).await;
        assert!(
            out.contains("NO_FD"),
            "descriptor {fd} reached the shell: {out:?}"
        );
        drop(leaked);
    });
}

#[test]
fn the_shell_leads_its_own_session_and_owns_its_terminal() {
    current_thread().expect("tokio runtime").block_on(async {
        // `ps` reports the shell's process group and its terminal's foreground group; the shell
        // stays alive (`sleep`) so its session can be read from outside.
        let (pty, rx) = Pty::spawn(
            24,
            80,
            &[
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo GROUPS $$ $(ps -o pgid= -p $$) $(ps -o tpgid= -p $$) END; sleep 30"
                    .to_owned(),
            ],
            "xterm-256color",
            &launcher(),
        )
        .expect("spawn sh");
        let mut rx = rx;
        let mut out = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(20), async {
            while let Some(chunk) = rx.recv().await {
                out.push_str(&String::from_utf8_lossy(&chunk));
                if out.contains("END") {
                    break;
                }
            }
        })
        .await;
        let line = out
            .lines()
            .find(|l| l.starts_with("GROUPS"))
            .unwrap_or_else(|| panic!("no report: {out:?}"));
        let ids: Vec<i32> = line
            .split_whitespace()
            .filter_map(|w| w.parse().ok())
            .collect();
        let [pid, pgid, tpgid] = ids[..] else {
            panic!("unexpected report: {line:?}");
        };
        assert_eq!(pgid, pid, "the shell leads its own process group: {line}");
        assert_eq!(
            tpgid, pid,
            "the shell's group is its terminal's foreground group: {line}"
        );
        let pid = fuxix::process::Pid::from_raw(pid).expect("a valid pid");
        assert_eq!(
            fuxix::process::session(pid),
            Some(pid),
            "the shell leads its own session"
        );
        pty.kill_hard();
    });
}

#[test]
fn a_child_that_ignores_sighup_dies_when_its_pty_is_dropped() {
    current_thread().expect("tokio runtime").block_on(async {
        // `sleep` inherits the ignored SIGHUP, so only the SIGKILL `Drop` follows up with ends it;
        // until something does, it holds the slave open and the output channel never ends.
        let (pty, mut rx) = Pty::spawn(
            24,
            80,
            &[
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "trap '' HUP; echo READY; exec sleep 30".to_owned(),
            ],
            "xterm-256color",
            &launcher(),
        )
        .expect("spawn sh");
        let mut out = String::new();
        tokio::time::timeout(Duration::from_secs(20), async {
            while !out.contains("READY") {
                let Some(chunk) = rx.recv().await else { break };
                out.push_str(&String::from_utf8_lossy(&chunk));
            }
        })
        .await
        .expect("the child reports it is ready");
        drop(pty);
        let ended = tokio::time::timeout(Duration::from_secs(5), async {
            while rx.recv().await.is_some() {}
        })
        .await;
        assert!(
            ended.is_ok(),
            "a SIGHUP-immune child outlived its dropped PTY"
        );
    });
}

/// The launcher every PTY in these tests starts through.
fn launcher() -> koh_core::pty::Launcher {
    koh_core::pty::Launcher::new(env!("CARGO_BIN_EXE_koh-launch"))
}
