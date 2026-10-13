//! Real-PTY / real-shell tests for [`koh::pty::Pty`].
//!
//! These live in their own integration-test binary (rather than inline `#[cfg(test)]`) on purpose:
//! each spawns a real child + PTY + two pump threads, and running them alongside the ~100 inline
//! unit/property tests in one massively-parallel binary starved the PTY reader thread under load
//! (a flaky timeout). A dedicated binary runs only these few in parallel, so they stay reliable.
#![forbid(clippy::disallowed_methods)]

use std::time::Duration;

use koh_testkit::{current_thread, multi_thread, read_until};

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
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn signal fixture");
        let output = read_until(&mut rx, "\n").await.expect("the pid line");
        let pid = output
            .split_once("PID=")
            .and_then(|(_, rest)| rest.split_once(['\r', '\n']))
            .and_then(|(digits, _)| digits.parse::<i32>().ok())
            .expect("a pid");
        let pid = Pid::from_raw(pid).expect("a positive pid");
        kill(pid, Signal::Kill).expect("signal child");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = pty.try_wait().expect("wait child") {
                assert_eq!(status.code(), 137);
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

use koh::pty::Pty;
use koh::terminal::TtyModes;

#[cfg(target_os = "linux")]
#[test]
fn teardown_reaps_children_even_when_the_caller_does_not_wait() {
    current_thread().expect("runtime").block_on(async {
        for shutdown in [true, false, true, false] {
            let (pty, mut rx) = Pty::spawn(
                24,
                80,
                &[
                    "/bin/sh".into(),
                    "-c".into(),
                    "echo $$; exec sleep 60".into(),
                ],
                "xterm-256color",
                &launcher(),
                &koh::pty::Reaper::start().expect("reaper"),
            )
            .expect("spawn");
            let output = read_until(&mut rx, "\n").await.expect("the pid line");
            let pid: u32 = output.trim().parse().expect("pid");
            // Keep the receiver alive but unread: teardown must not depend on its consumer.
            if shutdown {
                tokio::task::spawn_blocking(move || pty.close())
                    .await
                    .expect("shutdown");
            } else {
                drop(pty);
            }
            let status = format!("/proc/{pid}/status");
            tokio::time::timeout(Duration::from_secs(5), async {
                while std::path::Path::new(&status).exists() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("child must be reaped, not merely killed");
        }
    });
}

#[test]
fn shutdown_does_not_need_a_consumer_for_flooded_output() {
    current_thread().expect("runtime").block_on(async {
        let (pty, mut unread) = Pty::spawn(
            24,
            80,
            &["/bin/sh".into(), "-c".into(), "exec yes".into()],
            "xterm-256color",
            &launcher(),
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn flood");
        // Once it floods, leave the rest unread.
        read_until(&mut unread, "y").await.expect("the flood");
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || pty.close()),
        )
        .await
        .expect("unread output must not wedge shutdown")
        .expect("shutdown");
    });
}

#[test]
fn stopped_reader_applies_backpressure_and_resumes_in_order() {
    current_thread().expect("runtime").block_on(async {
        use fuxix::process::{kill, Pid, Signal};
        use koh::pty::WriteError;
        let (pty, mut rx) = Pty::spawn(
            24,
            80,
            &[
                "/bin/sh".into(),
                "-c".into(),
                "stty raw -echo; echo $$; exec cat".into(),
            ],
            "xterm-256color",
            &launcher(),
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn");
        let line = read_until(&mut rx, "\n").await.expect("the pid line");
        let pid = Pid::from_raw(line.trim().parse().expect("pid digits")).expect("valid pid");
        kill(pid, Signal::Stop).expect("stop reader");
        let mut expected = Vec::new();
        let pending = loop {
            let bytes = format!("{:08}:\x1b[1;1R\x1b[48;24;80;0;0t", expected.len())
                .repeat(128)
                .into_bytes();
            match pty.write(bytes.clone()) {
                Ok(()) => expected.extend_from_slice(&bytes),
                Err(WriteError::Full(bytes)) => break bytes,
                Err(WriteError::Closed(_)) => panic!("reader is stopped, not closed"),
            }
            assert!(
                expected.len() < 2 * 1024 * 1024,
                "byte budget must bound input"
            );
        };
        assert_ne!(expected.len(), 0);
        kill(pid, Signal::Cont).expect("resume reader");
        let mut retry = pending;
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let pointer = retry.as_ptr();
                match pty.write(retry) {
                    Ok(()) => break,
                    Err(WriteError::Full(bytes)) => {
                        assert_eq!(bytes.as_ptr(), pointer, "retry keeps the allocation");
                        retry = bytes;
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    Err(WriteError::Closed(_)) => panic!("live reader closed"),
                }
            }
            // The final batch was made from the number of bytes already accepted.
            expected.extend_from_slice(
                format!("{:08}:\x1b[1;1R\x1b[48;24;80;0;0t", expected.len())
                    .repeat(128)
                    .as_bytes(),
            );
            while received.len() < expected.len() {
                received.extend_from_slice(&rx.recv().await.expect("echoed input"));
            }
        })
        .await
        .expect("input resumes without deadlock");
        assert_eq!(
            received, expected,
            "input and terminal replies preserve order"
        );
        drop(rx);
        tokio::task::spawn_blocking(move || pty.close())
            .await
            .expect("shutdown");
    });
}

#[test]
#[expect(
    clippy::match_wild_err_arm,
    reason = "a timeout in this test IS the test failing; panicking on the `Err(_)` deadline arm is the intended assertion"
)]
fn spawns_and_streams_output() {
    current_thread().expect("tokio runtime").block_on(async {
        // Run a one-shot command in the PTY and confirm we receive its output + reap it.
        let (mut pty, mut rx) = Pty::spawn(
            24,
            80,
            &["echo".to_owned()],
            "xterm-256color",
            &launcher(),
            &koh::pty::Reaper::start().expect("reaper"),
        )
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
        assert_eq!(status.code(), 0);
    });
}

#[test]
fn write_input_takes_shared_ref_and_preserves_order() {
    current_thread().expect("tokio runtime").block_on(async {
        // `pty` is bound WITHOUT `mut`, proving write_input takes `&self`. Two separate enqueues must
        // reach `cat` in FIFO order: the concatenated marker only appears if the second chunk did
        // not overtake the first.
        let (pty, mut rx) = Pty::spawn(
            24,
            80,
            &["cat".to_owned()],
            "xterm-256color",
            &launcher(),
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn cat");
        pty.write(b"ORDER_".to_vec()).expect("first enqueue");
        pty.write(b"AB_CD\n".to_vec()).expect("second enqueue");
        let in_order = read_until(&mut rx, "ORDER_AB_CD").await;
        // `cat` leaves the terminal as the kernel set it up: echoing, a line at a time. The
        // predictor shows typing at once only on that word.
        let modes = pty.tty_modes();
        drop(pty);
        in_order.expect("FIFO ordering of two enqueues should yield ORDER_AB_CD");
        assert_eq!(
            modes,
            Some(TtyModes {
                echo: true,
                line: true
            })
        );
    });
}

/// A shell a test hosts never reads or writes the user's files: its home is the test's, and it
/// keeps no history file and reads no `ENV` script.
#[test]
fn a_hosted_program_gets_the_tests_home_and_no_history_file() {
    current_thread().expect("tokio runtime").block_on(async {
        let (_pty, mut rx) = Pty::spawn(
            24,
            80,
            &[
                "sh".to_owned(),
                "-c".to_owned(),
                r#"echo "H=$HOME F=$HISTFILE E=[$ENV]""#.to_owned(),
            ],
            "xterm-256color",
            &launcher(),
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn sh");
        let shown = read_until(&mut rx, "]").await.expect("the shell ran");
        let home = koh_testkit::home!();
        assert!(
            shown.contains(&format!("H={} F=/dev/null E=[]", home.display())),
            "{shown}"
        );
    });
}

#[test]
fn a_password_prompt_without_echo_is_read_so() {
    current_thread().expect("tokio runtime").block_on(async {
        let (pty, mut rx) = Pty::spawn(
            24,
            80,
            &[
                "sh".to_owned(),
                "-c".to_owned(),
                "stty -echo; echo RE''ADY; cat".to_owned(),
            ],
            "xterm-256color",
            &launcher(),
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn sh");
        read_until(&mut rx, "READY").await.expect("stty ran");
        assert_eq!(
            pty.tty_modes(),
            Some(TtyModes {
                echo: false,
                line: true
            })
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
        let (pty, mut rx) = Pty::spawn(
            24,
            80,
            &[
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo READY; exec cat".to_owned(),
            ],
            "xterm-256color",
            &launcher(),
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn cat");
        read_until(&mut rx, "READY").await.expect("cat is running");
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
        let (pty, mut rx) = Pty::spawn(
            24,
            80,
            &[
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo READY; exec sh".to_owned(),
            ],
            "xterm-256color",
            &launcher(),
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn shell");
        read_until(&mut rx, "READY")
            .await
            .expect("the shell is running");
        // Keep the output channel drained so the reader thread never blocks on a full channel.
        let drain = koh_testkit::spawn(async move { while rx.recv().await.is_some() {} });

        tokio::time::timeout(
            Duration::from_secs(20),
            tokio::task::spawn_blocking(move || pty.close()),
        )
        .await
        .expect("shutdown must not deadlock (both threads must unblock and join)")
        .expect("shutdown task panicked");
        let _ = drain.await;
    });
}

#[test]
fn shutdown_returns_while_the_program_leaves_its_input_unread() {
    multi_thread(4).expect("tokio runtime").block_on(async {
        // `sleep` never reads its terminal, so a paste fills the PTY's input queue and the writer
        // thread blocks in `write`. Shutdown kills the program; it must not then wait on that
        // write forever, or `koh serve` could never exit after such a paste.
        let (pty, mut rx) = Pty::spawn(
            24,
            80,
            &[
                "sh".to_owned(),
                "-c".to_owned(),
                "stty raw -echo; sleep 60".to_owned(),
            ],
            "xterm-256color",
            &launcher(),
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn sleep");
        let drain = koh_testkit::spawn(async move { while rx.recv().await.is_some() {} });
        let chunk = vec![b'x'; 4096];
        let mut queued = 0;
        // Until the writer's budget is full: it holds more than the terminal's input queue takes,
        // so it is blocked on a write the program will never read.
        while queued < 256 && pty.write(chunk.clone()).is_ok() {
            queued += 1;
        }

        tokio::time::timeout(
            Duration::from_secs(20),
            tokio::task::spawn_blocking(move || pty.close()),
        )
        .await
        .expect("shutdown must not wait on a write the program will never read")
        .expect("shutdown task panicked");
        let _ = drain.await;
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
        let (mut pty, mut rx) = Pty::spawn(
            24,
            80,
            &argv,
            "xterm-256color",
            &launcher(),
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn sh -c");
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
            status.code(),
            7,
            "the `-c \"exit 7\"` tail must have reached sh"
        );
    });
}

#[test]
fn short_lived_children_never_lose_their_output() {
    multi_thread(4).expect("tokio runtime").block_on(async {
        // A child that writes and exits before anything reads the master loses ALL of its output
        // on macOS (a closed slave with nobody reading discards the queue), so the reader must be
        // running before the spawn. A reader started late loses about 3 outputs in 1000 under
        // load; spawning many at once is the load, and every one must deliver its marker.
        // 16 at a time stays well under macOS's PTY cap (`kern.tty.ptmx_max`, 511) even when several
        // PTY tests run at once, and within the room `launcher` makes in the kernel's PTY table;
        // 128 rounds reproduce a late reader on every run.
        const CHILDREN: usize = 16;
        const ROUNDS: usize = 128;
        for round in 0..ROUNDS {
            // Spawn every child before awaiting any, so they all run concurrently.
            let mut runs = Vec::with_capacity(CHILDREN);
            for i in 0..CHILDREN {
                runs.push(koh_testkit::spawn(async move {
                    let marker = format!("koh_short_{round}_{i}");
                    let (mut pty, mut rx) = Pty::spawn(
                        24,
                        80,
                        &["/bin/echo".to_owned(), marker.clone()],
                        "xterm-256color",
                        &launcher(),
                        &koh::pty::Reaper::start().expect("reaper"),
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
                    pty.close();
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
    let result = Pty::spawn(
        24,
        80,
        &[missing.to_owned()],
        "xterm-256color",
        &launcher(),
        &koh::pty::Reaper::start().expect("reaper"),
    );
    let Err(error) = result else {
        panic!("a missing program must fail the spawn, not yield a dead session");
    };
    assert!(matches!(error, koh::pty::PtyError::Spawn(_)), "{error:?}");
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
            &koh::pty::Reaper::start().expect("reaper"),
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
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn sh");
        let mut rx = rx;
        let out = read_until(&mut rx, "END").await.expect("the report");
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
        drop(pty);
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
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn sh");
        read_until(&mut rx, "READY")
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

/// The launcher every PTY in these tests starts through. First, once, room in the kernel's PTY
/// table (see [`grow_the_pty_table`]), so every test's PTYs are allocated after it.
fn launcher() -> koh::pty::Launcher {
    static GROWN: std::sync::Once = std::sync::Once::new();
    GROWN.call_once(grow_the_pty_table);
    koh::pty::Launcher::isolated(env!("CARGO_BIN_EXE_koh"), koh_testkit::home!())
}

/// How many PTYs [`grow_the_pty_table`] opens: well past what these tests hold at once (about 30).
const PTY_HEADROOM: usize = 64;

/// Grow macOS's PTY table past what these tests hold at once, so no PTY they open finds it full.
///
/// macOS allocates PTYs from a table that grows 16 slots at a time and never shrinks. An open that
/// finds it full picks the slot past its end, then drops a lock to allocate, and grows the table
/// only if it is still full: if another PTY was freed meanwhile, it does not grow it and the open
/// fails with ENXIO ("minor number out of range" in the kernel's log; `ptmx_get_ioctl` in XNU's
/// `bsd/kern/tty_ptmx.c`). A fresh machine's table is small, and these tests open PTYs while
/// others are freed, at a new high, so one could fail that way. Opening this many at once, and
/// only then freeing them, leaves the table larger than these tests ever fill.
fn grow_the_pty_table() {
    if cfg!(target_os = "macos") {
        let mut held = Vec::with_capacity(PTY_HEADROOM);
        // Another process's free can race these opens the same way; a few more tries win.
        for _ in 0..PTY_HEADROOM.saturating_mul(2) {
            if held.len() == PTY_HEADROOM {
                break;
            }
            if let Some(pty) =
                fuxix::terminal::Size::new(24, 80).and_then(|size| fuxix::pty::open(size).ok())
            {
                held.push(pty);
            }
        }
    }
}

/// A hung-up program has a moment to exit on its own, as a shell saving its history does, before
/// it is killed.
#[test]
fn a_hung_up_program_has_time_to_exit_before_it_is_killed() {
    current_thread().expect("tokio runtime").block_on(async {
        let dir = koh_testkit::scratch!("hangup").expect("a scratch directory");
        let saved = dir.join("saved");
        let script = format!(
            "trap 'sleep 0.3; echo saved > {}; exit 0' HUP; echo READY; while :; do sleep 0.05; done",
            saved.display()
        );
        let (pty, mut rx) = Pty::spawn(
            24,
            80,
            &["/bin/sh".to_owned(), "-c".to_owned(), script],
            "xterm-256color",
            &launcher(),
            &koh::pty::Reaper::start().expect("reaper"),
        )
        .expect("spawn sh");
        read_until(&mut rx, "READY")
            .await
            .expect("the child reports it is ready");
        tokio::task::spawn_blocking(move || pty.close())
            .await
            .expect("shutdown");
        let written = tokio::time::timeout(Duration::from_secs(5), async {
            while !saved.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(written.is_ok(), "the program was killed before its hangup handler finished");
    });
}
