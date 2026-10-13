//! Real-PTY / real-shell tests for [`koh::pty::Pty`].
//!
//! These live in their own integration-test binary (rather than inline `#[cfg(test)]`) on purpose:
//! each spawns a real child + PTY + two pump threads, and running them alongside the ~100 inline
//! unit/property tests in one massively-parallel binary starved the PTY reader thread under load
//! (a flaky timeout). A dedicated binary runs only these few in parallel, so they stay reliable.
#![forbid(clippy::disallowed_methods)]

use std::time::Duration;

use koh::pty::{Exit, Pty, PtyError};
use koh::terminal::TtyModes;
use koh_testkit::{current_thread, multi_thread, read_until};
use tokio::sync::mpsc::Receiver;

/// `argv` on a 24×80 PTY, through [`launcher`]: the PTY, and what the program prints.
fn spawn(argv: &[String]) -> Result<(Pty, Receiver<Vec<u8>>), PtyError> {
    Pty::spawn(
        24,
        80,
        argv,
        "xterm-256color",
        &launcher(),
        &koh::pty::Reaper::start()?,
    )
}

/// `sh -c script` on a PTY, as [`spawn`] starts it.
fn sh(script: &str) -> Result<(Pty, Receiver<Vec<u8>>), PtyError> {
    spawn(&["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()])
}

/// Everything the program writes until it exits and the PTY closes, if that is within 20 s.
async fn drain(mut rx: Receiver<Vec<u8>>) -> Option<String> {
    let mut collected = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(chunk) = rx.recv().await {
            collected.extend_from_slice(&chunk);
        }
    })
    .await
    .ok()?;
    Some(String::from_utf8_lossy(&collected).into_owned())
}

/// How the program exited, once it is reaped, if that is within 5 s.
async fn exit(pty: &mut Pty) -> Option<Exit> {
    for _ in 0..500 {
        if let Some(status) = pty.try_wait().ok()? {
            return Some(status);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    None
}

#[cfg(unix)]
#[test]
fn external_signal_retains_shell_style_exit_status() {
    current_thread().expect("tokio runtime").block_on(async {
        use fuxix::process::{kill, Pid, Signal};

        // The shell prints its own pid, so the test can signal it from outside like any other process.
        let (mut pty, mut rx) =
            sh("echo PID=$$; while :; do sleep 1; done").expect("spawn signal fixture");
        let output = read_until(&mut rx, "\n").await.expect("the pid line");
        let pid = output
            .split_once("PID=")
            .and_then(|(_, rest)| rest.split_once(['\r', '\n']))
            .and_then(|(digits, _)| digits.parse::<i32>().ok())
            .expect("a pid");
        let pid = Pid::from_raw(pid).expect("a positive pid");
        kill(pid, Signal::Kill).expect("signal child");
        assert_eq!(exit(&mut pty).await.map(Exit::code), Some(137));
    });
}

#[cfg(target_os = "linux")]
#[test]
fn teardown_reaps_children_even_when_the_caller_does_not_wait() {
    current_thread().expect("runtime").block_on(async {
        for shutdown in [true, false, true, false] {
            let (pty, mut rx) = sh("echo $$; exec sleep 60").expect("spawn");
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
        let (pty, mut unread) = sh("exec yes").expect("spawn flood");
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
        let (pty, mut rx) = sh("stty raw -echo; echo $$; exec cat").expect("spawn");
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

/// A one-shot program's output streams to the end, and its exit status is reaped: `echo`'s
/// newline, and the status `sh -c "exit 7"` exits with only if both `-c` and the script reached it
/// as separate arguments.
#[test]
fn a_programs_output_streams_and_its_exit_status_is_reaped() {
    current_thread().expect("tokio runtime").block_on(async {
        for (argv, printed, code) in [(&["echo"][..], "\n", 0), (&["sh", "-c", "exit 7"], "", 7)] {
            let argv: Vec<String> = argv.iter().map(|&arg| arg.to_owned()).collect();
            let (mut pty, rx) = spawn(&argv).expect("spawn");
            let output = drain(rx).await;
            assert!(
                output.as_deref().is_some_and(|out| out.contains(printed)),
                "{argv:?} printed {output:?}"
            );
            assert_eq!(exit(&mut pty).await.map(Exit::code), Some(code));
        }
    });
}

#[test]
fn write_input_takes_shared_ref_and_preserves_order() {
    current_thread().expect("tokio runtime").block_on(async {
        // `pty` is bound WITHOUT `mut`, proving write_input takes `&self`. Two separate enqueues must
        // reach `cat` in FIFO order: the concatenated marker only appears if the second chunk did
        // not overtake the first.
        let (pty, mut rx) = spawn(&["cat".to_owned()]).expect("spawn cat");
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
        let (_pty, mut rx) = sh(r#"echo "H=$HOME F=$HISTFILE E=[$ENV]""#).expect("spawn sh");
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
        let (pty, mut rx) = sh("stty -echo; echo RE''ADY; cat").expect("spawn sh");
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

/// Dropping the `Pty` ends its program, and so the output channel: `cat` on the EOF the writer
/// thread writes once its sender is dropped (if it were stuck, or kept its handle, the channel would
/// never close), and a program that ignores SIGHUP (`sleep` inherits it) on the SIGKILL `Drop`
/// follows up with.
#[test]
fn dropping_a_pty_ends_its_program() {
    current_thread().expect("tokio runtime").block_on(async {
        for script in [
            "echo READY; exec cat",
            "trap '' HUP; echo READY; exec sleep 30",
        ] {
            let (pty, mut rx) = sh(script).expect("spawn sh");
            read_until(&mut rx, "READY")
                .await
                .expect("the program runs");
            drop(pty);
            assert!(
                drain(rx).await.is_some(),
                "{script:?} outlived its dropped PTY"
            );
        }
    });
}

#[test]
fn shutdown_joins_both_io_threads_without_deadlock() {
    current_thread().expect("tokio runtime").block_on(async {
        // Graceful teardown: shutdown() kills the child (so the reader's blocking read returns EOF) and
        // drops the writer sender (so the writer's recv returns), then joins BOTH pump threads. It must
        // return promptly — a hang would mean a thread never unblocked.
        let (pty, mut rx) = sh("echo READY; exec sh").expect("spawn shell");
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
        let (pty, mut rx) = sh("stty raw -echo; sleep 60").expect("spawn sleep");
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
                    let (mut pty, rx) = spawn(&["/bin/echo".to_owned(), marker.clone()])
                        .expect("spawn short-lived child");
                    let out = drain(rx).await.expect("output EOF deadline");
                    // Reap the child (as the session drain task does in production), so thousands of
                    // runs don't pile up zombies and exhaust the process table.
                    exit(&mut pty).await.expect("reaped");
                    pty.close();
                    (marker, out)
                }));
            }
            for run in runs {
                let (marker, out) = run.await.expect("child task");
                assert!(
                    out.contains(&marker),
                    "a short-lived child's output was lost: expected {marker}, got {out:?}"
                );
            }
        }
    });
}

#[test]
fn a_program_that_cannot_start_fails_the_spawn_and_is_named() {
    let missing = "/nonexistent/koh-no-such-program";
    let result = spawn(&[missing.to_owned()]);
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
        let (_pty, rx) = sh(&script).expect("spawn sh");
        let out = drain(rx).await.unwrap_or_default();
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
        let (pty, rx) =
            sh("echo GROUPS $$ $(ps -o pgid= -p $$) $(ps -o tpgid= -p $$) END; sleep 30")
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
        let (pty, mut rx) = sh(&script)
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
