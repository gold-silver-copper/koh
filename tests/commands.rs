//! The real `koh` binary's commands besides a shell, against an in-process loopback server it
//! dials with `--direct`: `koh exec` (argv as given, output apart, statuses, stdin, the hang-up),
//! jobs (`run`, `wait`, `logs`, `kill`, `jobs`), `koh cp` as a sync both ways, and `koh sessions`,
//! `wait --session` and `output` beside `koh connect --new` and `--session`.
#![forbid(clippy::disallowed_methods)]

#[expect(
    dead_code,
    reason = "no `koh serve` process here: the server runs in process"
)]
mod common;

use std::ffi::OsString;
use std::io::{BufRead as _, Write as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use common::{connected, endpoint_id, on_pty};
use koh_testkit::Scratch;

/// A loopback server hosting `sh` for one client, and that client's key.
struct Remote {
    id: String,
    port: u16,
    key: PathBuf,
    _server: tokio::task::JoinHandle<()>,
    _dir: Scratch,
}

impl Remote {
    async fn start(name: &str) -> anyhow::Result<Self> {
        Self::serving(name, std::convert::identity).await
    }

    /// As [`Self::start`], its server's config as `config` makes it.
    async fn serving(
        name: &str,
        config: impl FnOnce(koh::server::ServeConfig) -> koh::server::ServeConfig,
    ) -> anyhow::Result<Self> {
        let dir = koh_testkit::scratch!(name)?;
        let key = dir.join("client.key");
        let (id, port, server) = common::serve_in_process(&config(koh::server::ServeConfig {
            allow: vec![koh::transport_iroh::parse_endpoint_id(&endpoint_id(&key)?)?],
            command: vec!["bash".to_owned()],
            home: common::home(),
            ..koh::server::ServeConfig::default()
        }))
        .await?;
        Ok(Self {
            id,
            port,
            key,
            _server: server,
            _dir: dir,
        })
    }

    /// The flags that dial this server as its client.
    fn dialing(&self) -> Vec<OsString> {
        vec![
            "--key-file".into(),
            self.key.clone().into_os_string(),
            "--direct".into(),
            format!("127.0.0.1:{}", self.port).into(),
        ]
    }

    /// `koh SUBCOMMAND`, dialing this server.
    fn koh(&self, subcommand: &str) -> anyhow::Result<Command> {
        let mut koh = koh_testkit::command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())?;
        koh.arg(subcommand).args(self.dialing());
        Ok(koh)
    }

    /// `path` on this server, as `koh cp` takes it.
    fn at(&self, path: &Path) -> OsString {
        let mut at = format!("{}:", self.id).into_bytes();
        at.extend_from_slice(path.as_os_str().as_bytes());
        OsString::from_vec(at)
    }

    /// `koh SUBCOMMAND SERVER ARGS`: what it printed and how it exited.
    fn run(&self, subcommand: &str, args: &[&str]) -> anyhow::Result<Output> {
        Ok(self.koh(subcommand)?.arg(&self.id).args(args).output()?)
    }

    /// `koh exec --sh LINE`, `stdin` its input: what it printed and how it exited.
    fn exec(&self, line: &str, stdin: &[u8]) -> anyhow::Result<Output> {
        let mut child = self
            .koh("exec")?
            .arg(&self.id)
            .arg("--sh")
            .arg(line)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut input) = child.stdin.take() {
            input.write_all(stdin)?;
        }
        Ok(child.wait_with_output()?)
    }
}

#[test]
fn exec_passes_its_words_as_they_are_and_exits_with_the_commands_status() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("exec").await.expect("the server");
            let out = remote
                .exec("echo out; echo err >&2; exit 3", b"")
                .expect("exec");
            assert_eq!(
                (out.status.code(), &out.stdout[..], &out.stderr[..]),
                (Some(3), &b"out\n"[..], &b"err\n"[..]),
                "{out:?}"
            );
            // Words go as they are, no shell between: quotes, spaces and `$` reach the program.
            let out = remote
                .run(
                    "exec",
                    &["--", "printf", "[%s]\n", "a b", "it's", "$HOME", "x\"y"],
                )
                .expect("exec");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                "[a b]\n[it's]\n[$HOME]\n[x\"y]\n",
                "{out:?}"
            );
            // No such program: 127, and koh says so.
            let out = remote
                .run("exec", &["--", "no-such-program"])
                .expect("exec");
            assert_eq!(out.status.code(), Some(127), "{out:?}");
            assert!(String::from_utf8_lossy(&out.stderr).contains("no-such-program"));
            // A directory to start in; one not there is said as that, 126: the command could
            // not start, not that there is no such program.
            let out = remote.run("exec", &["-C", "/", "--", "pwd"]).expect("exec");
            assert_eq!(out.stdout, b"/\n", "{out:?}");
            let out = remote
                .run("exec", &["-C", "/no/such/dir", "--", "pwd"])
                .expect("exec");
            let said = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(126), "{out:?}");
            assert!(said.contains("/no/such/dir: no such directory"), "{said}");
            // One in this machine's home, as an unquoted `-C ~/x` reaches koh, is said to be so.
            let local = koh_testkit::home!().join("no-such-proj");
            let out = remote
                .run("exec", &["-C", &local.to_string_lossy(), "--", "pwd"])
                .expect("exec");
            let said = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(126), "{out:?}");
            assert!(
                said.contains("this machine's home") && said.contains("-C '~/no-such-proj'"),
                "{said}"
            );
            // Killed by a signal: 128 plus it, as a shell says, and nothing else on stderr.
            let out = remote.exec("kill -9 $$", b"").expect("exec");
            assert_eq!((out.status.code(), &out.stderr[..]), (Some(137), &b""[..]));
            // Stdin goes through whole, and its end is the command's.
            let big = vec![b'x'; 3 << 20];
            let out = remote.exec("wc -c", &big).expect("exec");
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "3145728");
            // As JSON: the output kept and the status beside it.
            let out = remote
                .run("exec", &["--json", "--sh", "echo hi; echo no >&2; exit 2"])
                .expect("exec");
            let said: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
            assert_eq!(out.status.code(), Some(2));
            assert_eq!(said["status"], 2);
            assert_eq!(said["stdout"], "hi\n");
            assert_eq!(said["stderr"], "no\n");
            // With no stdin at all, as from a script, it runs at once.
            let out = remote
                .koh("exec")
                .expect("koh")
                .args([&remote.id, "--sh", "cat; echo done"])
                .stdin(Stdio::null())
                .output()
                .expect("exec");
            assert_eq!(
                (out.status.code(), &out.stdout[..]),
                (Some(0), &b"done\n"[..])
            );
        });
}

/// Lines written to stdout and stderr by turns, as fast as a shell writes them.
const BY_TURNS: &str = "i=1; while [ $i -le 400 ]; do if [ $((i % 2)) = 0 ]; then echo out$i; \
                        else echo err$i >&2; fi; i=$((i + 1)); done";

/// What [`BY_TURNS`] writes, in its order.
fn by_turns() -> String {
    let lines: Vec<String> = (1..=400)
        .map(|i| format!("{}{i}\n", if i % 2 == 0 { "out" } else { "err" }))
        .collect();
    lines.concat()
}

/// A command's stdout and stderr, sent to one file here (`2>&1`), come in the order it wrote
/// them, as from a local command; and so do a job's in its log.
#[test]
fn stdout_and_stderr_to_one_file_keep_their_order() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("exec-order").await.expect("the server");
            let (mut read, write) = std::io::pipe().expect("a pipe");
            let mut koh = remote.koh("exec").expect("koh");
            koh.args([&remote.id, "--sh", BY_TURNS])
                .stdin(Stdio::null())
                .stdout(write.try_clone().expect("the pipe"))
                .stderr(write);
            let mut child = koh.spawn().expect("exec");
            drop(koh);
            let mut got = String::new();
            std::io::Read::read_to_string(&mut read, &mut got).expect("its output");
            assert!(child.wait().expect("exec").success());
            assert_eq!(got, by_turns());
            remote
                .run("run", &["--name", "turns", "--sh", BY_TURNS])
                .expect("run");
            let out = remote.run("wait", &["turns", "--tail", "0"]).expect("wait");
            assert!(out.status.success(), "{out:?}");
            let logs = remote.run("logs", &["turns", "--all"]).expect("logs");
            assert_eq!(String::from_utf8_lossy(&logs.stdout), by_turns());
        });
}

/// A burst of commands from one client, as an agent's parallel reads send them: each is served,
/// none given up for the others' handshakes.
#[test]
fn a_burst_of_commands_from_one_client_is_all_served() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("exec-burst").await.expect("the server");
            #[expect(
                clippy::needless_collect,
                reason = "all start before any is waited for"
            )]
            let children: Vec<_> = (0..32)
                .map(|n| {
                    remote
                        .koh("exec")
                        .expect("koh")
                        .args([&remote.id, "--", "echo", &n.to_string()])
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .expect("exec")
                })
                .collect();
            for (n, child) in children.into_iter().enumerate() {
                let out = child.wait_with_output().expect("exec");
                assert_eq!(
                    (out.status.code(), String::from_utf8_lossy(&out.stdout)),
                    (Some(0), format!("{n}\n").into()),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        });
}

/// Quiet commands from several koh processes of one key at once, each outlasting the others'
/// starts, all keep their links through a relay, as agents' parallel calls do through n0's: each
/// process dials from a key of its own and proves the client's, so none takes another's place at
/// the relay, nor its paths at the server.
#[test]
fn quiet_commands_of_one_key_at_once_through_a_relay_all_keep_their_links() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let mut relaying = iroh_relay::server::ServerConfig::default();
            relaying.relay = Some(iroh_relay::server::RelayConfig::new((
                std::net::Ipv4Addr::LOCALHOST,
                0_u16,
            )));
            let relay = iroh_relay::server::Server::spawn(relaying)
                .await
                .expect("the relay");
            let url = koh::transport_iroh::parse_relay_url(&format!(
                "http://{}",
                relay.http_addr().expect("the relay's address")
            ))
            .expect("the relay's URL");
            let dir = koh_testkit::scratch!("exec-relay").expect("a scratch directory");
            let key = dir.join("client.key");
            let hosting = koh::server::cli::Hosting::from_config(&koh::server::ServeConfig {
                allow: vec![koh::transport_iroh::parse_endpoint_id(
                    &endpoint_id(&key).expect("the client's id"),
                )
                .expect("an id")],
                command: vec!["bash".to_owned()],
                home: common::home(),
                ..koh::server::ServeConfig::default()
            })
            .expect("the config");
            let network = koh::transport_iroh::Network::Relay(url.clone());
            let endpoint = koh::transport_iroh::bind_on(
                koh::transport_iroh::generate_secret_key().expect("a key"),
                (true, koh::transport_iroh::Idle::Shell),
                &network,
                None,
            )
            .await
            .expect("the server's endpoint");
            let id = endpoint.id().to_string();
            let _server = koh_testkit::spawn(koh::server::cli::serve_endpoint(
                endpoint,
                hosting,
                tokio_util::sync::CancellationToken::new(),
            ));
            let koh = |subcommand: &str| {
                let mut koh =
                    koh_testkit::command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())
                        .expect("koh");
                koh.arg(subcommand).arg("--key-file").arg(&key).args([
                    "--relay-url",
                    url.as_str(),
                    &id,
                ]);
                koh
            };
            let mut calls = Vec::new();
            for _ in 0..6 {
                calls.push(
                    koh("exec")
                        .args(["--", "sleep", "20"])
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .expect("exec"),
                );
                std::thread::sleep(Duration::from_secs(1));
            }
            // More of the key's processes come and go while they run.
            for _ in 0..5 {
                let jobs = koh("jobs").output().expect("jobs");
                assert!(
                    jobs.status.success(),
                    "{}",
                    String::from_utf8_lossy(&jobs.stderr)
                );
                std::thread::sleep(Duration::from_secs(2));
            }
            for call in calls {
                let out = call.wait_with_output().expect("exec");
                assert_eq!(
                    out.status.code(),
                    Some(0),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        });
}

/// A connection past `--max-connections` waits for room; one past as many waiting is turned away
/// as busy, saying so, with its own status: nothing ran, so it may be retried.
#[test]
fn past_its_room_a_command_waits_and_past_the_waiting_it_is_told_the_server_is_busy() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::serving("exec-busy", |config| koh::server::ServeConfig {
                max_connections: std::num::NonZeroU32::MIN,
                ..config
            })
            .await
            .expect("the server");
            // One runs, holding the one connection until its input ends.
            let mut running = remote
                .koh("exec")
                .expect("koh")
                .args([&remote.id, "--sh", "echo running; read x"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("exec");
            let mut said = String::new();
            let mut first = std::io::BufReader::new(running.stdout.take().expect("stdout"));
            first.read_line(&mut said).expect("its first line");
            assert_eq!(said, "running\n");
            // Two more: whichever the server takes first waits for room, and the other, past as
            // many waiting, is turned away.
            let mut next = [(); 2].map(|()| {
                remote
                    .koh("exec")
                    .expect("koh")
                    .args([&remote.id, "--", "echo", "waited"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("exec")
            });
            let mut refused = None;
            for _ in 0..200 {
                refused = next
                    .iter_mut()
                    .position(|child| child.try_wait().expect("try_wait").is_some());
                if refused.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let [a, b] = next;
            let (busy, waiting) = match refused.expect("one is turned away") {
                0 => (a, b),
                _ => (b, a),
            };
            let busy = busy.wait_with_output().expect("exec");
            assert_eq!(busy.status.code(), Some(75), "{busy:?}");
            let said = String::from_utf8_lossy(&busy.stderr);
            assert!(
                said.contains("server busy: too many connections at once; retry"),
                "{said}"
            );
            let busy = remote.run("sessions", &["--json"]).expect("sessions");
            assert_eq!(busy.status.code(), Some(75), "{busy:?}");
            let said: serde_json::Value = serde_json::from_slice(&busy.stdout).expect("json");
            assert_eq!(said["error"]["kind"], "busy");
            // The first ends; the one waiting is served.
            drop(running.stdin.take());
            let _ = running.wait();
            drop(first);
            let out = waiting.wait_with_output().expect("exec");
            assert_eq!(
                (out.status.code(), &out.stdout[..]),
                (Some(0), &b"waited\n"[..])
            );
        });
}

/// The command `koh exec` runs, hung up once its client goes, as `koh help exec` says: at once if
/// the client is stopped by a signal, within the 10 s idle timeout if it is killed where it
/// stands.
#[test]
fn a_command_whose_client_is_stopped_or_killed_is_hung_up() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("exec-hangup").await.expect("the server");
            // Neither gone nor a zombie (a hung-up command's group leader is reaped only once its
            // group's grace is over), as `ps` says.
            let runs = |pid: u32| {
                let ps = remote
                    .exec(&format!("ps -o stat= -p {pid}"), b"")
                    .expect("ps");
                let stat = String::from_utf8_lossy(&ps.stdout);
                !stat.trim().is_empty() && !stat.trim_start().starts_with('Z')
            };
            for (signal, within) in [
                (fuxix::process::Signal::Term, Duration::from_secs(1)),
                (fuxix::process::Signal::Hup, Duration::from_secs(1)),
                (fuxix::process::Signal::Int, Duration::from_secs(1)),
                (fuxix::process::Signal::Kill, Duration::from_secs(15)),
            ] {
                let mut child = remote
                    .koh("exec")
                    .expect("koh")
                    .args([&remote.id, "--sh", "echo $$; exec sleep 100"])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("exec");
                let mut line = String::new();
                std::io::BufReader::new(child.stdout.take().expect("stdout"))
                    .read_line(&mut line)
                    .expect("the command's pid");
                let pid: u32 = line.trim().parse().expect("a pid");
                let client = fuxix::process::Pid::of(&child).expect("the client's pid");
                fuxix::process::kill(client, signal).expect("stop the client");
                let stopped = std::time::Instant::now();
                while runs(pid) && stopped.elapsed() < within {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert!(
                    !runs(pid),
                    "the command outlived its client by {within:?} ({signal:?})"
                );
                let out = child.wait_with_output().expect("the client's end");
                // Stopped by a signal it can take, it says which, what became of the command, and
                // how to run one past it.
                if signal != fuxix::process::Signal::Kill {
                    let said = String::from_utf8_lossy(&out.stderr);
                    let name = format!("stopped by SIG{} after ", signal.name());
                    assert!(said.contains(&name), "{said}");
                    assert!(
                        said.contains("hung up") && said.contains("koh run"),
                        "{said}"
                    );
                }
            }
        });
}

/// A `koh serve` started ignoring signals (a script's `&` ignores SIGINT and SIGQUIT, `nohup`
/// SIGHUP) starts its programs with them at their defaults, as from a login: an ignored signal
/// stays ignored across `exec` unless koh catches it. It is started as a job of the in-process
/// server, by a shell that ignores them; its own command reads what it ignores (Linux says).
#[cfg(target_os = "linux")]
#[test]
fn a_server_started_ignoring_signals_starts_its_programs_with_their_defaults() {
    use fuxix::process::Signal::{Hup, Int, Quit, Tstp};
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("ignored-signals").await.expect("the server");
            let client = endpoint_id(&remote.key).expect("the client's id");
            let line = format!(
                "trap '' HUP INT QUIT TSTP; exec '{}' serve --local --allow {client} --shell sh \
                 --key-file '{}'",
                env!("CARGO_BIN_EXE_koh"),
                remote.key.with_file_name("inner.key").display()
            );
            let started = remote
                .run("run", &["--name", "inner", "--sh", &line])
                .expect("run");
            assert!(started.status.success(), "{started:?}");
            let up = remote
                .run("wait", &["inner", "--text", "udp port", "--timeout", "20"])
                .expect("wait");
            assert!(up.status.success(), "{up:?}");
            let logs = remote.run("logs", &["inner"]).expect("logs");
            let banner = String::from_utf8_lossy(&logs.stdout).into_owned();
            let after = |label: &str| {
                banner
                    .lines()
                    .find_map(|l| l.split_once(label))
                    .and_then(|(_, rest)| rest.split_whitespace().next())
                    .map_or_else(|| panic!("no {label:?} in {banner}"), str::to_owned)
            };
            let (id, port) = (after("endpoint id : "), after("udp port    : "));
            let mut exec = koh_testkit::command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())
                .expect("koh");
            exec.arg("exec")
                .arg("--key-file")
                .arg(&remote.key)
                .args(["--direct", &format!("127.0.0.1:{port}"), &id, "--sh"])
                .arg("grep '^SigIgn:' /proc/self/status");
            let out = exec.output().expect("exec");
            let _ = remote.run("kill", &["inner"]);
            let said = String::from_utf8_lossy(&out.stdout);
            let mask = said
                .trim()
                .strip_prefix("SigIgn:")
                .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
                .unwrap_or_else(|| panic!("{out:?}"));
            let bit = |signal: fuxix::process::Signal| 1_u64 << (signal.raw() - 1);
            let wanted = [Hup, Int, Quit, Tstp]
                .map(bit)
                .iter()
                .fold(0, |all, b| all | b);
            assert_eq!(mask & wanted, 0, "ignored: {mask:#x}");
        });
}

#[test]
fn a_job_outlives_its_client_and_is_waited_for_followed_and_killed() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("jobs").await.expect("the server");
            let ok = |out: &Output| {
                assert!(out.status.success(), "{out:?}");
                String::from_utf8_lossy(&out.stdout).into_owned()
            };
            let started = remote
                .run(
                    "run",
                    &[
                        "--name",
                        "build",
                        "--sh",
                        "echo start; sleep 1; echo listening; sleep 1; echo err >&2; exit 4",
                    ],
                )
                .expect("run");
            assert_eq!(ok(&started), "build\n");
            // Its name is taken while it runs.
            let again = remote
                .run("run", &["--name", "build", "--", "true"])
                .expect("run");
            assert_eq!(again.status.code(), Some(1), "{again:?}");
            // A job that cannot start says so as `exec` does: 126 no such directory, 127 no such
            // program.
            let nowhere = remote
                .run("run", &["-C", "/no/such/dir", "--", "true"])
                .expect("run");
            assert_eq!(nowhere.status.code(), Some(126), "{nowhere:?}");
            let missing = remote.run("run", &["--", "no-such-program"]).expect("run");
            assert_eq!(missing.status.code(), Some(127), "{missing:?}");
            // The text comes before the end: the wait ends at it.
            let waited = remote
                .run("wait", &["build", "--text", "listening", "--json"])
                .expect("wait");
            assert_eq!(waited.status.code(), Some(0), "{waited:?}");
            // The end, with its status, and the end of its output.
            let ended = remote.run("wait", &["build"]).expect("wait");
            assert_eq!(ended.status.code(), Some(4), "{ended:?}");
            assert_eq!(ended.stdout, b"start\nlistening\nerr\n");
            let said = String::from_utf8_lossy(&ended.stderr);
            assert!(said.starts_with("· exited 4 after "), "{said}");
            let quiet = remote.run("wait", &["build", "--tail", "0"]).expect("wait");
            assert_eq!(
                (quiet.status.code(), &quiet.stdout[..], &quiet.stderr[..]),
                (Some(4), &b""[..], &b""[..])
            );
            let logs = remote.run("logs", &["build"]).expect("logs");
            assert_eq!(ok(&logs), "start\nlistening\nerr\n");
            assert!(String::from_utf8_lossy(&logs.stderr).starts_with("· exited 4 after "));
            // Its last lines, and how many went before them.
            let last = remote.run("logs", &["build", "--tail", "1"]).expect("logs");
            assert_eq!(ok(&last), "err\n");
            let said = String::from_utf8_lossy(&last.stderr);
            assert!(
                said.contains("2 earlier lines not shown (--tail N shows more, --all all)"),
                "{said}"
            );
            let listed = remote.run("jobs", &["--json"]).expect("jobs");
            let jobs: serde_json::Value = serde_json::from_slice(&listed.stdout).expect("json");
            assert_eq!(jobs[0]["name"], "build");
            assert_eq!(jobs[0]["status"], 4);
            // A job is one line in the list, its command's first line marked as cut; by name, its
            // command whole.
            let script = "echo one\necho two";
            ok(&remote
                .run("run", &["--name", "lines", "--sh", script])
                .expect("run"));
            let listed = ok(&remote.run("jobs", &[]).expect("jobs"));
            let line = listed
                .lines()
                .find(|l| l.starts_with("lines "))
                .expect("listed");
            assert!(line.ends_with(" echo one …"), "{listed}");
            assert_eq!(listed.lines().count(), 2, "{listed}");
            let one = ok(&remote.run("jobs", &["lines"]).expect("jobs"));
            assert!(one.ends_with("\n  echo one\n  echo two\n"), "{one}");
            // At work though it writes nothing koh sees: its processes and CPU time say so, where
            // the server has a `/proc` to read them from.
            ok(&remote
                .run(
                    "run",
                    &[
                        "--name",
                        "quiet",
                        "--sh",
                        "i=0; while [ $i -lt 100000 ]; do i=$((i+1)); done > quiet.log; \
                         : > quiet.done; sleep 300",
                    ],
                )
                .expect("run"));
            ok(&remote
                .run("wait", &["--file", "quiet.done", "--timeout", "60"])
                .expect("wait"));
            let listed = ok(&remote.run("jobs", &[]).expect("jobs"));
            let line = listed
                .lines()
                .find(|l| l.starts_with("quiet "))
                .expect("listed");
            let json = remote.run("jobs", &["quiet", "--json"]).expect("jobs");
            let quiet: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json");
            if cfg!(target_os = "linux") {
                assert!(
                    line.contains(" processes=") && line.contains(" cpu="),
                    "{line}"
                );
                assert!(line.contains(" output=0 B "), "{line}");
                assert!(quiet[0]["processes"].as_u64() >= Some(1), "{quiet}");
                assert!(quiet[0]["cpu_ms"].as_u64() > Some(0), "{quiet}");
            } else {
                assert!(quiet[0]["processes"].is_null(), "{quiet}");
            }
            ok(&remote.run("kill", &["quiet"]).expect("kill"));
            // Unnamed, it takes the next number; killed, it ends by the signal.
            let sleeper = remote
                .run("run", &["--sh", "echo up; exec sleep 300"])
                .expect("run");
            assert_eq!(ok(&sleeper), "1\n");
            // Running, it is said to run on, and what waits for it.
            let running = remote.run("logs", &["1"]).expect("logs");
            ok(&running);
            let said = String::from_utf8_lossy(&running.stderr);
            assert!(said.starts_with("· running "), "{said}");
            let hint = format!("`koh logs {} 1 --follow` follows it to its end", remote.id);
            assert!(said.contains(&hint), "{said}");
            // A wait that gives up says the job runs on, and what it last wrote.
            let gave_up = remote
                .run("wait", &["1", "--timeout", "0.3"])
                .expect("wait");
            assert_eq!(gave_up.status.code(), Some(124), "{gave_up:?}");
            assert_eq!(String::from_utf8_lossy(&gave_up.stdout), "up\n");
            let said = String::from_utf8_lossy(&gave_up.stderr);
            assert!(
                said.starts_with("koh: timed out after 0s: 1 running "),
                "{said}"
            );
            assert!(said.contains(&hint), "{said}");
            ok(&remote.run("kill", &["1"]).expect("kill"));
            let killed = remote.run("wait", &["1", "--timeout", "10"]).expect("wait");
            assert_eq!(killed.status.code(), Some(128 + 15), "{killed:?}");
            // Followed: what it writes as it writes it, then its status.
            remote
                .run(
                    "run",
                    &["--name", "f", "--sh", "sleep 0.5; echo late; exit 6"],
                )
                .expect("run");
            let followed = remote.run("logs", &["f", "--follow"]).expect("logs");
            assert_eq!(
                (followed.status.code(), &followed.stdout[..]),
                (Some(6), &b"late\n"[..])
            );
            // A wait for a file, and one that gives up.
            let gave_up = remote
                .run("wait", &["--file", "never-made", "--timeout", "0.3"])
                .expect("wait");
            assert_eq!(gave_up.status.code(), Some(124), "{gave_up:?}");
            let no_job = remote.run("wait", &["nope"]).expect("wait");
            assert_ne!(no_job.status.code(), Some(0));
            assert!(String::from_utf8_lossy(&no_job.stderr).contains("no such job"));
        });
}

/// One entry of a tree: its path in it, kind, mode and contents (a file's bytes, a symlink's
/// target).
type Entry = (PathBuf, char, u32, Vec<u8>);

/// What is in `dir`, recursively, sorted.
fn tree(dir: &Path) -> std::io::Result<Vec<Entry>> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<Entry>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(at)? {
            let path = entry?.path();
            let rel = path
                .strip_prefix(root)
                .map_err(std::io::Error::other)?
                .to_path_buf();
            let meta = std::fs::symlink_metadata(&path)?;
            let mode = meta.mode() & 0o7777;
            if meta.is_symlink() {
                let target = std::fs::read_link(&path)?;
                out.push((rel, 'l', 0, target.into_os_string().into_vec()));
            } else if meta.is_dir() {
                out.push((rel, 'd', mode, Vec::new()));
                walk(root, &path, out)?;
            } else {
                out.push((rel, 'f', mode, std::fs::read(&path)?));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort();
    Ok(out)
}

/// A tree with a mode, a name holding a newline and a byte no UTF-8 holds, a directory in it and
/// a symlink.
fn sample(at: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(at.join("sub dir"))?;
    // A byte that is no UTF-8 where the file system takes one; macOS's refuses it.
    let odd = std::ffi::OsStr::from_bytes(if cfg!(target_os = "macos") {
        b"line\nbreak \xc3\xa9"
    } else {
        b"line\nbreak \xff"
    });
    std::fs::write(at.join(odd), b"odd")?;
    std::fs::write(at.join("run me"), b"#!/bin/sh\n")?;
    std::fs::set_permissions(at.join("run me"), std::fs::Permissions::from_mode(0o751))?;
    std::fs::write(at.join("sub dir/inner"), vec![7; 200_000])?;
    std::os::unix::fs::symlink("run me", at.join("link"))
}

/// The modification time of `path`.
fn mtime(path: &Path) -> (i64, i64) {
    std::fs::metadata(path).map_or((0, 0), |meta| (meta.mtime(), meta.mtime_nsec()))
}

#[test]
fn cp_brings_a_tree_into_line_both_ways_and_says_what_it_did() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("cp").await.expect("the server");
            let dir = koh_testkit::scratch!("cp-trees").expect("a scratch directory");
            let from = dir.join("a tree");
            sample(&from).expect("the tree");
            let cp = |args: &[OsString]| {
                remote
                    .koh("cp")
                    .expect("koh")
                    .args(args)
                    .output()
                    .expect("cp")
            };
            // Here to there, into a directory made with its parents.
            let there = dir.join("there/deep");
            let mut into = remote.at(&there);
            into.push("/");
            let out = cp(&["-r".into(), from.clone().into(), into.clone()]);
            assert!(out.status.success(), "{out:?}");
            // It says where the tree landed: in the directory, as its own name.
            let said = String::from_utf8_lossy(&out.stdout);
            let landed = format!("{}a tree", into.to_string_lossy());
            assert!(
                said.starts_with(&format!("3 files sent, 200 KB → {landed} (3 new; ")),
                "{said}"
            );
            let want = tree(&from).expect("the tree");
            assert_eq!(tree(&there.join("a tree")).expect("there"), want);
            // Named as the tree, which is there now: it is brought into line, as `a tree/.` would
            // be, not nested inside it as cp's rule would.
            let same = remote.at(&there.join("a tree"));
            let out = cp(&["-r".into(), from.clone().into(), same.clone()]);
            assert!(out.status.success(), "{out:?}");
            assert!(!there.join("a tree/a tree").exists());
            let said = String::from_utf8_lossy(&out.stdout);
            assert!(
                said.starts_with(&format!(
                    "0 files sent, 0 B → {} (3 unchanged",
                    same.to_string_lossy()
                )),
                "{said}"
            );
            // Again: nothing changed, nothing sent.
            let out = cp(&[from.clone().into(), into.clone()]);
            assert!(
                String::from_utf8_lossy(&out.stdout).starts_with("0 files sent, 0 B"),
                "{out:?}"
            );
            // One file edited, dated before the copy landed (an editor's save, or `touch -d`):
            // sent, and it lands with its arrival time, newer than the copy before, so a build
            // there sees it changed (K1).
            let inner = there.join("a tree/sub dir/inner");
            let before = mtime(&inner);
            std::fs::write(from.join("sub dir/inner"), vec![8; 200_000]).expect("edit");
            let old = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
            std::fs::File::options()
                .write(true)
                .open(from.join("sub dir/inner"))
                .and_then(|f| f.set_modified(old))
                .expect("an old time");
            let out = cp(&["--json".into(), from.clone().into(), into.clone()]);
            let summary: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
            assert_eq!(
                (summary["replaced"].as_u64(), summary["unchanged"].as_u64()),
                (Some(1), Some(2)),
                "{summary}"
            );
            assert_eq!(summary["landed"].as_str(), Some(&*landed), "{summary}");
            assert!(mtime(&inner) > before, "the edit landed with an old time");
            // A file new and one edited: the two sent, said apart, and the rest beside them.
            std::fs::write(from.join("fresh"), b"new").expect("a new file");
            std::fs::write(from.join("run me"), b"#!/bin/sh\nexit\n").expect("edit");
            let out = cp(&[from.clone().into(), into.clone()]);
            let said = String::from_utf8_lossy(&out.stdout);
            assert!(
                said.starts_with(&format!(
                    "2 files sent, 18 B → {landed} (1 new, 1 replaced; 2 unchanged"
                )),
                "{said}"
            );
            // -p keeps the source's time.
            let out = cp(&["-p".into(), from.clone().into(), into.clone()]);
            assert!(out.status.success(), "{out:?}");
            assert_eq!(mtime(&inner).0, 1_000_000);
            // There to here, as a new name.
            let back = dir.join("back");
            let out = cp(&[remote.at(&there.join("a tree")), back.clone().into()]);
            assert!(out.status.success(), "{out:?}");
            // Said by its direction: received here.
            let said = String::from_utf8_lossy(&out.stdout);
            assert!(
                said.contains(" files received, ") && !said.contains("sent"),
                "{said}"
            );
            assert_eq!(tree(&back).expect("back"), tree(&from).expect("the tree"));
            // --delete takes away what the source lacks, but what is excluded.
            std::fs::write(there.join("a tree/stray"), b"s").expect("a stray file");
            std::fs::write(there.join("a tree/kept.o"), b"o").expect("an excluded file");
            // Without it, what the source lacks is kept, and said so.
            let out = cp(&[from.clone().into(), into.clone()]);
            let said = String::from_utf8_lossy(&out.stdout);
            assert!(
                said.contains("2 there not in the source, kept: --delete removes them"),
                "{said}"
            );
            // A dry run says what would change, one a line, and changes nothing, either way.
            let exclude = || ["--exclude".into(), "*.o".into()];
            let mut args: Vec<OsString> = vec!["--dry-run".into(), "--delete".into()];
            args.extend(exclude());
            let out = cp(&[&args[..], &[from.clone().into(), into.clone()]].concat());
            let said = String::from_utf8_lossy(&out.stdout);
            assert!(
                said.starts_with("deleted  a tree/stray\ndry run: 0 files would be sent, 0 B"),
                "{out:?}"
            );
            assert!(
                said.contains("1 deleted") && said.contains("nothing changed"),
                "{said}"
            );
            assert!(there.join("a tree/stray").exists());
            let mut from_there = remote.at(&there.join("a tree"));
            from_there.push("/.");
            let out = cp(&[&args[..], &[from_there, back.clone().into()]].concat());
            let said = String::from_utf8_lossy(&out.stdout);
            assert!(
                said.starts_with("new      stray (1 B)\ndry run: 1 file would be received, 1 B"),
                "{out:?}"
            );
            assert!(!back.join("stray").exists());
            // --diff says how a file it would replace differs, the other end's text escaped but
            // for its tabs, and changes nothing.
            let note = dir.join("note");
            std::fs::write(&note, b"a\tb\x1b\n").expect("a note");
            std::fs::write(there.join("note"), b"a\n").expect("the note there");
            let out = cp(&["--diff".into(), note.into(), remote.at(&there.join("note"))]);
            let said = String::from_utf8_lossy(&out.stdout);
            assert!(
                said.starts_with(
                    "replaced note (5 B, was 2 B)\n--- a/note\n+++ b/note\n@@ -1 +1 @@\n-a\n+a\tb\\u{1b}\n"
                ),
                "{out:?}"
            );
            assert!(said.contains("nothing changed"), "{said}");
            assert_eq!(std::fs::read(there.join("note")).expect("there"), b"a\n");
            let out = cp(&[
                "--delete".into(),
                "--exclude".into(),
                "*.o".into(),
                from.clone().into(),
                into.clone(),
            ]);
            assert!(
                String::from_utf8_lossy(&out.stdout).contains("1 deleted"),
                "{out:?}"
            );
            assert!(!there.join("a tree/stray").exists());
            assert!(there.join("a tree/kept.o").exists());
            // `~` is the server user's home.
            let name = format!("koh-cp-{}", std::process::id());
            let mut home_path = b"~/".to_vec();
            home_path.extend_from_slice(name.as_bytes());
            let home_arg = remote.at(Path::new(std::ffi::OsStr::from_bytes(&home_path)));
            let out = cp(&[from.join("run me").into(), home_arg]);
            assert!(out.status.success(), "{out:?}");
            let landed = koh_testkit::home!().join(&name);
            let mode = std::fs::metadata(&landed).map(|m| m.mode() & 0o7777);
            let _ = std::fs::remove_file(&landed);
            assert_eq!(mode.ok(), Some(0o751));
            // A copy that fails partway says why, and leaves no file half written.
            if fuxix::process::geteuid() != 0 {
                let bad = dir.join("bad");
                sample(&bad).expect("the tree");
                let locked = bad.join("sub dir/locked");
                std::fs::write(&locked, b"secret").expect("a file");
                std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
                    .expect("mode");
                let into = dir.join("into");
                std::fs::create_dir(&into).expect("a directory");
                for args in [
                    [bad.clone().into(), remote.at(&into)],
                    [remote.at(&bad), into.clone().into()],
                ] {
                    let out = cp(&args);
                    assert!(!out.status.success(), "{out:?}");
                    let said = String::from_utf8_lossy(&out.stderr);
                    assert!(said.contains("permission denied"), "{said}");
                    assert!(!into.join("bad/sub dir/locked").exists());
                }
            }
        });
}

/// `--sync DIR` brings the same path there into line with DIR here, says so in a line on stderr,
/// and runs the command in it: an edit-and-build loop is one call. Only what changed is sent;
/// `-C` names another place there; `.` alone, with no name of its own there, needs `-C`.
#[test]
fn exec_and_run_sync_a_tree_first_and_run_in_it() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("sync").await.expect("the server");
            let here = koh_testkit::scratch!("sync-here").expect("a scratch directory");
            let name = format!("koh-sync-{}", std::process::id());
            std::fs::create_dir_all(here.join(&name).join("src")).expect("the tree");
            std::fs::write(here.join(&name).join("src/a.txt"), b"one\n").expect("a file");
            let koh = |sub: &str, args: &[&str]| {
                remote
                    .koh(sub)
                    .expect("koh")
                    .arg(&remote.id)
                    .args(args)
                    .current_dir(&here)
                    .output()
                    .expect("koh")
            };
            let at = format!("{}:{name}", remote.id);
            let cat = ["--", "sh", "-c", "cat src/a.txt; basename \"$PWD\""];
            let out = koh("exec", &[&["--sync", &name][..], &cat[..]].concat());
            let said = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                format!("one\n{name}\n")
            );
            assert!(
                said.starts_with(&format!("koh: synced 1 file sent, 4 B → {at} (1 new;")),
                "{said}"
            );
            // Edited here: that file alone goes, before the command reads it.
            std::fs::write(here.join(&name).join("src/a.txt"), b"two\n").expect("an edit");
            let out = koh(
                "exec",
                &[&["--sync", &format!("./{name}/")][..], &cat[..]].concat(),
            );
            let said = String::from_utf8_lossy(&out.stderr);
            assert!(
                String::from_utf8_lossy(&out.stdout).starts_with("two\n"),
                "{out:?}"
            );
            assert!(
                said.starts_with(&format!("koh: synced 1 file sent, 4 B → {at} (1 replaced")),
                "{said}"
            );
            // What a command made there is kept, and said so, with nothing to act on.
            koh("exec", &["--sync", &name, "--", "touch", "made"]);
            let out = koh("exec", &["--sync", &name, "--", "true"]);
            let said = String::from_utf8_lossy(&out.stderr);
            assert!(said.contains("1 there not in the source, kept)"), "{said}");
            // A job, the same way; and its JSON says the sync.
            let out = koh(
                "run",
                &[
                    "--json",
                    "--name",
                    "synced",
                    "--sync",
                    &name,
                    "--",
                    "cat",
                    "src/a.txt",
                ],
            );
            let said: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
            assert_eq!(said["job"], "synced", "{said}");
            assert_eq!(said["synced"]["unchanged"], 1, "{said}");
            let out = koh("wait", &["synced"]);
            assert_eq!(String::from_utf8_lossy(&out.stdout), "two\n", "{out:?}");
            // Into -C's directory, from within the tree.
            let out = remote
                .koh("exec")
                .expect("koh")
                .args([
                    &remote.id,
                    "--sync",
                    ".",
                    "-C",
                    &format!("{name}-too"),
                    "--",
                    "ls",
                ])
                .current_dir(here.join(&name))
                .output()
                .expect("koh");
            assert_eq!(String::from_utf8_lossy(&out.stdout), "src\n", "{out:?}");
            // `.` alone goes nowhere it names: refused, saying how, and nothing ran.
            let out = koh("exec", &["--sync", ".", "--", "touch", "ran"]);
            let said = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(2), "{out:?}");
            assert!(said.contains("with -C DIR"), "{said}");
        });
}

/// An in-process loopback server for the client `client`, saved with the scope `scope`
/// (`cp=DIR`, `exec=DIR`), as `koh clients add` saves one: its id, its port, its saved clients
/// and its task.
async fn scoped_server(
    client: &str,
    scope: &str,
) -> anyhow::Result<(String, u16, PathBuf, tokio::task::JoinHandle<()>)> {
    let dir = koh_testkit::scratch!("scoped-server")?;
    let server_key = dir.join("server.key");
    let clients = dir.join("clients");
    std::fs::write(&clients, format!("agent {client} {scope}\n"))?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&clients, std::fs::Permissions::from_mode(0o600))?;
    }
    let config = koh::server::ServeConfig {
        saved_clients: Some(koh::names::Places::new(None, Some(server_key))?),
        command: vec!["bash".to_owned()],
        home: common::home(),
        ..koh::server::ServeConfig::default()
    };
    let (id, port, task) = common::serve_in_process(&config).await?;
    // The scratch directory lives as long as the server.
    let task = koh_testkit::spawn(async move {
        let _dir = dir;
        let _ = task.await;
    });
    Ok((id, port, clients, task))
}

/// A client removed from the saved clients is cut off, its jobs hung up with it.
#[test]
fn a_removed_clients_jobs_are_hung_up() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let dir = koh_testkit::scratch!("revoked").expect("a scratch directory");
            let key = dir.join("client.key");
            let id = endpoint_id(&key).expect("the client's id");
            let (server_id, port, clients, _server) =
                scoped_server(&id, &format!("exec={}", dir.display()))
                    .await
                    .expect("the server");
            let ran = koh_testkit::command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())
                .expect("koh")
                .args(["run", &server_id, "--sh", "echo $$ > pid; exec sleep 600"])
                .arg("--key-file")
                .arg(&key)
                .args(["--direct", &format!("127.0.0.1:{port}")])
                .output()
                .expect("koh");
            assert!(ran.status.success(), "{ran:?}");
            let job = async {
                loop {
                    let pid = std::fs::read_to_string(dir.join("pid")).unwrap_or_default();
                    if let Some(pid) = pid
                        .trim()
                        .parse()
                        .ok()
                        .and_then(fuxix::process::Pid::from_raw)
                    {
                        return pid;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            };
            let job = tokio::time::timeout(Duration::from_secs(10), job)
                .await
                .expect("the job started");
            std::fs::write(&clients, "").expect("the client removed");
            let gone = async {
                while fuxix::process::exists(job) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            };
            tokio::time::timeout(Duration::from_secs(10), gone)
                .await
                .expect("the removed client's job hung up");
        });
}

#[test]
fn a_scoped_key_copies_only_in_its_directory_and_runs_no_shell() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let dir = koh_testkit::scratch!("scoped").expect("a scratch directory");
            let drop_dir = dir.join("drop");
            std::fs::create_dir_all(&drop_dir).expect("the scope");
            let key = dir.join("client.key");
            let id = endpoint_id(&key).expect("the client's id");
            let (server_id, port, _, _server) =
                scoped_server(&id, &format!("cp={}", drop_dir.display()))
                    .await
                    .expect("the server");
            let koh = |args: &[OsString]| {
                koh_testkit::command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())
                    .expect("koh")
                    .args(args)
                    .args([
                        "--key-file".into(),
                        key.clone().into_os_string(),
                        "--direct".into(),
                        OsString::from(format!("127.0.0.1:{port}")),
                    ])
                    .output()
                    .expect("koh")
            };
            let file = dir.join("f");
            std::fs::write(&file, b"f").expect("a file");
            let at = |p: &str| OsString::from(format!("{server_id}:{p}"));
            let ok = koh(&["cp".into(), file.clone().into(), at("in/f")]);
            assert!(ok.status.success(), "{ok:?}");
            assert_eq!(std::fs::read(drop_dir.join("in/f")).expect("landed"), b"f");
            for outside in ["../f", "/etc/f", "~/f"] {
                let out = koh(&["cp".into(), file.clone().into(), at(outside)]);
                assert!(!out.status.success(), "{outside}: {out:?}");
            }
            // No command, no shell: refused for good (4).
            let out = koh(&[
                "exec".into(),
                server_id.clone().into(),
                "--".into(),
                "true".into(),
            ]);
            assert_eq!(out.status.code(), Some(255), "{out:?}");
            let out = koh(&["sessions".into(), server_id.clone().into()]);
            assert_eq!(out.status.code(), Some(4), "{out:?}");
        });
}

/// `koh connect SERVER -C DIR -- PROG ARG...`: a new session running the program on a terminal
/// of its own, in place of the shell, started in DIR; the client ends when it does, with its
/// status. A DIR not there starts nothing: 126, as `exec` says it.
#[test]
fn connect_runs_one_program_on_a_terminal_and_exits_with_its_status() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("connect-program").await.expect("the server");
            let mut argv = vec![env!("CARGO_BIN_EXE_koh").to_owned(), "connect".to_owned()];
            argv.extend(
                remote
                    .dialing()
                    .into_iter()
                    .map(|a| a.to_string_lossy().into_owned()),
            );
            let program = "[ -t 0 ] && [ -t 1 ] && echo \"tty_$(stty size | tr ' ' x)_in_$PWD\"; \
                           read line; echo \"got_${line}_$((6*7))\"; exit 3";
            let nowhere = {
                let mut argv = argv.clone();
                argv.extend([remote.id.clone(), "-C".into(), "/no/such/dir".into()]);
                argv.extend(["--".into(), "true".into()]);
                argv
            };
            argv.extend([
                remote.id.clone(),
                "-C".into(),
                "/".into(),
                "--".into(),
                "sh".into(),
                "-c".into(),
                program.into(),
            ]);
            let (mut client, seen, at) = connected(&argv, b"hi\r", "got_hi_42")
                .await
                .expect("the program's answer");
            assert!(
                seen.text_from(0).contains("tty_24x80_in_/\r"),
                "{}",
                seen.text_from(0)
            );
            // It ends as soon as the end is here: it closes the link, waiting on the server for
            // nothing (it waited 2 s for the server to close).
            let ending = std::time::Instant::now();
            assert_eq!(
                exit_of(&mut client).await,
                Some(3),
                "{}",
                seen.text_from(at)
            );
            assert!(
                ending.elapsed() < Duration::from_millis(1800),
                "{:?}",
                ending.elapsed()
            );
            let (mut client, seen) = on_pty(&nowhere).expect("koh connect");
            assert_eq!(
                exit_of(&mut client).await,
                Some(126),
                "{}",
                seen.text_from(0)
            );
            assert!(
                seen.text_from(0)
                    .contains("/no/such/dir: no such directory"),
                "{}",
                seen.text_from(0)
            );
            // It was a session of its own, now ended: none is left.
            let out = remote.run("sessions", &["--json"]).expect("sessions");
            let listed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
            assert_eq!(listed.as_array().map(Vec::len), Some(0), "{listed}");
        });
}

/// How `client` exited, waited for up to 10 s.
async fn exit_of(client: &mut koh::pty::Pty) -> Option<u32> {
    for _ in 0..100 {
        if let Ok(Some(status)) = client.try_wait() {
            return Some(status.code());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

#[test]
fn connect_picks_a_session_by_number_or_a_new_one_and_sessions_lists_them() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("sessions").await.expect("the server");
            let connect = |pick: &[&str]| {
                let mut argv = vec![env!("CARGO_BIN_EXE_koh").to_owned(), "connect".to_owned()];
                argv.extend(
                    remote
                        .dialing()
                        .into_iter()
                        .map(|a| a.to_string_lossy().into_owned()),
                );
                argv.push(remote.id.clone());
                argv.extend(pick.iter().map(|&a| a.to_owned()));
                argv
            };
            // Typed in the session it reaches, whose variable only it holds: what it answers says
            // which it is. Then left with the escape, detached.
            let session = |pick: &[&str], typed: &'static [u8], answer: &'static str| {
                let argv = connect(pick);
                async move {
                    let (mut client, seen, at) = connected(&argv, typed, answer).await?;
                    client.write(vec![0x1e, b'.'])?;
                    for _ in 0..100 {
                        if client.try_wait()?.is_some() {
                            return anyhow::Ok(());
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    anyhow::bail!("the client did not leave: {}", seen.text_from(at))
                }
            };
            session(&[], b"X=one; echo set_${X}_$((6*7))\r", "set_one_42")
                .await
                .expect("the first session");
            session(&["--new"], b"X=two; echo set_${X}_$((6*7))\r", "set_two_42")
                .await
                .expect("a new session");
            let out = remote
                .koh("sessions")
                .expect("koh")
                .arg(&remote.id)
                .output()
                .expect("sessions");
            let listed = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = listed.lines().collect();
            assert_eq!(lines.len(), 2, "{listed}");
            for (line, n) in lines.iter().zip(["1 ", "2 "]) {
                assert!(line.starts_with(n) && line.contains(" 80x24 "), "{listed}");
            }
            session(
                &["--session", "1"],
                b"echo got_${X}_$((6*7))\r",
                "got_one_42",
            )
            .await
            .expect("session 1");
            // The latest attached, though the other started after it.
            session(&[], b"echo got_${X}_$((6*7))\r", "got_one_42")
                .await
                .expect("the latest");
            // The last command's output, as the shell's marks place it; no command runs, so a
            // wait for its end ends at once, with the last one's status.
            let out = remote
                .run("output", &["--session", "1", "--last"])
                .expect("output");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                "got_one_42\n",
                "{out:?}"
            );
            let out = remote.run("wait", &["--session", "1"]).expect("wait");
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            let out = remote.run("sessions", &["--json"]).expect("sessions");
            let listed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
            assert_eq!(
                listed[0]["commands_finished"].as_u64().map(|n| n >= 2),
                Some(true),
                "{listed}"
            );
            // On a terminal, as connect needs one: the refusal is the server's.
            let (_client, seen) = on_pty(&connect(&["--session", "9"])).expect("connect");
            seen.wait_for(0, "no such session", 20)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        });
}
