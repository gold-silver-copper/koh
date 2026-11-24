//! A koh server and its clients on the fault link.
//!
//! The server is `koh serve`'s own (`start_server`) and a client is `koh mount`'s own
//! (`Client::mount`), both in this process, each on an endpoint whose only transport is the
//! link. A session is a pane started as `koh serve` starts one, by the real binary (`koh fux
//! start` in the sessions' folder): its holder is a real `koh hold`, and the server finds it
//! by its name. A mirror is a real folder that the test reads and types into.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iroh::EndpointId;
use koh::client::{Client, ConnectOptions};
use koh::keys::{Role, load_or_create_key};
use koh::server::{RunningServer, ServeOptions, start_server};

use crate::net::{FaultNet, Profile};

pub struct Rig {
    pub net: FaultNet,
    pub server_id: EndpointId,
    sessions: PathBuf,
    tmp: PathBuf,
    _server: RunningServer,
}

impl Drop for Rig {
    fn drop(&mut self) {
        // (The holders are processes of their own: they are ended with the test.)
        for pane in fs::read_dir(&self.sessions).into_iter().flatten().flatten() {
            let status = fs::read_to_string(pane.path().join("status")).unwrap_or_default();
            if let Some(holder) = status
                .lines()
                .next()
                .and_then(|l| l.strip_prefix("holder "))
            {
                let _ = Command::new("kill").args(["-KILL", holder]).status();
            }
        }
        let _ = fs::remove_dir_all(&self.tmp);
    }
}

impl Rig {
    /// A server on a link of `profile`, seeded.
    pub async fn start(tag: &str, profile: Profile, seed: u64) -> Rig {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let name = format!("koh-link-{tag}-{}-{}", std::process::id(), nanos.as_nanos());
        let tmp = std::env::temp_dir().join(name);
        fs::create_dir_all(&tmp).unwrap();
        let tmp = fs::canonicalize(tmp).unwrap();
        let net = FaultNet::new(profile, seed);
        let key_file = tmp.join("srv_cfg/server.key");
        let secret = load_or_create_key(Role::Server, Some(&key_file)).unwrap();
        let server_id = secret.public();
        let server = start_server(ServeOptions {
            key_file: Some(key_file),
            allow: vec![Self::key(&tmp, "a").public(), Self::key(&tmp, "b").public()],
            shell: Some("/bin/sh".into()),
            state_dir: Some(tmp.join("state")),
            endpoint: Some(net.endpoint(secret, true).await),
            quiet: true,
            ..ServeOptions::default()
        })
        .await
        .unwrap();
        Rig {
            net,
            server_id,
            sessions: tmp.join("state/fux/koh-sessions"),
            tmp,
            _server: server,
        }
    }

    fn key(tmp: &Path, who: &str) -> iroh::SecretKey {
        let file = tmp.join(who).join("client.key");
        load_or_create_key(Role::Client, Some(&file)).unwrap()
    }

    /// A file of the test's own.
    pub fn file(&self, name: &str) -> PathBuf {
        self.tmp.join(name)
    }

    /// Starts the session `name` running `program`, 80 by 24, as the server starts one, and
    /// gives its folder.
    pub fn pane(&self, name: &str, program: &[&str]) -> PathBuf {
        let pane = self.sessions.join(name);
        let mut start = Command::new(env!("CARGO_BIN_EXE_koh"));
        start
            .args(["fux", "start"])
            .arg(&pane)
            .arg("--")
            .args(program);
        start
            .env("COLUMNS", "80")
            .env("LINES", "24")
            .env("XDG_RUNTIME_DIR", self.tmp.join("run"))
            .env("HOME", &self.tmp)
            // (A shell that ends with the test writes no history into a folder that is going.)
            .env("HISTFILE", "/dev/null")
            .current_dir(&self.tmp)
            .stdin(std::process::Stdio::null());
        let said = start.output().unwrap();
        assert!(
            said.status.success(),
            "{}",
            String::from_utf8_lossy(&said.stderr)
        );
        pane
    }

    /// `koh mount` of the session `name` by the client `who` ("a" or "b"): its mirror.
    pub async fn mount_now(&self, name: &str, who: &str) -> Mount {
        let secret = Self::key(&self.tmp, who);
        let id = secret.public();
        let endpoint = self.net.endpoint(secret.clone(), false).await;
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let root = self.tmp.join(format!("{who}-{}", nanos.as_nanos()));
        fs::create_dir_all(root.join("ws")).unwrap();
        let dir = root.join("ws/m");
        let client = Client::connect_on(secret, endpoint, FaultNet::addr(self.server_id));
        let client = client.await.unwrap();
        let asks = ConnectOptions {
            session: Some(name.into()),
            ..ConnectOptions::default()
        };
        let task = tokio::spawn(client.mount(asks, Some(dir.clone()), "server"));
        Mount { dir, id, task }
    }

    pub async fn mount(&self, name: &str, who: &str) -> Mount {
        let mount = self.mount_now(name, who).await;
        mount.has_a_round(Duration::from_secs(20));
        mount
    }
}

/// A `koh mount` in this process, and its mirror. It is stopped when the test lets go of it.
pub struct Mount {
    pub dir: PathBuf,
    /// The client's endpoint: what the link counts towards it is what the server sent.
    pub id: EndpointId,
    task: tokio::task::JoinHandle<koh::Result<i32>>,
}

impl Drop for Mount {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Mount {
    /// Waits until the mirror has its first whole round: until then there is nothing to show.
    pub fn has_a_round(&self, long: Duration) {
        until("the mirror has a round", long, || {
            self.dir.join("generation").is_file() || self.task.is_finished()
        });
        assert!(!self.task.is_finished(), "koh mount ended");
    }

    /// Writes to the mirror's `in`, as a viewer of it would type.
    pub fn types(&self, bytes: &[u8]) {
        let mut keys = fs::OpenOptions::new().write(true).open(self.dir.join("in"));
        keys.as_mut().unwrap().write_all(bytes).unwrap();
    }
}

/// A program for a session that takes what is typed as it is typed, into the file `out`: it
/// says READY once its terminal is raw, and then reads.
pub fn reads_into(out: &Path) -> [&str; 4] {
    let script = "stty raw -echo; echo READY; exec cat > \"$0\"";
    ["sh", "-c", script, out.to_str().unwrap()]
}

/// Waits, `long` at most, until `done` says so.
pub fn until(what: &str, long: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + long;
    while !done() {
        assert!(Instant::now() < deadline, "not in {long:?}: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The screen a pane's folder, or a mirror, shows.
pub fn screen(dir: &Path) -> String {
    fs::read_to_string(dir.join("shown/screen")).unwrap_or_default()
}

/// What a pane's folder holds that a mirror of it holds too (as `tests/e2e.rs` has it): all
/// but `generation`, the two names that are not carried and names with a dot first. A file by
/// its length and its hash, a link by where it leads.
fn held(dir: &Path) -> BTreeMap<String, String> {
    let (mut held, mut folders) = (BTreeMap::new(), vec![String::new()]);
    while let Some(folder) = folders.pop() {
        let entries = fs::read_dir(dir.join(&folder)).into_iter().flatten();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let own = ["generation", "status", "command"].contains(&name.as_str());
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if name.starts_with('.') || (folder.is_empty() && own) {
                continue;
            }
            let (path, name) = (entry.path(), format!("{folder}{name}"));
            let what = if kind.is_symlink() {
                format!("to {}", fs::read_link(&path).unwrap_or_default().display())
            } else if kind.is_dir() {
                folders.push(format!("{name}/"));
                "a folder".to_string()
            } else if kind.is_file() {
                let bytes = fs::read(&path).unwrap_or_default();
                format!("{} bytes {}", bytes.len(), blake3::hash(&bytes).to_hex())
            } else {
                "a FIFO".to_string()
            };
            held.insert(name, what);
        }
    }
    held
}

/// Waits, twenty seconds at most, until a mirror is its pane: the same names, each the same
/// thing, and an even number.
pub fn agrees(pane: &Path, mirror: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let (theirs, ours) = (held(pane), held(mirror));
        let number = fs::read_to_string(mirror.join("generation")).unwrap_or_default();
        let even = number.trim().parse::<u64>().is_ok_and(|n| n % 2 == 0);
        if theirs == ours && even && !ours.is_empty() {
            return;
        }
        let differ = |(name, what): (&String, &String)| ours.get(name) != Some(what);
        let differ: Vec<_> = theirs
            .iter()
            .filter(|at| differ(*at))
            .map(|at| at.0)
            .collect();
        let over: Vec<_> = ours
            .keys()
            .filter(|name| !theirs.contains_key(*name))
            .collect();
        assert!(
            Instant::now() < deadline,
            "the mirror is not the pane: {differ:?} differ, {over:?} are left over, generation {number:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The numbered line `n` of sixteen bytes, as a test types them.
pub fn line(n: u64) -> Vec<u8> {
    format!("{n:015}\n").into_bytes()
}

/// The last `n` bytes of a file.
pub fn tail(path: &Path, n: u64) -> Vec<u8> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let Ok(mut file) = fs::File::open(path) else {
        return Vec::new();
    };
    let len = file.metadata().map_or(0, |file| file.len());
    let _ = file.seek(SeekFrom::Start(len.saturating_sub(n)));
    let mut end = Vec::new();
    let _ = file.read_to_end(&mut end);
    end
}

/// What was read of numbered lines of 16 bytes that were typed (line N at byte 16 N), as
/// `tests/e2e.rs` has it: how many stretches of them are left out, or where a byte came twice
/// or out of its order.
pub fn stretches(read: &[u8], typed: &[u8]) -> Result<usize, String> {
    let (mut at, mut i, mut left_out) = (0, 0, 0);
    while i < read.len() {
        // Where what was read from here on is in what was typed: by the first whole line in it.
        let rest = &read[i..];
        let newline = rest.iter().position(|byte| *byte == b'\n');
        let before = newline.map_or(rest.len(), |end| end + 1);
        let line = rest.get(before..before + 15);
        let place = match line.map(|line| String::from_utf8_lossy(line).parse::<usize>()) {
            Some(Ok(line)) => (line * 16)
                .checked_sub(before)
                .ok_or(format!("byte {i}: before the first line"))?,
            // (The last bytes, with no whole line among them: the end of what was typed.)
            _ => typed
                .len()
                .checked_sub(rest.len())
                .ok_or(format!("byte {i}: more than was typed"))?,
        };
        if place < at {
            return Err(format!(
                "byte {i} of what was read was typed at {place}: before {at}, which was read already"
            ));
        }
        left_out += usize::from(place > at);
        let same = rest.iter().zip(&typed[place..]);
        let same = same.take_while(|(read, typed)| read == typed).count();
        if same == 0 {
            return Err(format!(
                "byte {i} of what was read is not what was typed at {place}"
            ));
        }
        (i, at) = (i + same, place + same);
    }
    Ok(left_out)
}

/// A test's own draws from its seed (splitmix64): when a link goes, and for how long.
pub struct Draws(pub u64);

impl Draws {
    /// A number below `n`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)) % n
    }
}
