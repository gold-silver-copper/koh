//! A side: `koh-oracle-side` built at one tree, kept running and given one case after another.
//! A side that fails, or takes longer than [`TIMEOUT`] over a case, is restarted for the next.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use crate::case::Case;

/// The longest a side may take over one case.
const TIMEOUT: Duration = Duration::from_secs(120);

pub struct Side {
    pub name: &'static str,
    binary: PathBuf,
    running: Option<Running>,
}

struct Running {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<std::io::Result<String>>,
}

impl Side {
    pub const fn new(name: &'static str, binary: PathBuf) -> Self {
        Self {
            name,
            binary,
            running: None,
        }
    }

    fn start(&self) -> Result<Running, String> {
        let mut child = Command::new(&self.binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{}: {e}", self.binary.display()))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Running {
            child,
            stdin,
            lines,
        })
    }

    /// Run `case`: the lines the side printed for it, up to its `end`.
    pub fn run(&mut self, case: &Case) -> Result<Vec<String>, String> {
        let result = self.attempt(case);
        if result.is_err() {
            if let Some(mut running) = self.running.take() {
                let _ = running.child.kill();
                let _ = running.child.wait();
            }
        }
        result
    }

    fn attempt(&mut self, case: &Case) -> Result<Vec<String>, String> {
        if self.running.is_none() {
            self.running = Some(self.start()?);
        }
        let running = self.running.as_mut().ok_or("not running")?;
        let mut text = case.text();
        text.push_str("end\n");
        // Written from a thread of its own, so a side that prints much before it has read the
        // whole case cannot block on a full pipe while the driver blocks on writing.
        let mut stdin = running
            .stdin
            .try_clone_for_writer()
            .ok_or("cannot write to the side")?;
        let writer = std::thread::spawn(move || stdin.write_all(text.as_bytes()));
        let mut lines = Vec::new();
        let outcome = loop {
            match running.lines.recv_timeout(TIMEOUT) {
                Ok(Ok(line)) if line == "end" => break Ok(()),
                Ok(Ok(line)) => lines.push(line),
                Ok(Err(e)) => break Err(format!("{}: reading: {e}", self.name)),
                Err(RecvTimeoutError::Timeout) => {
                    break Err(format!("{}: no answer in {TIMEOUT:?}", self.name))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let mut stderr = String::new();
                    if let Some(mut err) = running.child.stderr.take() {
                        let _ = std::io::Read::read_to_string(&mut err, &mut stderr);
                    }
                    break Err(format!("{} failed: {}", self.name, stderr.trim()));
                }
            }
        };
        let written = writer
            .join()
            .map_err(|_panic| "the writer panicked".to_owned())?;
        outcome?;
        written.map_err(|e| format!("{}: writing: {e}", self.name))?;
        Ok(lines)
    }
}

/// A second handle to a child's stdin, for the writer thread.
trait CloneForWriter {
    fn try_clone_for_writer(&self) -> Option<std::fs::File>;
}

impl CloneForWriter for ChildStdin {
    fn try_clone_for_writer(&self) -> Option<std::fs::File> {
        use std::os::fd::AsFd;
        self.as_fd()
            .try_clone_to_owned()
            .ok()
            .map(std::fs::File::from)
    }
}
