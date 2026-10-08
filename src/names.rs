//! Names for endpoint ids, kept beside the keys.
//!
//! `servers`, the servers this machine connects to, sits beside the client key; `clients`, the
//! clients allowed to connect to it, beside the server key. Each line is `name id`; `#` lines and
//! blank lines are kept as they are. Both files go through [`KeyFile`]'s rules, as the key does:
//! `clients` decides who may open a shell here.
//!
//! When each server was last reached is kept apart, in `connected` beside the client key (`id
//! seconds` lines), so a connect never rewrites the list the user edits.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use iroh::EndpointId;

use crate::identity::KeyFile;
use crate::transport_iroh::parse_endpoint_id;

/// Most bytes in a name.
pub const MAX_NAME: usize = 32;

/// Which list of names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum List {
    /// The servers this machine connects to (`koh connect <name>`).
    Servers,
    /// The clients allowed to connect to this machine (`koh serve`).
    Clients,
}

impl List {
    /// The list's file, beside its key.
    pub fn file(self) -> &'static str {
        match self {
            Self::Servers => "servers",
            Self::Clients => "clients",
        }
    }

    /// The key the list sits beside: a machine's servers are its client key's, its clients its
    /// server key's.
    pub fn role(self) -> &'static str {
        match self {
            Self::Servers => "client",
            Self::Clients => "server",
        }
    }

    /// One entry of the list, for messages.
    pub fn noun(self) -> &'static str {
        match self {
            Self::Servers => "server",
            Self::Clients => "client",
        }
    }
}

/// Where this machine's keys are, and so its lists.
#[derive(Debug, Clone)]
pub struct Places {
    pub client_key: PathBuf,
    pub server_key: PathBuf,
}

impl Places {
    /// The given key paths, or the default ones.
    pub fn new(client_key: Option<PathBuf>, server_key: Option<PathBuf>) -> anyhow::Result<Self> {
        Ok(Self {
            client_key: KeyFile::path_for(client_key, "client")?,
            server_key: KeyFile::path_for(server_key, "server")?,
        })
    }

    /// The key path for `role` (`"client"` or `"server"`).
    pub fn key(&self, role: &str) -> &Path {
        if role == "server" {
            &self.server_key
        } else {
            &self.client_key
        }
    }

    fn key_file(&self, list: List) -> anyhow::Result<KeyFile> {
        KeyFile::open(self.key(list.role()))
    }
}

/// A list of names, with the comments and blank lines it was read with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names {
    lines: Vec<Line>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Entry {
        name: String,
        id: EndpointId,
    },
    /// A comment or a blank line, kept as written.
    Other(String),
}

impl Names {
    /// Parse `text`, the contents of `file` (for errors). A line that is neither a comment, blank,
    /// nor `name id` with a good name and id is an error naming the file and the line.
    pub fn parse(text: &str, file: &str) -> anyhow::Result<Self> {
        let mut names = Self::default();
        for (number, line) in (1_usize..).zip(text.lines()) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                names.lines.push(Line::Other(line.to_owned()));
                continue;
            }
            let at = || format!("{file}, line {number}");
            let mut words = trimmed.split_whitespace();
            let (Some(name), Some(id), None) = (words.next(), words.next(), words.next()) else {
                anyhow::bail!("{}: expected `name id`, found {trimmed:?}", at());
            };
            check_name(name).with_context(at)?;
            let id = parse_endpoint_id(id).with_context(at)?;
            if names.get(name).is_some() {
                anyhow::bail!("{}: {name:?} is named twice", at());
            }
            names.lines.push(Line::Entry {
                name: name.to_owned(),
                id,
            });
        }
        Ok(names)
    }

    /// The list as its file holds it.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut text = String::new();
        for line in &self.lines {
            let _ = match line {
                Line::Entry { name, id } => writeln!(text, "{name} {id}"),
                Line::Other(other) => writeln!(text, "{other}"),
            };
        }
        text
    }

    /// Every name and its id, in the file's order.
    pub fn entries(&self) -> impl Iterator<Item = (&str, EndpointId)> {
        self.lines.iter().filter_map(|line| match line {
            Line::Entry { name, id } => Some((name.as_str(), *id)),
            Line::Other(_) => None,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.entries().next().is_none()
    }

    /// The id saved under `name`.
    pub fn get(&self, name: &str) -> Option<EndpointId> {
        self.entries().find(|(n, _)| *n == name).map(|(_, id)| id)
    }

    /// The name `id` is saved under.
    pub fn name_of(&self, id: EndpointId) -> Option<&str> {
        self.entries().find(|(_, i)| *i == id).map(|(n, _)| n)
    }

    /// Save `id` as `name`: refused if the name is taken or the id is saved under another name.
    pub fn add(&mut self, name: &str, id: EndpointId) -> anyhow::Result<()> {
        check_name(name)?;
        if self.get(name).is_some() {
            anyhow::bail!("{name:?} is already saved; remove or rename it first");
        }
        if let Some(other) = self.name_of(id) {
            anyhow::bail!("{id} is already saved as {other:?}");
        }
        self.lines.push(Line::Entry {
            name: name.to_owned(),
            id,
        });
        Ok(())
    }

    /// Forget `name`, and return its id.
    pub fn remove(&mut self, name: &str) -> anyhow::Result<EndpointId> {
        let id = self.get(name).with_context(|| self.unknown(name))?;
        self.lines
            .retain(|line| !matches!(line, Line::Entry { name: n, .. } if n == name));
        Ok(id)
    }

    /// Save `old`'s id as `new` instead.
    pub fn rename(&mut self, old: &str, new: &str) -> anyhow::Result<()> {
        check_name(new)?;
        if self.get(new).is_some() {
            anyhow::bail!("{new:?} is already saved");
        }
        let unknown = self.unknown(old);
        let entry = self
            .lines
            .iter_mut()
            .find_map(|line| match line {
                Line::Entry { name, .. } if name == old => Some(name),
                Line::Entry { .. } | Line::Other(_) => None,
            })
            .context(unknown)?;
        new.clone_into(entry);
        Ok(())
    }

    /// The error for a name that is not saved, listing those that are.
    fn unknown(&self, name: &str) -> String {
        let saved: Vec<&str> = self.entries().map(|(n, _)| n).collect();
        if saved.is_empty() {
            format!("{name:?} is not saved, and nothing is")
        } else {
            format!("{name:?} is not saved; saved: {}", saved.join(", "))
        }
    }
}

/// A name: 1 to [`MAX_NAME`] letters, digits, `-`, `_` or `.`, not starting with `-` (it would read
/// as a flag), and never something that reads as an endpoint id.
pub fn check_name(name: &str) -> anyhow::Result<()> {
    let good = !name.is_empty()
        && name.len() <= MAX_NAME
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    anyhow::ensure!(
        good,
        "{name:?} is not a name: use 1 to {MAX_NAME} letters, digits, '-', '_' or '.', not \
         starting with '-'"
    );
    anyhow::ensure!(
        parse_endpoint_id(name).is_err(),
        "{name:?} reads as an endpoint id, so it cannot be a name"
    );
    Ok(())
}

/// `id` shortened for a list: its first and last four characters.
pub fn short(id: EndpointId) -> String {
    let id = id.to_string();
    let head: String = id.chars().take(4).collect();
    let tail: String = id
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}…{tail}")
}

/// The list `list`, empty if its file does not exist.
pub fn load(places: &Places, list: List) -> anyhow::Result<Names> {
    let key = places.key_file(list)?;
    let text = key.read_beside(list.file())?;
    Names::parse(text.as_deref().unwrap_or(""), &shown(places, list))
}

/// Change the list `list` with `change`, which sees it as it is on disk now; another koh's change
/// made meanwhile is never lost, as the directory is locked throughout. What `change` returns is
/// returned.
pub fn update<T>(
    places: &Places,
    list: List,
    change: impl FnOnce(&mut Names) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let key = places.key_file(list)?;
    let file = shown(places, list);
    let mut out = None;
    key.update_beside(list.file(), |text| {
        let mut names = Names::parse(text.as_deref().unwrap_or(""), &file)?;
        out = Some(change(&mut names)?);
        Ok(Some(names.render()))
    })?;
    out.context("internal error: the list was not changed")
}

/// What `koh servers` or `koh clients` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Print the list, one `name id` a line.
    List,
    Add {
        name: String,
        id: EndpointId,
    },
    Remove {
        name: String,
    },
    Rename {
        old: String,
        new: String,
    },
}

/// Run `koh servers` or `koh clients`, saying what was done to `out`.
pub fn run(
    places: &Places,
    list: List,
    op: Op,
    out: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let file = shown(places, list);
    match op {
        Op::List => {
            let names = load(places, list)?;
            if names.is_empty() {
                writeln!(
                    out,
                    "no {}s saved in {file}; add one with `koh {} add <name> <id>`",
                    list.noun(),
                    list.file()
                )?;
            }
            for (name, id) in names.entries() {
                writeln!(out, "{name} {id}")?;
            }
        }
        Op::Add { name, id } => {
            update(places, list, |names| names.add(&name, id))?;
            writeln!(
                out,
                "saved {} {name} ({}) in {file}",
                list.noun(),
                short(id)
            )?;
        }
        Op::Remove { name } => {
            let id = update(places, list, |names| names.remove(&name))?;
            writeln!(
                out,
                "removed {} {name} ({}) from {file}",
                list.noun(),
                short(id)
            )?;
        }
        Op::Rename { old, new } => {
            update(places, list, |names| names.rename(&old, &new))?;
            writeln!(out, "renamed {} {old} to {new} in {file}", list.noun())?;
        }
    }
    Ok(())
}

/// The list's path, for messages.
pub fn shown(places: &Places, list: List) -> String {
    places
        .key(list.role())
        .with_file_name(list.file())
        .display()
        .to_string()
}

/// The file of when each server was last reached, beside the client key.
const CONNECTED: &str = "connected";

/// Note that `server` was reached now. A failure is the caller's to report, not to stop on.
pub fn record_connected(client_key: &Path, server: EndpointId) -> anyhow::Result<()> {
    let key = KeyFile::open(client_key)?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    key.update_beside(CONNECTED, |text| {
        let mut lines: Vec<String> = text
            .as_deref()
            .unwrap_or("")
            .lines()
            .filter(|line| !line.starts_with(&server.to_string()))
            .map(str::to_owned)
            .collect();
        lines.push(format!("{server} {now}"));
        let mut out = lines.join("\n");
        out.push('\n');
        Ok(Some(out))
    })
}

/// When `server` was last reached, if it ever was. The file is koh's own state, so a line it cannot
/// read is skipped rather than refused.
pub fn last_connected(client_key: &Path, server: EndpointId) -> Option<SystemTime> {
    let key = KeyFile::open(client_key).ok()?;
    let text = key.read_beside(CONNECTED).ok().flatten()?;
    let server = server.to_string();
    text.lines().rev().find_map(|line| {
        let (id, secs) = line.split_once(' ')?;
        (id == server).then_some(())?;
        let secs = secs.trim().parse::<u64>().ok()?;
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
    })
}

/// How long ago `then` was, briefly: "2h ago".
pub fn ago(then: SystemTime, now: SystemTime) -> String {
    let secs = now.duration_since(then).map_or(0, |d| d.as_secs());
    let (amount, unit) = match secs {
        0..=59 => return "just now".to_owned(),
        60..=3599 => (secs.checked_div(60).unwrap_or(0), "m"),
        3600..=86_399 => (secs.checked_div(3600).unwrap_or(0), "h"),
        _ => (secs.checked_div(86_400).unwrap_or(0), "d"),
    };
    format!("{amount}{unit} ago")
}

#[cfg(test)]
mod tests;
