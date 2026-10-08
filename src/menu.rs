//! The menu `koh` alone opens on a terminal: this machine's keys, the servers it connects to and
//! the clients allowed here, by name, and what can be done with each.
//!
//! It is line-based (a number or a letter, then Enter) rather than full-screen, so it works the same
//! in Termux, over adb, over ssh and in any terminal. It reads `input` and writes `output`, so tests
//! drive it as two byte streams; every action is the same function its command (`koh servers`,
//! `koh clients`, `koh key`) runs. End of input at any prompt leaves, changing nothing more.

use std::io::{BufRead, Write};
use std::time::SystemTime;

use iroh::EndpointId;

use crate::names::{self, List, Places};

/// What the user chose to do once the menu ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Nothing more: quit.
    Quit,
    /// `koh connect` to this server.
    Connect(EndpointId),
    /// `koh serve` for the saved clients.
    Serve,
}

/// Run the menu until the user quits, connects or serves.
pub fn run(
    input: &mut impl BufRead,
    output: &mut impl Write,
    places: &Places,
) -> anyhow::Result<Choice> {
    let mut menu = Menu {
        input,
        output,
        places,
    };
    menu.main()
}

struct Menu<'a, R, W> {
    input: &'a mut R,
    output: &'a mut W,
    places: &'a Places,
}

/// A saved entry the user can pick by number.
struct Picked {
    list: List,
    name: String,
    id: EndpointId,
}

impl<R: BufRead, W: Write> Menu<'_, R, W> {
    fn main(&mut self) -> anyhow::Result<Choice> {
        loop {
            let entries = self.overview()?;
            let Some(answer) = self.ask("> ")? else {
                return Ok(Choice::Quit);
            };
            let choice = match answer.as_str() {
                "q" => return Ok(Choice::Quit),
                "c" => self.connect(&entries)?,
                "s" => self.serve(&entries)?,
                "a" => self.add()?,
                "k" => self.keys()?,
                "" => None,
                number => match number.parse::<usize>().ok().and_then(|n| n.checked_sub(1)) {
                    Some(at) => match entries.get(at) {
                        Some(picked) => self.entry(picked)?,
                        None => self.say(&format!("there is no {number}"))?,
                    },
                    None => self.say(&format!("{number:?} is not a choice"))?,
                },
            };
            match choice {
                Some(Outcome::Choose(choice)) => return Ok(choice),
                Some(Outcome::Quit) => return Ok(Choice::Quit),
                None => {}
            }
        }
    }

    /// Print what this machine has, and return the entries by their numbers.
    fn overview(&mut self) -> anyhow::Result<Vec<Picked>> {
        writeln!(self.output, "\nkoh — this machine")?;
        for (role, label) in [("client", "you as a client"), ("server", "you as a server")] {
            let path = self.places.key(role).display().to_string();
            let id = key_id(self.places, role).map_or_else(
                || format!("none yet ({})", crate::keycmd::creates(role)),
                names::short,
            );
            writeln!(self.output, "  {label}   {id}   {path}")?;
        }
        let now = SystemTime::now();
        let mut entries = Vec::new();
        for (list, heading) in [
            (List::Servers, "servers you connect to"),
            (List::Clients, "clients allowed here"),
        ] {
            writeln!(self.output, "\n{heading}")?;
            let saved = match names::load(self.places, list) {
                Ok(saved) => saved,
                Err(error) => {
                    writeln!(self.output, "  (cannot read {}: {error:#})", list.file())?;
                    continue;
                }
            };
            if saved.is_empty() {
                writeln!(self.output, "  none yet — add one with a")?;
            }
            for (name, id) in saved.entries() {
                entries.push(Picked {
                    list,
                    name: name.to_owned(),
                    id,
                });
                let mut line = format!("  {}  {name:<10} {}", entries.len(), names::short(id));
                if list == List::Servers {
                    let seen = names::last_connected(&self.places.client_key, id).map_or_else(
                        || "never connected".to_owned(),
                        |then| format!("last connected {}", names::ago(then, now)),
                    );
                    line = format!("{line}   {seen}");
                }
                writeln!(self.output, "{line}")?;
            }
        }
        let pick = if entries.is_empty() {
            String::new()
        } else {
            format!("[1-{}] pick   ", entries.len())
        };
        writeln!(
            self.output,
            "\n{pick}c connect   s serve   a add   k keys   q quit"
        )?;
        Ok(entries)
    }

    /// `c`: connect to the one server saved, or to the one the user names.
    fn connect(&mut self, entries: &[Picked]) -> anyhow::Result<Option<Outcome>> {
        let servers: Vec<&Picked> = entries.iter().filter(|e| e.list == List::Servers).collect();
        let only = match servers.as_slice() {
            [] => return self.say("no servers saved yet: add one with a"),
            [only] => *only,
            _ => {
                let Some(answer) = self.ask("connect to which server (number or name)? ")? else {
                    return Ok(Some(Outcome::Quit));
                };
                let found = answer
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| n.checked_sub(1))
                    .and_then(|at| entries.get(at))
                    .filter(|e| e.list == List::Servers)
                    .or_else(|| servers.iter().copied().find(|e| e.name == answer));
                match found {
                    Some(found) => found,
                    None => return self.say(&format!("{answer:?} is not a saved server")),
                }
            }
        };
        Ok(Some(Outcome::Choose(Choice::Connect(only.id))))
    }

    /// `s`: serve the saved clients, if there are any.
    fn serve(&mut self, entries: &[Picked]) -> anyhow::Result<Option<Outcome>> {
        if entries.iter().any(|e| e.list == List::Clients) {
            Ok(Some(Outcome::Choose(Choice::Serve)))
        } else {
            self.say("no clients allowed yet: add one with a, then serve")
        }
    }

    /// A picked entry: what can be done with it.
    fn entry(&mut self, picked: &Picked) -> anyhow::Result<Option<Outcome>> {
        let noun = picked.list.noun();
        writeln!(
            self.output,
            "\n{noun} {}  {}",
            picked.name,
            names::short(picked.id)
        )?;
        let connect = if picked.list == List::Servers {
            "c connect   "
        } else {
            ""
        };
        writeln!(
            self.output,
            "  {connect}r rename   d delete   i show the full id   b back"
        )?;
        let Some(answer) = self.ask("> ")? else {
            return Ok(Some(Outcome::Quit));
        };
        match answer.as_str() {
            "c" if picked.list == List::Servers => {
                Ok(Some(Outcome::Choose(Choice::Connect(picked.id))))
            }
            "r" => {
                let Some(new) = self.ask(&format!("new name for {}: ", picked.name))? else {
                    return Ok(Some(Outcome::Quit));
                };
                let op = names::Op::Rename {
                    old: picked.name.clone(),
                    new,
                };
                self.act(picked.list, op)
            }
            "d" => {
                let question = format!("delete {noun} {}? [y/N] ", picked.name);
                match self.confirm(&question)? {
                    None => Ok(Some(Outcome::Quit)),
                    Some(false) => self.say("kept"),
                    Some(true) => self.act(
                        picked.list,
                        names::Op::Remove {
                            name: picked.name.clone(),
                        },
                    ),
                }
            }
            "i" => self.say(&picked.id.to_string()),
            _ => Ok(None),
        }
    }

    /// `a`: save a server or a client under a name.
    fn add(&mut self) -> anyhow::Result<Option<Outcome>> {
        let Some(kind) = self.ask("add a [s]erver you connect to, or a [c]lient allowed here? ")?
        else {
            return Ok(Some(Outcome::Quit));
        };
        let list = match kind.as_str() {
            "s" | "server" => List::Servers,
            "c" | "client" => List::Clients,
            _ => return Ok(None),
        };
        let Some(name) = self.ask("its name (a word, e.g. laptop): ")? else {
            return Ok(Some(Outcome::Quit));
        };
        if let Err(error) = names::check_name(&name) {
            return self.say(&format!("{error:#}"));
        }
        let hint = match list {
            List::Servers => {
                "on that machine, `koh key info server` prints it, as `koh serve` does"
            }
            List::Clients => "on that machine, `koh id` prints it",
        };
        writeln!(self.output, "  ({hint})")?;
        let Some(id) = self.ask("its endpoint id: ")? else {
            return Ok(Some(Outcome::Quit));
        };
        let id = match crate::transport_iroh::parse_endpoint_id(&id) {
            Ok(id) => id,
            Err(error) => return self.say(&format!("not an endpoint id: {error}")),
        };
        let saved = names::load(self.places, list)?;
        if let Some(old) = saved.get(&name) {
            let question = format!(
                "{name} is saved already, as {}; replace it? [y/N] ",
                names::short(old)
            );
            match self.confirm(&question)? {
                None => return Ok(Some(Outcome::Quit)),
                Some(false) => return self.say("kept"),
                Some(true) => {
                    let remove = names::Op::Remove { name: name.clone() };
                    if let Some(outcome) = self.act(list, remove)? {
                        return Ok(Some(outcome));
                    }
                }
            }
        }
        self.act(list, names::Op::Add { name, id })
    }

    /// `k`: both keys, in full and as QR codes, and resetting one.
    fn keys(&mut self) -> anyhow::Result<Option<Outcome>> {
        for role in ["client", "server"] {
            let path = self.places.key(role).display().to_string();
            writeln!(self.output, "\n{role} key   {path}")?;
            match key_id(self.places, role) {
                Some(id) => {
                    writeln!(self.output, "  id   {id}")?;
                    if let Some(qr) = crate::server::cli::connect_qr(&id.to_string()) {
                        writeln!(self.output, "{qr}")?;
                    }
                }
                None => writeln!(self.output, "  none yet ({})", crate::keycmd::creates(role))?,
            }
        }
        writeln!(self.output, "\n  r reset a key   b back")?;
        let Some(answer) = self.ask("> ")? else {
            return Ok(Some(Outcome::Quit));
        };
        if answer != "r" {
            return Ok(None);
        }
        let Some(role) = self.ask("reset which key, client or server? ")? else {
            return Ok(Some(Outcome::Quit));
        };
        let (role, list) = match role.as_str() {
            "client" => ("client", List::Servers),
            "server" => ("server", List::Clients),
            _ => return self.say("kept: neither client nor server"),
        };
        let affected: Vec<String> = names::load(self.places, list)
            .map(|saved| saved.entries().map(|(n, _)| n.to_owned()).collect())
            .unwrap_or_default();
        writeln!(
            self.output,
            "  resetting the {role} key deletes it; the next use makes a new id, so {}",
            crate::keycmd::who_loses_access(role)
        )?;
        if !affected.is_empty() {
            let whose = match list {
                List::Servers => "servers that allow you now",
                List::Clients => "clients that connect here now",
            };
            writeln!(self.output, "  {whose}: {}", affected.join(", "))?;
        }
        let Some(typed) = self.ask(&format!(
            "type {role} to reset it, anything else keeps it: "
        ))?
        else {
            return Ok(Some(Outcome::Quit));
        };
        if typed != role {
            return self.say("kept");
        }
        match crate::keycmd::reset(self.places.key(role)) {
            Ok(()) => self.say(&format!("removed the {role} key")),
            Err(error) => self.say(&format!("not reset: {error:#}")),
        }
    }

    /// Run `op` on `list` as its command does, and say what came of it.
    fn act(&mut self, list: List, op: names::Op) -> anyhow::Result<Option<Outcome>> {
        let mut said = Vec::new();
        match names::run(self.places, list, op, &mut said) {
            Ok(()) => {
                self.output.write_all(&said)?;
                Ok(None)
            }
            Err(error) => self.say(&format!("koh: {error:#}")),
        }
    }

    /// Ask `question`; `None` at the end of input.
    fn ask(&mut self, question: &str) -> anyhow::Result<Option<String>> {
        write!(self.output, "{question}")?;
        self.output.flush()?;
        let mut line = String::new();
        if self.input.read_line(&mut line)? == 0 {
            writeln!(self.output)?;
            return Ok(None);
        }
        Ok(Some(line.trim().to_owned()))
    }

    /// Ask a yes-or-no `question`, no unless `y`; `None` at the end of input.
    fn confirm(&mut self, question: &str) -> anyhow::Result<Option<bool>> {
        Ok(self
            .ask(question)?
            .map(|answer| matches!(answer.as_str(), "y" | "yes")))
    }

    fn say(&mut self, what: &str) -> anyhow::Result<Option<Outcome>> {
        writeln!(self.output, "  {what}")?;
        Ok(None)
    }
}

/// How an action ended the menu, if it did.
enum Outcome {
    Choose(Choice),
    /// The input ended mid-question.
    Quit,
}

/// The `role` key's endpoint id, if it exists (reading it creates nothing).
fn key_id(places: &Places, role: &str) -> Option<EndpointId> {
    crate::identity::load_existing(places.key(role))
        .ok()
        .map(|identity| identity.endpoint_id())
}

#[cfg(test)]
mod tests;
