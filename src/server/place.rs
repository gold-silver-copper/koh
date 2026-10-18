//! Where a request's paths are: as the server user's shell takes them, or, for a scoped key,
//! beneath the directory its scope names and nowhere else.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};

use crate::request::{Problem, ProblemKind, RemotePath};
use crate::sync::Name;

/// Where a request's paths are.
#[derive(Clone, Debug)]
pub(super) struct Place {
    /// The server user's home, if they have one.
    home: Option<PathBuf>,
    /// The directory a scoped key's paths stay in.
    root: Option<PathBuf>,
}

/// A path resolved: as the system finds it, or beneath a scoped key's directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Resolved {
    Path(PathBuf),
    Beneath { root: PathBuf, path: Vec<Name> },
}

impl Resolved {
    /// The path, as the system finds it: for a scoped key's, after its directory.
    pub(super) fn path(&self) -> PathBuf {
        match self {
            Self::Path(path) => path.clone(),
            Self::Beneath { root, path } => path.iter().fold(root.clone(), |at, name| {
                at.join(OsStr::from_bytes(name.as_bytes()))
            }),
        }
    }
}

impl Place {
    pub(super) const fn new(home: Option<PathBuf>, root: Option<PathBuf>) -> Self {
        Self { home, root }
    }

    /// The directory commands start in when none is asked: the scope's, else the home.
    pub(super) fn start(&self) -> Option<&Path> {
        self.root.as_deref().or(self.home.as_deref())
    }

    /// Where `path` is: as the server user's shell reads it (`~` and `~/…` in their home, a
    /// relative path in it, an absolute one as it is); for a scoped key, from its directory, with
    /// no `..`, `~` or absolute path reaching out of it.
    pub(super) fn resolve(&self, path: &RemotePath) -> Result<Resolved, Problem> {
        let bytes = path.as_bytes();
        let os = |bytes| Path::new(OsStr::from_bytes(bytes));
        let Some(root) = &self.root else {
            if bytes.starts_with(b"/") {
                return Ok(Resolved::Path(os(bytes).to_path_buf()));
            }
            let in_home = match bytes {
                b"" | b"~" => b"",
                _ => bytes.strip_prefix(b"~/").unwrap_or(bytes),
            };
            let home = self
                .home
                .as_deref()
                .ok_or_else(|| Problem::new(ProblemKind::NoHome, os(bytes).display()))?;
            return Ok(Resolved::Path(if in_home.is_empty() {
                home.to_path_buf()
            } else {
                home.join(os(in_home))
            }));
        };
        let out = || Problem::new(ProblemKind::OutOfScope, os(bytes).display());
        let rel = if bytes.starts_with(b"/") {
            os(bytes).strip_prefix(root).map_err(|_outside| out())?
        } else if bytes.starts_with(b"~") {
            return Err(out());
        } else {
            os(bytes)
        };
        let path: Option<Vec<Name>> = rel
            .components()
            .filter(|c| *c != Component::CurDir)
            .map(|c| match c {
                Component::Normal(name) => Name::new(name.as_bytes().to_vec()).ok(),
                Component::ParentDir
                | Component::RootDir
                | Component::Prefix(_)
                | Component::CurDir => None,
            })
            .collect();
        Ok(Resolved::Beneath {
            root: root.clone(),
            path: path.ok_or_else(out)?,
        })
    }

    /// The directory `cwd` names for a command to start in (or the default), which, for a scoped
    /// key, is in its directory as the system finds it, symlinks followed.
    pub(super) fn cwd(&self, cwd: Option<&RemotePath>) -> Result<Option<PathBuf>, Problem> {
        let Some(cwd) = cwd else {
            return Ok(self.start().map(Path::to_path_buf));
        };
        let dir = self.resolve(cwd)?.path();
        if let Some(root) = &self.root {
            let real = std::fs::canonicalize(&dir).map_err(|e| {
                Problem::new(ProblemKind::NotFound, format!("{}: {e}", dir.display()))
            })?;
            let real_root = std::fs::canonicalize(root).map_err(|e| {
                Problem::new(ProblemKind::NotFound, format!("{}: {e}", root.display()))
            })?;
            if !real.starts_with(&real_root) {
                return Err(Problem::new(ProblemKind::OutOfScope, dir.display()));
            }
        }
        Ok(Some(dir))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(p: &[u8]) -> RemotePath {
        RemotePath::new(p.to_vec()).unwrap()
    }

    #[test]
    fn a_path_resolves_as_the_users_shell_takes_it() {
        let place = Place::new(Some("/home/u".into()), None);
        let at = |p: &[u8]| place.resolve(&path(p)).unwrap().path();
        assert_eq!(at(b""), Path::new("/home/u"));
        assert_eq!(at(b"~"), Path::new("/home/u"));
        assert_eq!(at(b"~/a b"), Path::new("/home/u/a b"));
        assert_eq!(at(b"x/y"), Path::new("/home/u/x/y"));
        assert_eq!(at(b"/etc/hosts"), Path::new("/etc/hosts"));
        // `~name` is no home of anyone's here: a name in the user's home.
        assert_eq!(at(b"~other"), Path::new("/home/u/~other"));
        let homeless = Place::new(None, None).resolve(&path(b"~/x"));
        assert_eq!(homeless.unwrap_err().kind, ProblemKind::NoHome);
    }

    #[test]
    fn a_scoped_keys_paths_stay_in_its_directory() {
        let place = Place::new(Some("/home/u".into()), Some("/srv/drop".into()));
        let name = |n: &str| Name::new(n.as_bytes().to_vec()).unwrap();
        let beneath = |names: &[&str]| Resolved::Beneath {
            root: "/srv/drop".into(),
            path: names.iter().map(|n| name(n)).collect(),
        };
        assert_eq!(place.resolve(&path(b"")).unwrap(), beneath(&[]));
        assert_eq!(
            place.resolve(&path(b"a/./b")).unwrap(),
            beneath(&["a", "b"])
        );
        assert_eq!(
            place.resolve(&path(b"/srv/drop/a")).unwrap(),
            beneath(&["a"])
        );
        for outside in [
            &b"../x"[..],
            b"a/../../x",
            b"/etc/passwd",
            b"~/x",
            b"~",
            b"/srv/dropped",
        ] {
            let refused = place.resolve(&path(outside)).unwrap_err();
            assert_eq!(refused.kind, ProblemKind::OutOfScope, "{outside:?}");
        }
    }
}
