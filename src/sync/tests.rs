use super::*;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// Copy `sources` to `dest` under `opts`, the two ends on threads of their own joined as the
/// streams join them, the sender's bytes cut after `cut` if given: the receiver's outcome.
fn copy_with(
    sources: &[Source],
    dest: &Dest,
    opts: &Opts,
    cut: Option<usize>,
) -> Result<Summary, Failure> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(PIPE_DEPTH);
    let (cut_tx, cut_rx) = mpsc::channel::<Vec<u8>>(PIPE_DEPTH);
    let (reply_tx, reply_rx) = mpsc::channel::<Reply>(REPLY_DEPTH);
    let count = sources.len();
    let sources = sources.to_vec();
    let send_opts = opts.clone();
    let sender = std::thread::spawn(move || send(&sources, &send_opts, tx, reply_rx));
    // What the sender writes, cut short if asked.
    let pipe = std::thread::spawn(move || {
        let mut passed = 0_usize;
        while let Some(chunk) = rx.blocking_recv() {
            let room = cut.map_or(chunk.len(), |cut| {
                cut.saturating_sub(passed).min(chunk.len())
            });
            if room > 0 && cut_tx.blocking_send(chunk[..room].to_vec()).is_err() {
                return;
            }
            passed = passed.saturating_add(chunk.len());
            if cut.is_some_and(|cut| passed >= cut) {
                return;
            }
        }
    });
    let outcome = Target::resolve(dest, count, opts.dry_run).and_then(|(target, made)| {
        let summary = receive(ChannelReader::new(cut_rx), target, opts, &reply_tx);
        let _ = reply_tx.try_send(Reply::End(summary.clone()));
        summary.map(|mut s| {
            s.dirs = s.dirs.saturating_add(made);
            s
        })
    });
    drop(reply_tx);
    if pipe.join().is_err() || sender.join().is_err() {
        let panicked = Path::new("a copy's thread panicked");
        return Err(Failure::new(FailKind::Other, panicked));
    }
    outcome
}

fn copy(sources: &[&Path], dest: &Path, opts: &Opts) -> Result<Summary, Failure> {
    let sources: Vec<Source> = sources
        .iter()
        .map(|p| Source::Path(p.to_path_buf()))
        .collect();
    copy_with(&sources, &Dest::Path(dest.to_path_buf()), opts, None)
}

/// What is in `dir`, recursively: each entry's relative path, kind, mode and contents (a file's
/// bytes, a symlink's target), sorted.
fn tree(dir: &Path) -> Vec<(PathBuf, char, u32, Vec<u8>)> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<(PathBuf, char, u32, Vec<u8>)>) {
        for entry in fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            let meta = fs::symlink_metadata(&path).unwrap();
            let mode = meta.mode() & 0o7777;
            if meta.is_symlink() {
                use std::os::unix::ffi::OsStringExt as _;
                let target = fs::read_link(&path).unwrap().into_os_string().into_vec();
                out.push((rel, 'l', 0, target));
            } else if meta.is_dir() {
                out.push((rel, 'd', mode, Vec::new()));
                walk(root, &path, out);
            } else {
                out.push((rel, 'f', mode, fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// A tree with a mode, an odd name, a symlink, an empty file and one past a chunk.
fn sample(root: &Path) -> PathBuf {
    let top = root.join("top dir");
    fs::create_dir_all(top.join("sub")).unwrap();
    let odd = std::ffi::OsStr::from_bytes(if cfg!(target_os = "macos") {
        b"line\nbreak \xc3\xa9 name"
    } else {
        b"line\nbreak \xff name"
    });
    fs::write(top.join(odd), b"odd").unwrap();
    fs::write(top.join("sub/big"), vec![7u8; CHUNK * 2 + 5]).unwrap();
    fs::write(top.join("empty"), b"").unwrap();
    fs::set_permissions(top.join("empty"), fs::Permissions::from_mode(0o751)).unwrap();
    std::os::unix::fs::symlink("sub/big", top.join("link")).unwrap();
    top
}

fn mtime(path: &Path) -> (i64, i64) {
    let meta = fs::metadata(path).unwrap();
    (meta.mtime(), meta.mtime_nsec())
}

/// Set `path`'s modification time to `secs` (a file's or a directory's), and say it.
fn filetime(path: &Path, secs: u64) -> (i64, i64) {
    let at = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(secs));
    fs::File::open(path)
        .unwrap()
        .set_modified(at.unwrap())
        .unwrap();
    mtime(path)
}

fn excluding(pattern: &str) -> glob::Excludes {
    let pattern = glob::Pattern::new(pattern.as_bytes().to_vec()).unwrap();
    glob::Excludes::new(vec![pattern]).unwrap()
}

#[test]
fn a_tree_lands_then_only_what_changed_is_sent_and_gets_its_arrival_time() {
    let scratch = crate::test_runtime::scratch("sync-again");
    let top = sample(&scratch.join("from"));
    let into = scratch.join("into");
    let first = copy(&[&top], &into.join("x/"), &Opts::default()).unwrap();
    let landed = into.join("x/top dir");
    assert_eq!(tree(&landed), tree(&top));
    assert_eq!((first.new, first.links, first.dirs), (3, 1, 4), "{first:?}");
    // The source's time was not kept: a copy is new where it lands.
    let old = filetime(&top.join("sub/big"), 1_000_000);
    assert_ne!(mtime(&landed.join("sub/big")), old);
    // Again: nothing is sent, and nothing it did not send is touched.
    let before = mtime(&landed.join("sub/big"));
    let again = copy(&[&top], &into.join("x/"), &Opts::default()).unwrap();
    assert_eq!(
        (again.written(), again.unchanged, again.bytes),
        (0, 3, 0),
        "{again:?}"
    );
    assert_eq!(mtime(&landed.join("sub/big")), before);
    // A file edited before the last copy landed (an older time than the copy's) is sent, and
    // lands newer than the copy before: a build there sees it changed (K1).
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(top.join("sub/big"), vec![8u8; CHUNK * 2 + 5]).unwrap();
    filetime(&top.join("sub/big"), 1_000_000);
    let edited = copy(&[&top], &into.join("x/"), &Opts::default()).unwrap();
    assert_eq!((edited.replaced, edited.unchanged), (1, 2), "{edited:?}");
    assert!(mtime(&landed.join("sub/big")) > before);
    // With -p, the source's times, the unchanged files' too.
    let kept = Opts {
        keep_times: true,
        ..Opts::default()
    };
    copy(&[&top], &into.join("x/"), &kept).unwrap();
    assert_eq!(mtime(&landed.join("sub/big")).0, 1_000_000);
    // A setuid or setgid program lands as a plain one.
    fs::set_permissions(top.join("empty"), fs::Permissions::from_mode(0o6755)).unwrap();
    copy(&[&top], &into.join("x/"), &Opts::default()).unwrap();
    let mode = fs::metadata(landed.join("empty")).unwrap().mode() & 0o7777;
    assert_eq!(mode, 0o755);
}

#[test]
fn a_tree_merges_into_one_there_and_delete_and_exclude_say_what_goes() {
    let scratch = crate::test_runtime::scratch("sync-merge");
    let src = scratch.join("src");
    fs::create_dir_all(src.join("a")).unwrap();
    fs::write(src.join("a/one"), b"1").unwrap();
    fs::write(src.join("keep.o"), b"o").unwrap();
    let dest = scratch.join("dest/src");
    fs::create_dir_all(dest.join("a")).unwrap();
    fs::write(dest.join("a/theirs"), b"t").unwrap();
    fs::write(dest.join("cache.o"), b"c").unwrap();
    // Merged: what was there stays, without --delete.
    let merged = copy(&[&src], &scratch.join("dest"), &Opts::default()).unwrap();
    assert_eq!(merged.new, 2, "{merged:?}");
    assert!(dest.join("a/theirs").exists() && dest.join("a/one").exists());
    // With --delete, what the source lacks goes, but what is excluded stays and is not sent.
    let opts = Opts {
        delete: true,
        excludes: excluding("*.o"),
        ..Opts::default()
    };
    fs::remove_file(src.join("keep.o")).unwrap();
    let pruned = copy(&[&src], &scratch.join("dest"), &opts).unwrap();
    assert_eq!(pruned.deleted, 1, "{pruned:?}");
    assert!(!dest.join("a/theirs").exists());
    assert!(dest.join("cache.o").exists() && dest.join("keep.o").exists());
    // What is in a directory (`dir/.`) lands in the destination itself.
    let flat = scratch.join("flat");
    copy(&[&src.join(".")], &flat, &Opts::default()).unwrap();
    assert!(flat.join("a/one").exists());
    // A file into a missing directory: its parents are made.
    copy(
        &[&src.join("a/one")],
        &scratch.join("p/q/r/one"),
        &Opts::default(),
    )
    .unwrap();
    assert_eq!(fs::read(scratch.join("p/q/r/one")).unwrap(), b"1");
}

/// A pattern with a `/` matches the same path at both ends, from the top of the tree copied:
/// what it names is neither sent nor removed, however deep and wherever the tree lands.
#[test]
fn delete_spares_what_a_path_pattern_excludes() {
    let scratch = crate::test_runtime::scratch("sync-exclude-path");
    let src = scratch.join("src");
    fs::create_dir_all(src.join("a/b")).unwrap();
    fs::write(src.join("a/b/ours"), b"o").unwrap();
    fs::write(src.join("a/one"), b"1").unwrap();
    let opts = Opts {
        delete: true,
        excludes: excluding("a/b/*"),
        ..Opts::default()
    };
    // The tree into a directory, as its own name; and its contents into one.
    for (source, dest, landed) in [
        (src.clone(), scratch.join("into/"), scratch.join("into/src")),
        (src.join("."), scratch.join("flat"), scratch.join("flat")),
    ] {
        fs::create_dir_all(landed.join("a/b")).unwrap();
        fs::write(landed.join("a/b/theirs"), b"t").unwrap();
        fs::write(landed.join("a/stray"), b"s").unwrap();
        let done = copy(&[&source], &dest, &opts).unwrap();
        assert_eq!((done.new, done.deleted), (1, 1), "{dest:?}: {done:?}");
        assert!(landed.join("a/b/theirs").exists(), "{dest:?}");
        assert!(!landed.join("a/b/ours").exists(), "{dest:?}");
        assert!(!landed.join("a/stray").exists(), "{dest:?}");
    }
}

/// A read-only directory gets its mode, and with -p its time, once its files landed: the end of
/// a directory comes before the bytes of its last window of files.
#[test]
fn a_read_only_directory_lands_whole() {
    let scratch = crate::test_runtime::scratch("sync-read-only");
    let src = scratch.join("src");
    fs::create_dir_all(src.join("ro/inner")).unwrap();
    for n in 0..WINDOW * 2 {
        fs::write(src.join(format!("ro/f{n}")), b"f").unwrap();
    }
    fs::write(src.join("ro/inner/last"), b"l").unwrap();
    for dir in ["ro/inner", "ro"] {
        fs::set_permissions(src.join(dir), fs::Permissions::from_mode(0o555)).unwrap();
        filetime(&src.join(dir), 1_000_000);
    }
    let dest = scratch.join("dest");
    let opts = Opts {
        keep_times: true,
        ..Opts::default()
    };
    let done = copy(&[&src.join(".")], &dest, &opts);
    let again = copy(&[&src.join(".")], &dest, &opts);
    let landed = (tree(&dest), mtime(&dest.join("ro")).0);
    for at in [&src, &dest] {
        for dir in ["ro", "ro/inner"] {
            let _ = fs::set_permissions(at.join(dir), fs::Permissions::from_mode(0o755));
        }
    }
    let files = u64::try_from(WINDOW * 2 + 1).unwrap();
    assert_eq!(done.unwrap().new, files);
    assert_eq!(again.unwrap().unchanged, files);
    let mut want = tree(&src);
    for entry in &mut want {
        if entry.1 == 'd' {
            entry.2 = 0o555;
        }
    }
    assert_eq!(landed, (want, 1_000_000));
}

#[test]
fn a_copy_cut_anywhere_leaves_whole_files_and_the_next_one_resumes() {
    let scratch = crate::test_runtime::scratch("sync-cut");
    let src = scratch.join("src");
    fs::create_dir_all(&src).unwrap();
    let big: Vec<u8> = (0..CHUNK * 5)
        .map(|n| u8::try_from(n % 251).unwrap())
        .collect();
    fs::write(src.join("big"), &big).unwrap();
    fs::write(src.join("small"), b"small").unwrap();
    let source = [Source::Path(src)];
    for cut in [10, 300, CHUNK, CHUNK * 3 + 77] {
        let dest = scratch.join(format!("cut-{cut}/"));
        let failed = copy_with(
            &source,
            &Dest::Path(dest.clone()),
            &Opts::default(),
            Some(cut),
        );
        assert_eq!(
            failed.unwrap_err().kind,
            FailKind::Truncated,
            "cut at {cut}"
        );
        // Whatever landed is whole.
        for (name, want) in [("big", &big[..]), ("small", &b"small"[..])] {
            if let Ok(got) = fs::read(dest.join("src").join(name)) {
                assert_eq!(got, want, "{name} cut at {cut}");
            }
        }
        // Run again: it all lands, the big file from where the cut left it.
        let resumed =
            copy_with(&source, &Dest::Path(dest.clone()), &Opts::default(), None).unwrap();
        assert_eq!(fs::read(dest.join("src/big")).unwrap(), big, "cut at {cut}");
        let names: Vec<_> = fs::read_dir(dest.join("src"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "no part left: {names:?}");
        if cut > CHUNK * 2 {
            assert_eq!(resumed.resumed, 1, "cut at {cut}: {resumed:?}");
            assert!(
                resumed.bytes < u64::try_from(big.len()).unwrap(),
                "{resumed:?}"
            );
        }
    }
}

#[test]
fn nothing_lands_through_a_symlink_or_outside_a_scoped_directory() {
    let scratch = crate::test_runtime::scratch("sync-symlink");
    let src = scratch.join("src");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::write(src.join("d/f"), b"f").unwrap();
    let outside = scratch.join("outside");
    fs::create_dir_all(&outside).unwrap();
    // Where the source has a directory, the destination has a symlink to elsewhere.
    let dest = scratch.join("dest/src");
    fs::create_dir_all(&dest).unwrap();
    std::os::unix::fs::symlink(&outside, dest.join("d")).unwrap();
    let refused = copy(&[&src], &scratch.join("dest"), &Opts::default()).unwrap_err();
    assert_eq!(refused.kind, FailKind::IsASymlink);
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    // Beneath a scoped directory, a symlinked part of the destination is not followed either.
    let root = scratch.join("root");
    fs::create_dir_all(&root).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    let name = |n: &str| Name::new(n.as_bytes().to_vec()).unwrap();
    let dest = Dest::Beneath {
        root,
        path: vec![name("link"), name("x")],
        dir: true,
    };
    let refused = copy_with(
        &[Source::Path(src.join("d/f"))],
        &dest,
        &Opts::default(),
        None,
    );
    assert!(refused.is_err());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    // Built by hand past the constructor, a name that reaches out is refused as it is decoded.
    for bad in [&b""[..], b".", b"..", b"a/b", b"a\0"] {
        assert!(Name::new(bad.to_vec()).is_err(), "{bad:?}");
    }
}

/// A dry run changes nothing and sends no file's bytes, and says what the copy would do: the
/// same counts the copy then makes, and each change.
#[test]
fn a_dry_run_says_what_the_copy_would_do_and_changes_nothing() {
    let scratch = crate::test_runtime::scratch("sync-dry");
    let src = scratch.join("src");
    fs::create_dir_all(src.join("new_dir")).unwrap();
    fs::write(src.join("same"), b"same").unwrap();
    fs::write(src.join("edited"), b"edit").unwrap();
    fs::write(src.join("grown"), b"grown longer").unwrap();
    fs::write(src.join("new_dir/fresh"), b"fresh").unwrap();
    std::os::unix::fs::symlink("same", src.join("link")).unwrap();
    let dest = scratch.join("dest");
    copy(&[&src.join(".")], &dest, &Opts::default()).unwrap();
    fs::remove_dir_all(dest.join("new_dir")).unwrap();
    fs::remove_file(dest.join("link")).unwrap();
    fs::write(dest.join("edited"), b"EDIT").unwrap();
    fs::write(dest.join("grown"), b"short").unwrap();
    fs::write(dest.join("stale"), b"x").unwrap();
    let before = tree(&dest);
    let opts = |dry_run| Opts {
        delete: true,
        dry_run,
        ..Opts::default()
    };
    let dry = copy(&[&src.join(".")], &dest, &opts(true)).unwrap();
    assert_eq!(tree(&dest), before, "a dry run changed the destination");
    let said: Vec<(&str, ChangeKind)> = dry
        .changes
        .iter()
        .map(|c| (c.path.as_str(), c.kind))
        .collect();
    assert_eq!(
        said,
        [
            ("edited", ChangeKind::Replaced),
            ("grown", ChangeKind::Replaced),
            ("link", ChangeKind::Link),
            ("new_dir", ChangeKind::Dir),
            ("new_dir/fresh", ChangeKind::New),
            ("stale", ChangeKind::Deleted),
        ],
        "{dry:?}"
    );
    // What it said is what the copy does.
    let done = copy(&[&src.join(".")], &dest, &opts(false)).unwrap();
    let counts = |s: &Summary| {
        (
            s.new,
            s.replaced,
            s.unchanged,
            s.deleted,
            s.dirs,
            s.links,
            s.bytes,
        )
    };
    assert_eq!(counts(&dry), counts(&done), "{dry:?} {done:?}");
    assert_eq!(done.changes, []);
    // Into a destination that is not there, beneath a scoped key's directory too: nothing made.
    for (missing, dirs) in [("gone/deeper/", 4), ("gone/deeper", 3)] {
        let dry = copy(&[&src], &scratch.join(missing), &opts(true)).unwrap();
        assert_eq!((dry.new, dry.dirs), (4, dirs), "{missing}: {dry:?}");
    }
    let name = |n: &str| Name::new(n.as_bytes().to_vec()).unwrap();
    let beneath = Dest::Beneath {
        root: scratch.to_path_buf(),
        path: vec![name("gone"), name("deeper")],
        dir: true,
    };
    let dry = copy_with(&[Source::Path(src)], &beneath, &opts(true), None).unwrap();
    assert_eq!((dry.new, dry.dirs), (4, 4), "{dry:?}");
    assert!(!scratch.join("gone").exists());
}
