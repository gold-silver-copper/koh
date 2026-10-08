use super::*;
use std::os::unix::fs::PermissionsExt as _;

const A: &str = "d12841817cf7b0e8b357ae293f8a0c7d911d9661b06833a8365a1b3e7f83febf";

fn id(seed: u8) -> EndpointId {
    iroh::SecretKey::from_bytes(&[seed; 32]).public()
}

/// A key directory of its own, removed afterwards.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "koh-names-{tag}-{}-{:016x}",
            std::process::id(),
            getrandom::u64().unwrap()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(dir)
    }

    fn places(&self) -> Places {
        Places {
            client_key: self.0.join("client.key"),
            server_key: self.0.join("server.key"),
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_list_round_trips_with_its_comments_and_blank_lines() {
    let text = format!("# my machines\nlaptop {A}\n\n  # spare\ndesk {}\n", id(2));
    let names = Names::parse(&text, "servers").unwrap();
    assert_eq!(names.render(), text);
    assert_eq!(names.get("laptop"), Some(A.parse().unwrap()));
    assert_eq!(names.name_of(id(2)), Some("desk"));
    assert_eq!(names.entries().count(), 2);
}

#[test]
fn a_bad_line_is_an_error_that_names_the_file_and_the_line() {
    for (text, says) in [
        (format!("ok {A}\nlaptop\n"), "line 2"),
        (format!("ok {A}\nlaptop not-an-id\n"), "line 2"),
        (format!("# x\nbad/name {A}\n"), "line 2"),
        (format!("laptop {A} extra\n"), "line 1"),
        (format!("laptop {A}\nlaptop {}\n", id(3)), "named twice"),
    ] {
        let error = Names::parse(&text, "/k/servers").unwrap_err();
        let error = format!("{error:#}");
        assert!(
            error.contains("/k/servers") || error.contains(says),
            "{error}"
        );
        assert!(error.contains(says), "{text:?}: {error}");
    }
}

#[test]
fn a_name_is_a_short_word_never_an_id_or_a_flag() {
    for good in ["laptop", "desk-2", "pi_4", "home.lan", "a"] {
        check_name(good).unwrap();
    }
    for bad in [
        "",
        "-x",
        "with space",
        "a/b",
        "ünï",
        A,
        &"x".repeat(MAX_NAME + 1),
    ] {
        assert!(check_name(bad).is_err(), "{bad:?} was taken as a name");
    }
}

#[test]
fn add_rm_and_rename_keep_names_and_ids_unique() {
    let mut names = Names::default();
    names.add("laptop", id(1)).unwrap();
    assert!(names.add("laptop", id(2)).is_err(), "a name taken");
    assert!(names.add("other", id(1)).is_err(), "an id saved twice");
    names.add("desk", id(2)).unwrap();
    assert!(
        names.rename("desk", "laptop").is_err(),
        "a rename onto a name"
    );
    names.rename("desk", "office").unwrap();
    assert_eq!(names.get("office"), Some(id(2)));
    assert_eq!(names.remove("laptop").unwrap(), id(1));
    let missing = format!("{:#}", names.remove("laptop").unwrap_err());
    assert!(missing.contains("office"), "lists what is saved: {missing}");
}

#[test]
fn a_missing_list_is_empty_and_a_saved_one_is_read_back() {
    let dir = Scratch::new("roundtrip");
    let places = dir.places();
    assert!(load(&places, List::Servers).unwrap().is_empty());
    update(&places, List::Servers, |names| names.add("laptop", id(1))).unwrap();
    update(&places, List::Clients, |names| names.add("phone", id(2))).unwrap();
    assert_eq!(
        load(&places, List::Servers).unwrap().get("laptop"),
        Some(id(1))
    );
    assert_eq!(
        load(&places, List::Clients).unwrap().get("phone"),
        Some(id(2))
    );
    let mode = std::fs::metadata(dir.0.join("servers"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "written private");
}

#[test]
fn a_failed_change_leaves_the_list_as_it_was() {
    let dir = Scratch::new("failed");
    let places = dir.places();
    update(&places, List::Servers, |names| names.add("laptop", id(1))).unwrap();
    assert!(update(&places, List::Servers, |names| names.add("laptop", id(2))).is_err());
    assert_eq!(
        load(&places, List::Servers).unwrap().get("laptop"),
        Some(id(1))
    );
}

#[test]
fn a_symlinked_list_is_refused_and_its_target_left_alone() {
    let dir = Scratch::new("symlink");
    let target = dir.0.join("elsewhere");
    std::fs::write(&target, format!("evil {A}\n")).unwrap();
    std::os::unix::fs::symlink(&target, dir.0.join("clients")).unwrap();
    let places = dir.places();
    assert!(
        load(&places, List::Clients).is_err(),
        "a symlinked clients file is not trusted"
    );
    assert!(update(&places, List::Clients, |names| names.add("x", id(1))).is_err());
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        format!("evil {A}\n")
    );
}

#[test]
fn a_loose_list_is_tightened() {
    let dir = Scratch::new("loose");
    let path = dir.0.join("clients");
    std::fs::write(&path, format!("phone {A}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(load(&dir.places(), List::Clients)
        .unwrap()
        .get("phone")
        .is_some());
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_list_another_user_owns_is_refused() {
    // Needs a file this user does not own: /etc/passwd is root's, unless we are root.
    if fuxix::process::geteuid() == 0 {
        return;
    }
    let dir = Scratch::new("foreign");
    let Ok(meta) = std::fs::metadata("/etc/passwd") else {
        return;
    };
    if std::os::unix::fs::MetadataExt::uid(&meta) != 0 {
        return;
    }
    // A hard link keeps the owner; it needs the same filesystem, so skip if it fails.
    if std::fs::hard_link("/etc/passwd", dir.0.join("clients")).is_err() {
        return;
    }
    let error = format!("{:#}", load(&dir.places(), List::Clients).unwrap_err());
    assert!(error.contains("owned by uid 0"), "{error}");
}

#[test]
fn a_connect_is_remembered_beside_the_client_key() {
    let dir = Scratch::new("connected");
    let places = dir.places();
    assert_eq!(last_connected(&places.client_key, id(1)), None);
    record_connected(&places.client_key, id(1)).unwrap();
    record_connected(&places.client_key, id(2)).unwrap();
    record_connected(&places.client_key, id(1)).unwrap();
    assert!(last_connected(&places.client_key, id(1)).is_some());
    let text = std::fs::read_to_string(dir.0.join("connected")).unwrap();
    assert_eq!(text.lines().count(), 2, "one line per server: {text}");
    assert!(!dir.0.join("servers").exists(), "the list is not rewritten");
}

#[test]
fn ago_says_how_long_ago_briefly() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let at = |secs| now - Duration::from_secs(secs);
    assert_eq!(ago(at(5), now), "just now");
    assert_eq!(ago(at(120), now), "2m ago");
    assert_eq!(ago(at(7200), now), "2h ago");
    assert_eq!(ago(at(3 * 86_400), now), "3d ago");
}

#[test]
fn short_keeps_the_ends_of_an_id() {
    let s = short(A.parse().unwrap());
    let full = A.parse::<EndpointId>().unwrap().to_string();
    let head: String = full.chars().take(4).collect();
    let tail: String = full.chars().skip(full.chars().count() - 4).collect();
    assert_eq!(s, format!("{head}…{tail}"));
}
