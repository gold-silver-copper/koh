use super::*;
use std::os::unix::fs::PermissionsExt as _;

const A: &str = "d12841817cf7b0e8b357ae293f8a0c7d911d9661b06833a8365a1b3e7f83febf";

pub fn id(seed: u8) -> EndpointId {
    iroh::SecretKey::from_bytes(&[seed; 32]).public()
}

/// A key directory of its own, removed afterwards.
pub struct Scratch(pub koh_testkit::Scratch);

impl Scratch {
    pub fn new(tag: &str) -> Self {
        Self(crate::test_runtime::scratch(tag))
    }

    pub fn places(&self) -> Places {
        Places {
            client_key: self.0.join("client.key"),
            server_key: self.0.join("server.key"),
        }
    }
}

#[test]
fn a_list_round_trips_with_its_comments_and_blank_lines() {
    let text = format!(
        "# my machines\nlaptop {A}\n\n  # spare\ndesk {} direct=[::1]:4433\nfar {} relay=https://relay.example/\n",
        id(2),
        id(3)
    );
    let names = Names::parse(&text, "servers", List::Servers).unwrap();
    assert_eq!(names.render(), text);
    assert_eq!(
        names.get("desk").and_then(|entry| entry.route.clone()),
        Some(Route::Direct("[::1]:4433".parse().unwrap()))
    );
    assert_eq!(
        names.get("laptop").map(|entry| entry.id),
        Some(A.parse().unwrap())
    );
    assert_eq!(names.name_of(id(2)), Some("desk"));
    assert_eq!(names.entries().count(), 3);
}

#[test]
fn a_bad_line_is_an_error_that_names_the_file_and_the_line() {
    for (text, says) in [
        (format!("ok {A}\nlaptop\n"), "line 2"),
        (format!("ok {A}\nlaptop not-an-id\n"), "line 2"),
        (format!("# x\nbad/name {A}\n"), "line 2"),
        (format!("laptop {A} extra\n"), "line 1"),
        (format!("laptop {A}\nlaptop {}\n", id(3)), "named twice"),
        (format!("laptop {A} direct=nowhere\n"), "line 1"),
        (format!("laptop {A} via=1.2.3.4:5\n"), "line 1"),
        (format!("laptop {A} direct=1.2.3.4:5 extra\n"), "line 1"),
    ] {
        let error = Names::parse(&text, "/k/servers", List::Servers).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains(says), "{text:?}: {error}");
    }
    // Only a server is dialed, so only a server has a route.
    let client = format!("phone {A} direct=1.2.3.4:5\n");
    assert!(Names::parse(&client, "/k/clients", List::Clients).is_err());
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
    names.add("laptop", id(1), None, Scope::default()).unwrap();
    assert!(
        names.add("laptop", id(2), None, Scope::default()).is_err(),
        "a name taken"
    );
    assert!(
        names.add("other", id(1), None, Scope::default()).is_err(),
        "an id saved twice"
    );
    names.add("desk", id(2), None, Scope::default()).unwrap();
    assert!(
        names.rename("desk", "laptop").is_err(),
        "a rename onto a name"
    );
    names.rename("desk", "office").unwrap();
    assert_eq!(names.get("office").map(|entry| entry.id), Some(id(2)));
    assert_eq!(names.remove("laptop").unwrap(), id(1));
    let missing = format!("{:#}", names.remove("laptop").unwrap_err());
    assert!(missing.contains("office"), "lists what is saved: {missing}");
}

#[test]
fn a_missing_list_is_empty_and_a_saved_one_is_read_back() {
    let dir = Scratch::new("roundtrip");
    let places = dir.places();
    assert!(load(&places, List::Servers).unwrap().is_empty());
    update(&places, List::Servers, |names| {
        names.add("laptop", id(1), None, Scope::default())
    })
    .unwrap();
    update(&places, List::Clients, |names| {
        names.add("phone", id(2), None, Scope::default())
    })
    .unwrap();
    assert_eq!(
        load(&places, List::Servers)
            .unwrap()
            .get("laptop")
            .map(|entry| entry.id),
        Some(id(1))
    );
    assert_eq!(
        load(&places, List::Clients)
            .unwrap()
            .get("phone")
            .map(|entry| entry.id),
        Some(id(2))
    );
    let mode = std::fs::metadata(dir.0.join("servers"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "written private");
    // A failed change leaves the list as it was.
    assert!(update(&places, List::Servers, |names| names.add(
        "laptop",
        id(2),
        None,
        Scope::default()
    ))
    .is_err());
    assert_eq!(
        load(&places, List::Servers)
            .unwrap()
            .get("laptop")
            .map(|entry| entry.id),
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
    assert!(update(&places, List::Clients, |names| names.add(
        "x",
        id(1),
        None,
        Scope::default()
    ))
    .is_err());
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
        .map(|entry| entry.id)
        .is_some());
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn short_keeps_the_ends_of_an_id() {
    assert_eq!(short(A.parse().unwrap()), "d128…febf");
}
