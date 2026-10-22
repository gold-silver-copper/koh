use super::*;
use crate::names::tests::{id, Scratch};

/// The menu given `typed`, and what it chose and printed.
fn menu(places: &Places, typed: &str) -> (Choice, String) {
    let mut output = Vec::new();
    let choice = run(&mut typed.as_bytes(), &mut output, places).unwrap();
    (choice, String::from_utf8(output).unwrap())
}

fn saved(places: &Places, list: List) -> Vec<(String, EndpointId)> {
    names::load(places, list)
        .unwrap()
        .entries()
        .map(|entry| (entry.name.clone(), entry.id))
        .collect()
}

#[test]
fn q_or_the_end_of_input_quits_and_changes_nothing() {
    let dir = Scratch::new("quit");
    let places = dir.places();
    for typed in [
        "q\n",
        "",
        "a\n",
        "a\ns\n",
        "a\ns\nlaptop\n",
        "k\n",
        "k\nr\n",
    ] {
        assert_eq!(menu(&places, typed).0, Choice::Quit, "{typed:?}");
    }
    assert_eq!(saved(&places, List::Servers), []);
    assert!(!dir.0.join("servers").exists(), "nothing was written");
}

#[test]
fn the_overview_shows_both_keys_and_both_lists() {
    let dir = Scratch::new("overview");
    let places = dir.places();
    let client =
        crate::identity::load(&crate::identity::KeyFile::open(&places.client_key).unwrap())
            .unwrap()
            .public();
    names::update(&places, List::Servers, |n| {
        n.add("laptop", id(1), None, names::Scope::default())
    })
    .unwrap();
    let direct = Some(names::Route::Direct(([10, 0, 0, 2], 4433).into()));
    names::update(&places, List::Servers, |n| {
        n.add("desk", id(2), direct, names::Scope::default())
    })
    .unwrap();
    names::update(&places, List::Clients, |n| {
        n.add("phone", id(3), None, names::Scope::default())
    })
    .unwrap();
    let (_, shown) = menu(&places, "q\n");
    assert!(shown.contains(&names::short(client)), "{shown}");
    assert!(
        shown.contains("none yet (`koh serve` creates it)"),
        "{shown}"
    );
    assert!(shown.contains("1  laptop"), "{shown}");
    assert!(
        shown.contains("2  desk") && shown.contains("direct=10.0.0.2:4433"),
        "{shown}"
    );
    assert!(shown.contains("3  phone"), "{shown}");
    assert!(shown.contains("[1-3] pick"), "{shown}");
    // A key that is there but cannot be loaded says why, not "none yet".
    std::fs::write(&places.server_key, [7; 31]).unwrap();
    let (_, shown) = menu(&places, "q\n");
    assert!(
        shown.contains("cannot be loaded") && !shown.contains("none yet"),
        "{shown}"
    );
}

#[test]
fn one_entry_is_picked_as_1() {
    let dir = Scratch::new("one");
    let places = dir.places();
    names::update(&places, List::Clients, |n| {
        n.add("phone", id(3), None, names::Scope::default())
    })
    .unwrap();
    let (_, shown) = menu(&places, "q\n");
    assert!(
        shown.contains("1 pick") && !shown.contains("[1-1]"),
        "{shown}"
    );
}

#[test]
fn a_server_added_is_saved_and_connected_to() {
    let dir = Scratch::new("add-server");
    let places = dir.places();
    let typed = format!("a\ns\nlaptop\n{}\nc\n", id(1));
    let (choice, shown) = menu(&places, &typed);
    assert_eq!(choice, Choice::Connect("laptop".to_owned()), "{shown}");
    assert_eq!(
        saved(&places, List::Servers),
        [("laptop".to_owned(), id(1))]
    );
}

#[test]
fn with_several_servers_connect_asks_which() {
    let dir = Scratch::new("connect-which");
    let places = dir.places();
    names::update(&places, List::Servers, |n| {
        n.add("laptop", id(1), None, names::Scope::default())
    })
    .unwrap();
    names::update(&places, List::Servers, |n| {
        n.add("desk", id(2), None, names::Scope::default())
    })
    .unwrap();
    assert_eq!(
        menu(&places, "c\ndesk\n").0,
        Choice::Connect("desk".to_owned())
    );
    assert_eq!(
        menu(&places, "c\n1\n").0,
        Choice::Connect("laptop".to_owned())
    );
    assert_eq!(
        menu(&places, "2\nc\n").0,
        Choice::Connect("desk".to_owned())
    );
}

#[test]
fn serve_needs_a_client_first() {
    let dir = Scratch::new("serve");
    let places = dir.places();
    let (choice, shown) = menu(&places, "s\nq\n");
    assert_eq!(choice, Choice::Quit);
    assert!(shown.contains("no clients allowed yet"), "{shown}");
    let typed = format!("a\nc\nphone\n{}\ns\n", id(3));
    assert_eq!(menu(&places, &typed).0, Choice::Serve);
    assert_eq!(saved(&places, List::Clients), [("phone".to_owned(), id(3))]);
}

#[test]
fn a_bad_name_or_id_is_refused_and_nothing_saved() {
    let dir = Scratch::new("bad");
    let places = dir.places();
    let (_, shown) = menu(&places, "a\ns\nbad name\nq\n");
    assert!(shown.contains("is not a name"), "{shown}");
    let (_, shown) = menu(&places, "a\ns\nlaptop\nnot-an-id\nq\n");
    assert!(shown.contains("not an endpoint id"), "{shown}");
    assert_eq!(saved(&places, List::Servers), []);
}

#[test]
fn delete_asks_first() {
    let dir = Scratch::new("delete");
    let places = dir.places();
    names::update(&places, List::Servers, |n| {
        n.add("laptop", id(1), None, names::Scope::default())
    })
    .unwrap();
    let (_, shown) = menu(&places, "1\nd\nn\nq\n");
    assert!(
        shown.contains("delete server laptop? [y/N]") && shown.contains("kept"),
        "{shown}"
    );
    assert_eq!(saved(&places, List::Servers).len(), 1);
    menu(&places, "1\nd\ny\nq\n");
    assert_eq!(saved(&places, List::Servers), []);
}

#[test]
fn rename_and_show_the_full_id() {
    let dir = Scratch::new("rename");
    let places = dir.places();
    names::update(&places, List::Clients, |n| {
        n.add("phone", id(3), None, names::Scope::default())
    })
    .unwrap();
    let (_, shown) = menu(&places, "1\ni\n1\nr\ntablet\nq\n");
    assert!(shown.contains(&id(3).to_string()), "the full id: {shown}");
    assert_eq!(
        saved(&places, List::Clients),
        [("tablet".to_owned(), id(3))]
    );
}

#[test]
fn a_taken_name_is_refused_and_its_scope_kept() {
    let dir = Scratch::new("taken");
    let places = dir.places();
    let scope = names::Scope {
        cp: Some("/srv/drop".into()),
        exec: None,
    };
    names::update(&places, List::Clients, |n| {
        n.add("phone", id(1), None, scope.clone())
    })
    .unwrap();
    let typed = format!("a\nc\nphone\n{}\nq\n", id(2));
    let (_, shown) = menu(&places, &typed);
    assert!(shown.contains("already saved"), "{shown}");
    let saved = names::load(&places, List::Clients).unwrap();
    assert_eq!(
        saved.get("phone").map(|e| (e.id, &e.scope)),
        Some((id(1), &scope))
    );
}

#[test]
fn a_reset_says_who_loses_access_and_needs_the_keys_name_typed() {
    let dir = Scratch::new("reset");
    let places = dir.places();
    let key = crate::identity::KeyFile::open(&places.client_key).unwrap();
    drop(crate::identity::load(&key).unwrap());
    names::update(&places, List::Servers, |n| {
        n.add("laptop", id(1), None, names::Scope::default())
    })
    .unwrap();
    let (_, shown) = menu(&places, "k\nr\nclient\nyes\nq\n");
    assert!(
        shown.contains("servers that allow you now: laptop"),
        "{shown}"
    );
    assert!(shown.contains("kept"), "{shown}");
    assert!(
        places.client_key.exists(),
        "a reset not typed out keeps the key"
    );
    let (_, shown) = menu(&places, "k\nr\nclient\nclient\nq\n");
    assert!(shown.contains("removed the client key"), "{shown}");
    assert!(!places.client_key.exists());
}

#[test]
fn keys_show_each_id_in_full_with_a_qr_code() {
    let dir = Scratch::new("keys");
    let places = dir.places();
    let key = crate::identity::KeyFile::open(&places.client_key).unwrap();
    let client = crate::identity::load(&key).unwrap().public();
    let (_, shown) = menu(&places, "k\nb\nq\n");
    assert!(shown.contains(&client.to_string()), "{shown}");
    assert!(
        shown.contains('▀') || shown.contains('▄') || shown.contains('█'),
        "a QR code"
    );
    assert_eq!(
        crate::server::cli::connect_qr(&"x".repeat(10_000)),
        None,
        "too long for one"
    );
}
