// Transport fault verification belongs to koh, the remote transport owner.
#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]

#[test]
fn deterministic_transport_fault_matrix_converges_and_preserves_divergent_input() {
    use koh::input::{UserInput, WireEvent};
    use koh::ssp::testkit::{GridState, LinkParams, SimHarness};
    use koh::ssp::SyncState as _;

    let combined = LinkParams {
        loss: 0.30,
        min_delay_ms: 1,
        max_delay_ms: 150,
        dup: 0.10,
    };
    let mut observed_all_faults = false;
    for seed in 1..=1024 {
        let mut link = koh::ssp::testkit::Link::default();
        let mut rng = koh::ssp::testkit::Rng::new(seed);
        for id in 0_u8..64 {
            link.push(&mut rng, 0, &combined, vec![id]);
        }
        let delivered = link.due(150);
        let unique = delivered.iter().collect::<std::collections::BTreeSet<_>>();
        let duplicated = unique.iter().any(|value| {
            delivered
                .iter()
                .filter(|candidate| candidate == value)
                .count()
                > 1
        });
        let reordered = delivered.windows(2).any(|pair| {
            pair.first()
                .is_some_and(|left| pair.get(1).is_some_and(|right| left > right))
        });
        if unique.len() < 64 && duplicated && reordered {
            observed_all_faults = true;
            break;
        }
    }
    assert!(
        observed_all_faults,
        "combined deterministic link trace must contain loss, duplication, and reordering"
    );

    let mut harness = SimHarness::<GridState, GridState>::new(combined, 44, 256);
    for generation in 0_u32..64 {
        harness.a_mut().cells.insert(
            generation % 7,
            format!("combined:{generation:02}").into_bytes(),
        );
        harness.a_mut().echo_ack = u64::from(generation);
        harness.run_steps(2);
    }
    let authoritative = harness.a.current().clone();
    harness.run_until(50_000, |state| state.b.remote_state() == &authoritative);
    assert_eq!(harness.b.remote_state(), &authoritative);

    let mut target = UserInput::default();
    target.push_bytes(b"abd");
    let mut divergent = UserInput::default();
    divergent.push_bytes(b"abc");
    assert_eq!(
        target.diff_from(&divergent),
        vec![WireEvent::Keys(b"d".to_vec())]
    );
    target.subtract_prefix(&divergent);
    assert_eq!(
        target.events(),
        &[koh::input::InputEvent::Byte(b'd')],
        "divergent prefix subtraction must retain the exact divergent byte"
    );
}

#[derive(Clone, Copy)]
enum TransportFault {
    Lose,
    Duplicate,
    Reorder,
    Reconnect,
}

#[test]
fn individual_transport_faults_exercise_delivery_and_reconstruction() {
    for fault in [
        TransportFault::Lose,
        TransportFault::Duplicate,
        TransportFault::Reorder,
        TransportFault::Reconnect,
    ] {
        exercise_transport_fault(fault).expect("transport fault contract");
    }
}

fn exercise_transport_fault(fault: TransportFault) -> Result<(), String> {
    use koh::ssp::testkit::{GridState, Link, LinkParams, Rng, SimHarness};

    match fault {
        TransportFault::Lose => {
            let mut link = Link::default();
            link.push(
                &mut Rng::new(1),
                0,
                &LinkParams {
                    loss: 1.0,
                    min_delay_ms: 0,
                    max_delay_ms: 0,
                    dup: 0.0,
                },
                b"lost".to_vec(),
            );
            if link.next_due().is_some() || !link.due(u64::MAX).is_empty() {
                return Err("Koh loss seam delivered a dropped datagram".into());
            }
        }
        TransportFault::Duplicate => {
            let mut link = Link::default();
            link.push(
                &mut Rng::new(2),
                0,
                &LinkParams {
                    loss: 0.0,
                    min_delay_ms: 1,
                    max_delay_ms: 1,
                    dup: 1.0,
                },
                b"duplicate".to_vec(),
            );
            if link.due(1) != [b"duplicate".to_vec(), b"duplicate".to_vec()] {
                return Err("Koh duplication seam did not deliver two exact datagrams".into());
            }
        }
        TransportFault::Reorder => {
            let params = LinkParams {
                loss: 0.0,
                min_delay_ms: 0,
                max_delay_ms: 100,
                dup: 0.0,
            };
            let reordered = (1..=1024).any(|seed| {
                let mut link = Link::default();
                let mut rng = Rng::new(seed);
                link.push(&mut rng, 0, &params, b"first".to_vec());
                link.push(&mut rng, 0, &params, b"second".to_vec());
                link.due(100) == [b"second".to_vec(), b"first".to_vec()]
            });
            if !reordered {
                return Err("Koh reorder seam produced no deterministic inversion".into());
            }
            let mut sender = koh::ssp::Transport::<GridState, GridState>::new(0, 128);
            let mut receiver = koh::ssp::Transport::<GridState, GridState>::new(0, 128);
            sender.set_connected(true);
            receiver.set_connected(true);
            let mut rng = Rng::new(99);
            let payload = (0..4096)
                .map(|_| rng.next_u64().to_le_bytes()[0])
                .collect::<Vec<_>>();
            sender.current_mut().cells.insert(7, payload);
            let mut fragments = sender.tick(0);
            if fragments.len() <= 1 {
                return Err("Koh reorder row did not force a fragmented instruction".into());
            }
            fragments.reverse();
            for fragment in fragments {
                receiver.recv(1, &fragment);
            }
            if receiver.remote_state() != sender.current() {
                return Err("Koh reversed fragments did not reconstruct exact state".into());
            }
        }
        TransportFault::Reconnect => {
            let mut harness = SimHarness::<GridState, GridState>::new(
                LinkParams {
                    loss: 0.30,
                    min_delay_ms: 1,
                    max_delay_ms: 100,
                    dup: 0.10,
                },
                44,
                256,
            );
            harness.a.set_connected(false);
            harness.b.set_connected(false);
            harness
                .a_mut()
                .cells
                .insert(1, b"authoritative-after-loss".to_vec());
            let expected = harness.a.current().clone();
            harness.run_steps(32);
            if harness.b.remote_state() == &expected {
                return Err("Koh disconnected transport delivered outage state".into());
            }
            harness.a.set_connected(true);
            harness.b.set_connected(true);
            harness.run_until(50_000, |state| state.b.remote_state() == &expected);
            if harness.b.remote_state() != &expected {
                return Err("Koh reconnect seam did not converge".into());
            }
        }
    }
    Ok(())
}
