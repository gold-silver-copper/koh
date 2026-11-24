//! The link itself: each fault does what its name says, counted on packets of the test's own,
//! with no endpoint and no QUIC between.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::{EndpointId, SecretKey};
use tokio::time::Instant;

use crate::net::{Counts, FaultNet, Packet, Profile};

fn id(n: u8) -> EndpointId {
    SecretKey::from_bytes(&[n; 32]).public()
}

/// When each packet came, by its number, in the order they came.
type Came = Arc<Mutex<Vec<(u32, Instant)>>>;

fn number(packet: &Packet) -> u32 {
    u32::from_be_bytes(packet.data[..4].try_into().unwrap())
}

/// Two places on a link of `profile`: packets go from the first to the second, where a task
/// of its own notes each as it comes.
fn link(profile: Profile, seed: u64) -> (FaultNet, Came) {
    let net = FaultNet::new(profile, seed);
    let _back = net.join(id(1));
    let mut packets = net.join(id(2));
    let came = Came::default();
    let notes = came.clone();
    tokio::spawn(async move {
        while let Some(packet) = packets.recv().await {
            notes
                .lock()
                .unwrap()
                .push((number(&packet), Instant::now()));
        }
    });
    (net, came)
}

/// Sends the packet numbered `n`, of `len` bytes.
fn send(net: &FaultNet, n: u32, len: usize) {
    let mut packet = vec![0u8; len.max(4)];
    packet[..4].copy_from_slice(&n.to_be_bytes());
    net.route(id(1), id(2), &packet).unwrap();
}

/// What has come once nothing more does for a while.
async fn arrived(came: &Came) -> Vec<(u32, Instant)> {
    loop {
        let so_far = came.lock().unwrap().len();
        tokio::time::sleep(QUIET).await;
        let came = came.lock().unwrap();
        if came.len() == so_far {
            return came.clone();
        }
    }
}

fn numbers(came: &[(u32, Instant)]) -> Vec<u32> {
    came.iter().map(|(n, _)| *n).collect()
}

const QUIET: Duration = Duration::from_millis(300);

#[tokio::test]
async fn a_clean_link_delivers_every_packet_once_in_order_at_once() {
    let net = FaultNet::new(Profile::default(), 1);
    let (_back, mut packets) = (net.join(id(1)), net.join(id(2)));
    (0..1000).for_each(|n| send(&net, n, 1200));
    // (At once: they are there before anything is waited for.)
    let came = std::iter::from_fn(|| packets.try_recv().ok());
    let came: Vec<u32> = came.map(|packet| number(&packet)).collect();
    assert_eq!(came, (0..1000).collect::<Vec<_>>());
    let counts = Counts {
        sent: 1000,
        delivered: 1000,
        bytes: 1_200_000,
        ..Counts::default()
    };
    assert_eq!(net.counts(id(2)), counts);
    assert_eq!(net.counts(id(1)), Counts::default());
}

#[tokio::test]
async fn loss_loses_its_share_and_the_same_packets_for_the_same_seed() {
    let profile = Profile {
        loss: 0.05,
        ..Profile::default()
    };
    let mut runs = Vec::new();
    for seed in [7, 7, 8] {
        let (net, came) = link(profile.clone(), seed);
        (0..8000).for_each(|n| send(&net, n, 100));
        let came = numbers(&arrived(&came).await);
        let counts = net.counts(id(2));
        // Five in a hundred, give or take; what is not lost arrives once, in order.
        assert!((320..=480).contains(&counts.lost), "{counts:?}");
        assert_eq!(counts.delivered, 8000 - counts.lost);
        assert_eq!(came.len() as u64, counts.delivered);
        assert!(came.is_sorted_by(|a, b| a < b));
        runs.push(came);
    }
    assert_eq!(runs[0], runs[1], "one seed, one fate");
    assert_ne!(runs[0], runs[2], "another seed, another");
}

#[tokio::test]
async fn delay_holds_every_packet_that_long_and_keeps_the_order() {
    let delay = Duration::from_millis(25);
    let profile = Profile {
        delay,
        ..Profile::default()
    };
    let (net, came) = link(profile, 1);
    let mut sent = Vec::new();
    for n in 0..200 {
        sent.push(Instant::now());
        send(&net, n, 100);
        if n % 20 == 19 {
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
    }
    let came = arrived(&came).await;
    assert_eq!(numbers(&came), (0..200).collect::<Vec<_>>());
    for (n, at) in came {
        let took = at - sent[n as usize];
        // (Never early; and late by no more than a loaded machine's timers are.)
        assert!(took >= delay, "packet {n} took {took:?}");
        assert!(
            took < delay + Duration::from_millis(250),
            "packet {n} took {took:?}"
        );
    }
}

#[tokio::test]
async fn jitter_varies_the_delay_and_no_packet_overtakes_another() {
    let (delay, jitter) = (Duration::from_millis(40), Duration::from_millis(30));
    let profile = Profile {
        delay,
        jitter,
        ..Profile::default()
    };
    let (net, came) = link(profile, 3);
    let mut sent = Vec::new();
    for n in 0..60 {
        sent.push(Instant::now());
        send(&net, n, 100);
        // (Apart by more than the jitter's whole width, so that none waits behind another.)
        tokio::time::sleep(Duration::from_millis(65)).await;
    }
    let first = arrived(&came).await;
    assert_eq!(numbers(&first), (0..60).collect::<Vec<_>>());
    let took: Vec<Duration> = first
        .iter()
        .map(|(n, at)| *at - sent[*n as usize])
        .collect();
    let (least, most) = (took.iter().min().unwrap(), took.iter().max().unwrap());
    assert!(*least >= delay - jitter, "{least:?}");
    assert!(*least < delay - jitter / 2, "{least:?}");
    assert!(*most > delay + jitter / 2, "{most:?}");
    // Packets sent together keep their order whatever their delays were drawn as.
    (100..600).for_each(|n| send(&net, n, 100));
    let came = numbers(&arrived(&came).await);
    assert_eq!(came[60..], (100..600).collect::<Vec<_>>());
}

#[tokio::test]
async fn duplication_delivers_its_share_twice() {
    let profile = Profile {
        dup: 0.10,
        delay: Duration::from_millis(5),
        ..Profile::default()
    };
    let (net, came) = link(profile, 5);
    (0..5000).for_each(|n| send(&net, n, 100));
    let came = numbers(&arrived(&came).await);
    let counts = net.counts(id(2));
    assert!((400..=600).contains(&counts.duplicated), "{counts:?}");
    assert_eq!(counts.delivered, 5000 + counts.duplicated);
    assert_eq!(came.len() as u64, counts.delivered);
    // Every packet came, none more than twice, and as many twice as were counted.
    let mut times = vec![0u64; 5000];
    came.iter().for_each(|n| times[*n as usize] += 1);
    assert!(times.iter().all(|times| (1..=2).contains(times)));
    let twice = times.iter().filter(|times| **times == 2).count() as u64;
    assert_eq!(twice, counts.duplicated);
}

#[tokio::test]
async fn reordering_holds_its_share_back_behind_packets_sent_later() {
    let profile = Profile {
        reorder: 0.10,
        delay: Duration::from_millis(10),
        ..Profile::default()
    };
    let (net, came) = link(profile, 9);
    for n in 0..2000 {
        send(&net, n, 100);
        if n % 100 == 99 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    let came = numbers(&arrived(&came).await);
    let counts = net.counts(id(2));
    assert!((150..=250).contains(&counts.held_back), "{counts:?}");
    // Every packet once; those not held back in their order; each held one behind a later one.
    let mut sorted = came.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (0..2000).collect::<Vec<_>>());
    let overtaken: Vec<u32> = came
        .iter()
        .enumerate()
        .filter(|(at, n)| came[..*at].iter().any(|before| before > n))
        .map(|(_, n)| *n)
        .collect();
    // (All but the few held back at the very end, which nothing was sent after.)
    let held = counts.held_back as usize;
    assert!(
        (held - 20..=held).contains(&overtaken.len()),
        "{} of {held}",
        overtaken.len()
    );
    let rest: Vec<u32> = came
        .iter()
        .copied()
        .filter(|n| !overtaken.contains(n))
        .collect();
    assert!(rest.is_sorted());
}

#[tokio::test]
async fn a_rate_carries_no_more_than_it_says_and_drops_what_its_buffer_cannot_hold() {
    let (rate, queue) = (256_000u64, Duration::from_millis(100));
    let profile = Profile {
        rate: Some(rate),
        queue,
        ..Profile::default()
    };
    let (net, came) = link(profile, 1);
    // Offered four times what the link carries, for two seconds: 1,000 bytes every 8 ms.
    let (began, mut sent) = (Instant::now(), Vec::new());
    while began.elapsed() < Duration::from_secs(2) {
        sent.push(Instant::now());
        send(&net, sent.len() as u32 - 1, 1000);
        tokio::time::sleep(Duration::from_millis(8)).await;
    }
    let offered = began.elapsed();
    let came = arrived(&came).await;
    let counts = net.counts(id(2));
    assert_eq!(counts.sent, sent.len() as u64);
    assert_eq!(counts.overflowed + counts.delivered, counts.sent);
    // Never more than the rate for the time it was offered, the buffer and a packet more; and
    // most of that, for it was always offered more than it carries.
    let bits = (counts.bytes * 8) as f64;
    let most = rate as f64 * (offered + queue).as_secs_f64() + 8000.0;
    assert!(bits <= most, "{bits} bits, {most} at the most");
    assert!(
        bits >= 0.8 * rate as f64 * offered.as_secs_f64(),
        "{bits} bits"
    );
    assert!(counts.overflowed > counts.sent / 2, "{counts:?}");
    // In order. Each took at least the time its own bytes take to send (31 ms), and most of
    // them more: they waited their turn behind the one before, in the buffer.
    assert!(numbers(&came).is_sorted());
    let took = |(n, at): &(u32, Instant)| *at - sent[*n as usize];
    let own = Duration::from_millis(31);
    assert!(came.iter().all(|packet| took(packet) >= own));
    let waited = came.iter().filter(|packet| took(packet) >= own * 2).count();
    assert!(waited > came.len() / 2, "{waited} of {} waited", came.len());
}

#[tokio::test]
async fn a_black_hole_drops_everything_sent_in_it_and_nothing_after() {
    let (net, came) = link(Profile::named("25ms"), 1);
    (0..10).for_each(|n| send(&net, n, 100));
    net.black_hole(Duration::from_millis(300));
    (10..30).for_each(|n| send(&net, n, 100));
    tokio::time::sleep(Duration::from_millis(320)).await;
    (30..40).for_each(|n| send(&net, n, 100));
    // What was on its way when the hole opened arrives; what was sent into it never does.
    let came = numbers(&arrived(&came).await);
    assert_eq!(came, (0..10).chain(30..40).collect::<Vec<_>>());
    let counts = net.counts(id(2));
    assert_eq!((counts.black_holed, counts.delivered), (20, 20));
}

#[tokio::test]
async fn every_fault_at_once_falls_on_the_same_packets_for_the_same_seed() {
    let profile = Profile {
        loss: 0.1,
        dup: 0.1,
        reorder: 0.1,
        delay: Duration::from_millis(5),
        jitter: Duration::from_millis(3),
        ..Profile::default()
    };
    let mut runs = Vec::new();
    for seed in [42, 42, 43] {
        let (net, came) = link(profile.clone(), seed);
        (0..3000).for_each(|n| send(&net, n, 100));
        let mut came = numbers(&arrived(&came).await);
        // (Which packets came and how often is the seed's; their order is the clock's too.)
        came.sort_unstable();
        runs.push((came, net.counts(id(2))));
    }
    assert_eq!(runs[0], runs[1]);
    assert_ne!(runs[0].1, runs[2].1);
    // Each way has a generator of its own: what falls on a packet one way does not fall on
    // its like the other way.
    let net = FaultNet::new(profile.clone(), 42);
    let _places = (net.join(id(1)), net.join(id(2)));
    for _ in 0..3000 {
        net.route(id(1), id(2), &[0; 100]).unwrap();
        net.route(id(2), id(1), &[0; 100]).unwrap();
    }
    assert_ne!(net.counts(id(1)), net.counts(id(2)));
    // A profile changed on the way holds from then on.
    let (net, came) = link(profile, 1);
    net.set(Profile::default());
    (0..100).for_each(|n| send(&net, n, 100));
    assert_eq!(numbers(&arrived(&came).await).len(), 100);
}
