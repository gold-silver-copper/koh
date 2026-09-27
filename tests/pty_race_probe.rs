//! TEMPORARY, removed before the PR is ready: reproduces macOS's PTY-table growth race on a fresh
//! runner. Threads open and free PTYs across rising 16-slot boundaries of the kernel's PTY table;
//! with `KOH_PROBE_GROW` set, the table is grown first, as `tests/pty.rs` now does.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[test]
#[ignore = "a CI probe, run explicitly"]
fn pty_table_growth_race() {
    if std::env::var("KOH_PROBE_GROW").is_ok_and(|grow| !grow.is_empty()) {
        let mut held = Vec::new();
        for _ in 0..256 {
            if let Ok(pty) = fuxix::pty::open(24, 80) {
                held.push(pty);
            }
        }
        println!("grew the table with {} PTYs", held.len());
        drop(held);
    }
    let mut total: BTreeMap<String, usize> = BTreeMap::new();
    for threads in (24_u64..=264).step_by(16) {
        let stop = Arc::new(AtomicBool::new(false));
        let errors: Arc<Mutex<BTreeMap<String, usize>>> = Arc::default();
        let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handles: Vec<_> = (0..threads)
            .map(|i| {
                let (stop, errors, opens) = (stop.clone(), errors.clone(), opens.clone());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        match fuxix::pty::open(24, 80) {
                            Ok(pty) => {
                                std::thread::sleep(Duration::from_millis(10 + i % 10));
                                drop(pty);
                                opens.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                *errors.lock().unwrap().entry(e.to_string()).or_default() += 1;
                                std::thread::sleep(Duration::from_millis(1));
                            }
                        }
                    }
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(800));
        stop.store(true, Ordering::Relaxed);
        for handle in handles {
            handle.join().unwrap();
        }
        let errors = errors.lock().unwrap().clone();
        println!(
            "threads {threads}: {} opens, errors {errors:?}",
            opens.load(Ordering::Relaxed)
        );
        for (message, count) in errors {
            *total.entry(message).or_default() += count;
        }
    }
    println!("total errors {total:?}");
}

/// One thread raises the PTYs held, one at a time, through the table's 16-slot boundaries, while
/// churners free and retake a PTY each: errors by how many were held when they struck.
#[test]
#[ignore = "a CI probe, run explicitly"]
fn pty_table_boundary_race() {
    let stop = Arc::new(AtomicBool::new(false));
    let churners: Vec<_> = (0_u64..32)
        .map(|i| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(pty) = fuxix::pty::open(24, 80) {
                        std::thread::sleep(Duration::from_micros(i * 7));
                        drop(pty);
                    }
                }
            })
        })
        .collect();
    let mut held = Vec::new();
    let mut errors: BTreeMap<usize, BTreeMap<String, usize>> = BTreeMap::new();
    while held.len() < 440 {
        match fuxix::pty::open(24, 80) {
            Ok(pty) => held.push(pty),
            Err(e) => *errors.entry(held.len()).or_default().entry(e.to_string()).or_default() += 1,
        }
    }
    stop.store(true, Ordering::Relaxed);
    for churner in churners {
        churner.join().unwrap();
    }
    println!("held {}; errors by PTYs held: {errors:?}", held.len());
}
