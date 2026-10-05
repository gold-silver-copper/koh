//! Shrinking a case that shows a difference to a smaller one that still shows one: steps taken
//! out, a chunk at a time and then one at a time, and the bytes of each output and keys step
//! shortened, while the two sides still differ.

use crate::case::{Case, Step};

/// The most runs of both sides a shrink may take.
const RUNS: usize = 4_000;

/// The smallest case found from `case` for which `differs` holds. `differs` is true when the
/// sides still differ on the case it is given.
pub fn shrink(case: &Case, mut differs: impl FnMut(&Case) -> bool) -> Case {
    let mut best = case.clone();
    let mut runs = 0usize;
    let mut attempt = |candidate: &Case, best: &mut Case| {
        if runs >= RUNS {
            return false;
        }
        runs = runs.saturating_add(1);
        if differs(candidate) {
            *best = candidate.clone();
            true
        } else {
            false
        }
    };
    // Steps, a chunk at a time, the chunks halving.
    let mut chunk = best.steps.len().div_ceil(2);
    while chunk > 0 {
        let mut start = 0;
        while start < best.steps.len() {
            let mut candidate = best.clone();
            let end = start.saturating_add(chunk).min(candidate.steps.len());
            candidate.steps.drain(start..end);
            if !attempt(&candidate, &mut best) {
                start = start.saturating_add(chunk);
            }
        }
        chunk /= 2;
    }
    // Each output's and keys' bytes, the halves first, then single bytes from the end.
    let mut index = 0;
    while index < best.steps.len() {
        let mut cut = bytes(best.steps.get(index)).map_or(0, |b| b.len().div_ceil(2));
        while cut > 0 {
            let len = bytes(best.steps.get(index)).map_or(0, <[u8]>::len);
            let mut shortened = false;
            for keep_front in [true, false] {
                let mut candidate = best.clone();
                if let Some(Step::Output(b) | Step::Keys(b)) = candidate.steps.get_mut(index) {
                    if keep_front {
                        b.truncate(len.saturating_sub(cut));
                    } else {
                        b.drain(..cut.min(b.len()));
                    }
                }
                if attempt(&candidate, &mut best) {
                    shortened = true;
                    break;
                }
            }
            if !shortened {
                cut /= 2;
            }
        }
        index = index.saturating_add(1);
    }
    // Lost frames delivered, and ticks shortened, where the difference stays.
    for index in 0..best.steps.len() {
        let mut candidate = best.clone();
        match candidate.steps.get_mut(index) {
            Some(Step::Frame { dropped }) if *dropped => *dropped = false,
            Some(Step::Tick(ms)) if *ms > 0 => *ms = 0,
            Some(
                Step::Frame { .. }
                | Step::Tick(_)
                | Step::Output(_)
                | Step::Keys(_)
                | Step::Resize(..),
            )
            | None => continue,
        }
        attempt(&candidate, &mut best);
    }
    best
}

fn bytes(step: Option<&Step>) -> Option<&[u8]> {
    match step? {
        Step::Output(b) | Step::Keys(b) => Some(b),
        Step::Frame { .. } | Step::Tick(_) | Step::Resize(..) => None,
    }
}
