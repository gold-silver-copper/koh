//! What the oracle exempts: the input that sets off a change made on purpose since the commit it
//! compares against. Each exemption is taken out of every case before either side sees it, so
//! that everything else in the case is still compared. Once the commit compared against has the
//! change, its exemption comes off this list.
//!
//! The input events, the kitty keyboard and scheme answers and the reflow fix the last ones covered
//! are all in `main`. A new exemption names what sets it off here, takes it out in `strip`, and
//! counts it with `Tally::add`.

use crate::case::{Case, Step};

/// The changes exempted, each with what sets it off and why it differs.
pub const EXEMPTIONS: &[(&str, &str)] = &[(
    "prompt-hold",
    "a key typed within 200 ms of a frame that moved the cursor to another row (a fresh prompt) \
     is shown only once echoed, as the PTY's modes may lag: so each keys step comes 200 ms after \
     what came before it, for both sides, and predictions are still compared after the hold",
)];

/// How long the client holds keys at a fresh prompt: twice the server's `TTY_TICK`.
const PROMPT_HOLD_MS: u64 = 200;

/// How many times each exemption applied.
#[derive(Default)]
pub struct Tally {
    pub counts: Vec<(&'static str, u64)>,
}

impl Tally {
    fn add(&mut self, name: &'static str) {
        match self.counts.iter_mut().find(|(n, _)| *n == name) {
            Some((_, count)) => *count = count.saturating_add(1),
            None => self.counts.push((name, 1)),
        }
    }
}

/// `case` with what the exemptions name taken out: each keys step after a hold's worth of time.
pub fn strip(case: &Case, tally: &mut Tally) -> Case {
    let mut steps = Vec::with_capacity(case.steps.len().saturating_mul(2));
    for step in &case.steps {
        if let Step::Keys(_) = step {
            tally.add("prompt-hold");
            steps.push(Step::Tick(PROMPT_HOLD_MS));
        }
        steps.push(step.clone());
    }
    Case {
        name: case.name.clone(),
        rows: case.rows,
        cols: case.cols,
        steps,
    }
}
