# The oracle: koh beside a commit

`testing/oracle.sh` holds koh to what it did at a commit: by default the merge base with
`origin/main`, so that work which changes how koh diffs, encodes or paints can show it changed
nothing the user sees. koh at the working tree and koh at the commit get the same sessions, and
everything a user's terminal would show is compared after every step. Any difference fails, shrunk
to the smallest case that shows it and saved to replay. It is modelled on fux's `diff/oracle`.

```sh
testing/oracle.sh                    # against the merge base with origin/main
testing/oracle.sh 6c79280            # against any commit
testing/oracle.sh --cases 20000 --seed 7
testing/oracle.sh --no-recordings    # random sessions only
testing/oracle.sh --replay testing/oracle/target/cases/NAME.case
testing/oracle.sh --plants           # show it finds each planted bug
```

## How it runs

Two processes, one per side: `koh-oracle-side` (`side/`) is built at the working tree and, from a
worktree of the commit (`target/trees/SHA`), at the commit, each with its own lockfile and target
directory. The driver (`driver/`) gives both the same cases on stdin and compares what they print.

The sides are separate binaries rather than two versions of koh in one, as fux's oracle has them,
because Cargo cannot link two koh versions that pin different releases of the same 1.x crate:
koh pins iroh with `=`, and a commit before a bump pins another. Built apart, any commit whose
public API the side compiles against can be compared, the commit before a dependency bump
included.

A side drives koh through its public API, as a session does: `ServerTerminal` takes the output,
snapshots become frames against the newest frame the client acknowledged (`diff_from`), frames go
through `encode_frame` and `decode_frame` (or are lost on the way), `ClientSession` applies them,
takes keystrokes and ticks, and koh's own `BackendTerminal` paints into a capture after every
step, with the status line the tick reports. Messages the client sends go back to the server:
acknowledgements move the base, a resync goes back to the blank screen, and input becomes the
echo-ack of the next frame.

## What is compared

After every step:

- **The user's terminal**, as one fux-vt parser (the driver's, the same for both sides) reads
  what each side painted: every cell's text, halves and attributes (a printed space and an erased
  cell of the same attributes count as one); the cursor, its position when shown and whether it
  is; the mouse mode and encoding, bracketed paste, cursor keys and keypad mode the client
  mirrors; and the title, icon, bell count and clipboard the paint told it.
- **The server's replies** to the program's queries, byte for byte.
- **The messages the client sent** (`Input`, `Ack`, `Resync`, `Resize`), and **what it made of
  typed bytes** (`InputOutcome`).

**Frame bytes** (each frame encoded and compressed, as it goes on the wire) are counted for each
side and reported, not compared: a change in what koh sends shows as a number.

## The cases

- **The corpus:** every recording in `testing/corpus/` at its size, with its resizes and keys:
  each step's output cut into pieces of 1 to 2,048 bytes, a frame after about half of them and
  always at a step's end; every other recording loses a fifth of its frames on the way.
- **Random sessions** (2,000 by default) at 2–11 rows by 2–29 columns, so that edges, wraps and
  scrolls come often: output built from pieces that exercise every part of a screen (text, wide
  and combining clusters, every SGR attribute and colour kind, cursor motion, erases, scroll
  regions, inserted and deleted lines and characters, tabs, the alternate screen, resets,
  margins, titles, the clipboard, bells, input modes, queries) and random bytes; frames, a fifth
  of them lost; typed keys, most of them echoed; time passing (so the link-down banner shows);
  and resizes.

## A difference

The driver stops at the first difference, shrinks the case (steps taken out a chunk at a time,
then output and keys shortened, lost frames delivered, ticks shortened, while the sides still
differ), prints it, and saves it under `target/cases/`. `--replay` runs a saved case again.

## Exemptions

`driver/src/exempt.rs` names each change made on purpose since the commit compared against, and
what sets it off. Each is taken out of every case before either side sees it, so the rest of the
case is still compared, and the driver says how many times each applied. Once the commit compared
against has a change, its exemption comes off the list. Against `main` only `prompt-hold` is
listed: a key typed within 200 ms of a frame that moved the cursor to another row is shown only
once echoed, so each keys step comes 200 ms after what came before it. The input events, the kitty
keyboard and scheme answers and fux-vt's reflow fix are all in `main`, and every mode the user's
terminal is kept in is compared. The palette the client tells the server changes nothing here,
since neither side tells one.

## The planted bugs

`plants/` holds seven bugs, each a patch to koh; `testing/oracle.sh --plants` applies each to a
worktree of `HEAD`, builds a side from it, and runs the oracle with `HEAD` as the base. Each must
be found:

| Patch | The bug |
| --- | --- |
| `01-dropped-row-shift` | a shift that moves rows down is dropped after the rows were diffed |
| `02-stale-row-cache` | a snapshot takes a cached row by its id alone, whatever its version |
| `03-lost-style-bit` | strikeout is not carried on the wire |
| `04-wrong-cursor` | a cursor in the last two columns is put in the one before them |
| `05-missed-resize` | the server misses a resize that makes the screen taller |
| `06-stale-dirty-rows` | a snapshot from the rows changed since the last takes only the first of them |
| `07-lost-backspace` | the client decodes Backspace and never sends it |

A planted bug that is no longer found means the oracle lost sight of something: fix the oracle,
not the patch.

## Limits

- A commit whose public API differs from what `side/src/main.rs` uses does not build. Where the
  API changes, give the side both forms behind what each commit has, and say so here.
- The side's server has no PTY and no `ServerConn`: frames are taken when the case says, the
  echo-ack is the newest input received, and a lost frame is never resent by itself (the case
  ends each recording's step with an arriving frame). What the oracle holds fixed is koh's
  screen, diff, wire and paint, not its pacing.
