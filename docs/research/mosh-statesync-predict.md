# mosh state-sync + prediction/local-echo — ground-truth reference

Extracted verbatim from mosh source (`/Users/kisaczka/Desktop/code/mosh/src`). Quotes are copy-paste accurate against the files read. This is a cheat-sheet for a from-scratch Rust reimplementation whose transport is iroh and whose terminal model is backed by a vt100 crate (`contents_diff` substitutes for mosh's `Display::new_frame`). Files:

- `src/statesync/completeterminal.{h,cc}` — server screen state object (`Terminal::Complete`)
- `src/statesync/user.{h,cc}` — client keystroke state object (`Network::UserStream`)
- `src/frontend/terminaloverlay.{h,cc}` — the predictor (`Overlay::PredictionEngine` et al.)
- Supporting: `src/terminal/parseraction.h`, `src/terminal/terminalframebuffer.h`, `src/terminal/terminaldisplay.h`

---

## 0. The Transport state-object contract (what both objects implement)

Both `Complete` and `UserStream` are "state" types plugged into `Network::Transport<MyState, RemoteState>`. The duck-typed interface each must provide (no base class; templated):

```cpp
void   subtract( const T* prefix );          // remove a known-acked prefix from self (mutates)
std::string diff_from( const T& existing ) const;  // produce wire bytes carrying (self - existing)
std::string init_diff( void ) const;         // diff_from( T() ) i.e. against a fresh/empty state
void   apply_string( const std::string& diff );    // apply received wire bytes onto self (mutates)
bool   operator==( const T& x ) const;
bool   compare( const T& other ) const;      // debug-only structural compare
```

Wire format is **protobuf** in both cases (`HostBuffers::HostMessage` / `ClientBuffers::UserMessage`), each a repeated `Instruction` with extension fields. Diffs are *cumulative deltas between two full states*, not incremental op-logs — the transport keeps the last-acked state and diffs the current state against it.

Rust mapping note: you do NOT need protobuf wire compat unless interoperating with stock mosh. Reproduce the *semantics* (delta between two screen states; range of new keystrokes since ack). Back `Complete::diff_from` with vt100 `Screen::contents_diff` / `Screen::contents_formatted` and a resize sentinel + echo-ack number.

---

## 1. `Terminal::Complete` — server screen state (`completeterminal.{h,cc}`)

### Members
```cpp
Parser::UTF8Parser parser;
Terminal::Emulator terminal;
Terminal::Display  display;            // constructed display( false ) => initialized=false-capable renderer
Parser::Actions    actions;            // scratch; MUST be empty outside act()
using input_history_type = std::list<std::pair<uint64_t, uint64_t>>;  // (input_frame_num, timestamp)
input_history_type input_history;
uint64_t echo_ack;                     // newest user-input frame number the server has "echoed"
static const int ECHO_TIMEOUT = 50;    // ms, for late ack
```

### Constructor
```cpp
Complete( size_t width, size_t height )
  : parser(), terminal( width, height ), display( false ), actions(), input_history(), echo_ack( 0 ) {}
```

### Feeding host bytes into the screen
```cpp
std::string act( const std::string& str );      // parse octets -> Actions -> apply to terminal; returns terminal.read_octets_to_host()
std::string act( const Parser::Action& act );    // apply a single Action (e.g. Resize); returns read_octets_to_host()
```
`act(string)` loops octet-by-octet: `parser.input(str[i], actions)` (≤3 actions per octet), then `act.act_on_terminal(&terminal)` for each, then `actions.clear()`. Returns any bytes the terminal wants to send back to the host (terminal replies). Server asserts this is empty when applying a diff (`assert(terminal_to_host.empty())`).

### diff_from / init_diff — THE CONTRACT
```cpp
std::string Complete::diff_from( const Complete& existing ) const;
std::string Complete::init_diff( void ) const;   // = diff_from( Complete( width, height ) )
```
Builds a `HostBuffers::HostMessage` of up to three instruction kinds, in this order:

1. **echoack** — if `existing.get_echo_ack() != get_echo_ack()` (asserts ours ≥ theirs): `Instruction.MutableExtension(echoack)->set_echo_ack_num( get_echo_ack() )`.
2. **resize** — only if framebuffers differ AND width or height changed: `set_width(...)`, `set_height(...)` from `terminal.get_fb().ds`.
3. **hostbytes** — if framebuffers differ: `update = display.new_frame( true, existing.get_fb(), terminal.get_fb() )`; if non-empty, `Instruction.MutableExtension(hostbytes)->set_hoststring(update)`.

So a diff = (optional echo-ack bump) + (optional resize) + (a terminal-emulator escape-sequence patch that transforms `existing`'s screen into `this`'s screen). **`Display::new_frame` is the analogue of vt100 `contents_diff`** — it emits the minimal ANSI byte stream to morph one framebuffer into another.

```cpp
// terminaldisplay.h
std::string new_frame( bool initialized, const Framebuffer& last, const Framebuffer& f ) const;
```
`initialized=true` => incremental (diff) mode; `false` => full repaint.

### apply_string
```cpp
void Complete::apply_string( const std::string& diff );
```
`fatal_assert( input.ParseFromString(diff) )`, then per instruction:
- `HasExtension(hostbytes)` => `act( ...hoststring() )` and assert the result empty.
- `HasExtension(resize)` => `act( Resize( width, height ) )`.
- `HasExtension(echoack)` => assert `num >= echo_ack`; set `echo_ack = num`.

### subtract
```cpp
void subtract( const Complete* ) const {}   // NO-OP. (header-inline)
```
Screen state is absolute, not a prefix-stackable log, so `subtract` does nothing. (Contrast `UserStream::subtract`.)

### Equality / compare
```cpp
bool operator==( const Complete& x ) const;   // (terminal == x.terminal) && (echo_ack == x.echo_ack)
bool compare( const Complete& other ) const;  // debug: prints per-cell + cursor diffs to stderr; returns true if differ
```

### Echo-ack timing (local-echo confirmation on the server side)
The server tracks when each *user-input* frame N arrived, and "echo-acks" a frame once `ECHO_TIMEOUT` (50 ms) has elapsed since it was registered — i.e. the screen has had time to reflect that input.
```cpp
uint64_t get_echo_ack( void ) const;
bool     set_echo_ack( uint64_t now );        // recompute echo_ack; returns true if it changed
void     register_input_frame( uint64_t n, uint64_t now );  // push_back (n, now)
int      wait_time( uint64_t now ) const;     // ms until next echo-ack can fire; INT_MAX if <2 frames, 0 if due
```
`set_echo_ack`: newest_echo_ack = largest frame-num whose timestamp `<= now - ECHO_TIMEOUT`; prune history entries below it; assign. `wait_time`: if `<2` history entries → `INT_MAX`; else next fire = `(2nd entry).second + ECHO_TIMEOUT`, clamped to ≥0. This `echo_ack` is what the *client predictor* consumes as `local_frame_late_acked` (the authoritative "your keystroke up to frame N is now reflected on screen").

---

## 2. `Network::UserStream` — client keystroke state (`user.{h,cc}`)

### Event model
```cpp
enum UserEventType { UserByteType = 0, ResizeType = 1 };

class UserEvent {
public:
  UserEventType  type;
  Parser::UserByte userbyte;   // has: char c;
  Parser::Resize   resize;     // has: size_t width, height;
  UserEvent( const Parser::UserByte& s ) : type(UserByteType), userbyte(s), resize(-1,-1) {}
  UserEvent( const Parser::Resize&  s ) : type(ResizeType),   userbyte(0), resize(s)      {}
  bool operator==( const UserEvent& x ) const;   // type && userbyte && resize all equal
};
```
`Parser::UserByte`/`Parser::Resize` (from `parseraction.h`) both derive `Parser::Action`:
```cpp
class UserByte : public Action { public: char c;        UserByte(int s_c):c(s_c){}  bool operator==(...) };
class Resize   : public Action { public: size_t width, height; Resize(size_t w,size_t h):width(w),height(h){} bool operator==(...) };
```

### UserStream container
```cpp
class UserStream {
  std::deque<UserEvent> actions;          // ordered keystroke/resize log
public:
  void push_back( const Parser::UserByte& );   // append a typed byte
  void push_back( const Parser::Resize& );     // append a resize
  bool   empty() const;  size_t size() const;
  const Parser::Action& get_action( unsigned int i ) const;  // returns userbyte or resize as Action&

  void   subtract( const UserStream* prefix );
  std::string diff_from( const UserStream& existing ) const;
  std::string init_diff() const { return diff_from( UserStream() ); }
  void   apply_string( const std::string& diff );
  bool   operator==( const UserStream& x ) const;  // actions == x.actions
  bool   compare( const UserStream& ) { return false; }
};
```

### subtract — drop the acked prefix
```cpp
void UserStream::subtract( const UserStream* prefix );
```
Removes `prefix` from the FRONT of `actions`. If `this == prefix`, just `actions.clear()`. Otherwise for each event in `prefix->actions`: assert it equals `actions.front()`, then `pop_front()`. This is how the client discards keystrokes the server has acknowledged. (Unlike `Complete::subtract`, this is real.)

### diff_from — range of NEW keystrokes since the ack
```cpp
std::string UserStream::diff_from( const UserStream& existing ) const;
```
Walk `existing.actions` in lockstep against the head of `this->actions` (assert equal, advancing `my_it`); the *remaining tail* (`my_it .. actions.end()`) is the new events to send. Build `ClientBuffers::UserMessage`:
- **UserByteType**: **coalesce consecutive bytes** — if the last instruction already has a `keystroke` extension, append this byte to its `keys` string; else add a new instruction with `keystroke.set_keys(&byte,1)`. (So typed runs pack into one `keystroke` blob.)
- **ResizeType**: always a fresh instruction with `resize.set_width / set_height`.

### apply_string — server reconstructs keystrokes
```cpp
void UserStream::apply_string( const std::string& diff );
```
`fatal_assert(ParseFromString)`, then per instruction:
- `HasExtension(keystroke)`: for each byte of `keys()`, `actions.push_back( UserEvent( UserByte( byte ) ) )`.
- `HasExtension(resize)`: `actions.push_back( UserEvent( Resize( width, height ) ) )`.

### How resize travels
Resize is a first-class `UserEvent` interleaved in the same ordered stream as keystrokes (preserving order vs. typing). It is *never* coalesced. On the server it is replayed via `Complete::act( Resize(...) )`. There is a *separate* resize path in `Complete::diff_from`/`apply_string` (HostMessage `resize` extension) used to inform the *client* of the server-side terminal dimensions; the `UserStream` resize is the *client→server* notification of the local window size.

---

## 3. THE PREDICTOR — `Overlay::PredictionEngine` (`terminaloverlay.{h,cc}`)

The predictor overlays *speculative* local echo onto the authoritative framebuffer the server sends, so typing feels instant. It maintains predicted cells/cursor tagged by "epoch" and "expiration frame", then validates them against each fresh server frame, confirming or killing.

### 3.1 Validity enum (header)
```cpp
enum Validity { Pending, Correct, CorrectNoCredit, IncorrectOrExpired, Inactive };
```
- **Pending** — prediction made; the server frame that would confirm it hasn't arrived yet (`late_ack < expiration_frame`). Keep showing (subject to display policy).
- **Correct** — server frame arrived and the cell/cursor matches our prediction, AND it differed from the original contents (we get "credit": it advances `confirmed_epoch` and repairs the glitch trigger).
- **CorrectNoCredit** — matches, but it was a blank/unknown/we-don't-credit case (too easy to match falsely). Confirmed but no credit/epoch advance.
- **IncorrectOrExpired** — server frame arrived and the cell/cursor does NOT match (mis-prediction) OR went off-screen. Triggers kill/reset.
- **Inactive** — `active == false`; the overlay slot isn't predicting anything.

### 3.2 Data model (header)
```cpp
class ConditionalOverlay {                 // base of cell & cursor predictions
  uint64_t expiration_frame;               // local frame# whose ack confirms/refutes this prediction
  int      col;
  bool     active;                          // "represents a prediction at all"
  uint64_t tentative_until_epoch;          // epoch in which this was predicted; "when to show"
  uint64_t prediction_time;                // wall-clock ms when predicted (for glitch detection)
  ConditionalOverlay( uint64_t s_exp, int s_col, uint64_t s_tentative );
  bool tentative( uint64_t confirmed_epoch ) const { return tentative_until_epoch > confirmed_epoch; }
  void reset();                            // expiration=tentative=-1, active=false
  void expire( uint64_t s_exp, uint64_t now ) { expiration_frame=s_exp; prediction_time=now; }
};

class ConditionalCursorMove : public ConditionalOverlay {
  int row;
  void     apply( Framebuffer& fb, uint64_t confirmed_epoch ) const;
  Validity get_validity( const Framebuffer& fb, uint64_t early_ack, uint64_t late_ack ) const;
  ConditionalCursorMove( uint64_t s_exp, int s_row, int s_col, uint64_t s_tentative );
};

class ConditionalOverlayCell : public ConditionalOverlay {
  Cell  replacement;                        // the predicted glyph
  bool  unknown;                            // we predict "something changed here" but not what
  std::vector<Cell> original_contents;      // pre-prediction contents; matches => NO credit
  void     apply( Framebuffer& fb, uint64_t confirmed_epoch, int row, bool flag ) const;
  Validity get_validity( const Framebuffer& fb, int row, uint64_t early_ack, uint64_t late_ack ) const;
  ConditionalOverlayCell( uint64_t s_exp, int s_col, uint64_t s_tentative );
  void reset();              // unknown=false; original_contents.clear(); base::reset()
  void reset_with_orig();    // if !active||unknown: reset(); else push replacement into original_contents, base::reset()
};

class ConditionalOverlayRow {
  int row_num;
  using overlay_cells_type = std::vector<ConditionalOverlayCell>;   // one slot per column
  overlay_cells_type overlay_cells;
  void apply( Framebuffer& fb, uint64_t confirmed_epoch, bool flag ) const;  // applies each cell
  ConditionalOverlayRow( int s_row_num );
};
```

### 3.3 PredictionEngine fields & constants (header, numeric values verbatim)
```cpp
static const uint64_t SRTT_TRIGGER_LOW       = 20;   // ms: <= cures SRTT trigger (stop showing if idle)
static const uint64_t SRTT_TRIGGER_HIGH      = 30;   // ms: >  starts SRTT trigger (begin showing predictions)
static const uint64_t FLAG_TRIGGER_LOW       = 50;   // ms: <= cures flagging (stop underlining)
static const uint64_t FLAG_TRIGGER_HIGH      = 80;   // ms: >  starts flagging (begin underlining predictions)
static const uint64_t GLITCH_THRESHOLD       = 250;  // ms: a prediction outstanding this long = "glitch"
static const uint64_t GLITCH_REPAIR_COUNT    = 10;   // # of fast confirmations needed to cure glitch trigger
static const uint64_t GLITCH_REPAIR_MININTERVAL = 150;// ms: min spacing between counted non-glitches
static const uint64_t GLITCH_FLAG_THRESHOLD  = 5000; // ms: prediction outstanding this long => underline
```
```cpp
char last_byte;                       // for ESC-O => ESC-[ application-mode arrow translation
Parser::UTF8Parser parser;
std::list<ConditionalOverlayRow> overlays;     // predicted cells, by row
std::list<ConditionalCursorMove> cursors;      // predicted cursor moves (cursor() == cursors.back())
uint64_t local_frame_sent, local_frame_acked, local_frame_late_acked;  // epoch/ack bookkeeping
uint64_t prediction_epoch;            // epoch we are CURRENTLY predicting into (init 1)
uint64_t confirmed_epoch;             // newest epoch confirmed correct by server (init 0)
bool         flagging;                // underlining predictions
bool         srtt_trigger;            // show predictions due to slow RTT
unsigned int glitch_trigger;          // show predictions temporarily due to long-pending prediction
uint64_t     last_quick_confirmation;
unsigned int send_interval;           // == SRTT estimate fed in by caller (init 250 ms)
int          last_height, last_width; // detect resize => reset()
DisplayPreference display_preference;  // init Adaptive
bool         predict_overwrite;        // init false; true => overwrite mode instead of insert
```
```cpp
enum DisplayPreference { Always, Never, Adaptive, Experimental };
```
- **Always** — render predictions unconditionally.
- **Never** — disable prediction entirely (`new_user_byte`, `cull`, `apply` all early-return).
- **Adaptive** (default) — render only when `srtt_trigger || glitch_trigger` (i.e. RTT high or a prediction is lagging).
- **Experimental** — always render; uses different (non-epoch-incrementing) bookkeeping: `prediction_epoch = confirmed_epoch` on each byte, `become_tentative` does NOT bump epoch, and mispredictions `reset()` individual cells/clear cursors rather than `kill_epoch`/global `reset`.

Public knobs / wiring:
```cpp
void set_display_preference( DisplayPreference );
void set_predict_overwrite( bool );
void apply( Framebuffer& fb ) const;                 // draw predictions onto fb
void new_user_byte( char the_byte, const Framebuffer& fb );  // record a typed byte -> predictions
void cull( const Framebuffer& fb );                  // validate predictions vs fb (on new server frame)
void reset();                                        // drop all predictions, become_tentative()
void set_local_frame_sent( uint64_t );               // caller: most recent local frame# sent
void set_local_frame_acked( uint64_t );              // caller: early-ack frame#
void set_local_frame_late_acked( uint64_t );         // caller: late-ack frame# (== server echo_ack)
void set_send_interval( unsigned int );              // caller: SRTT in ms
int  wait_time() const;   // (timing_tests_necessary() && active()) ? 50 : INT_MAX
PredictionEngine();       // see init values above (prediction_epoch=1, confirmed_epoch=0, send_interval=250, display_preference=Adaptive)
```
`active()` = any cursor present OR any active overlay cell.
`timing_tests_necessary()` = `!(glitch_trigger && flagging)` — if both are already on, no timer needed.

Epoch semantics: a prediction is tagged with `tentative_until_epoch = prediction_epoch`. It is "tentative" (not shown by `apply`) while `tentative_until_epoch > confirmed_epoch`. A *correct* prediction with credit advances `confirmed_epoch` up to its `tentative_until_epoch`, instantly un-tentative-ing every earlier-epoch prediction. `become_tentative()` bumps `prediction_epoch` (except Experimental), opening a new epoch whenever we predict something risky/uncertain (control char, last column, CR/LF, escape sequence) so that a later confirmation gates the batch.

`expiration_frame = local_frame_sent + 1`: the prediction will be judged once the server acks a local frame ≥ that number. `late_ack` (set from server `echo_ack`) is compared against `expiration_frame` to decide Pending vs. resolved.

### 3.4 `apply()` — render predictions onto the framebuffer
```cpp
void PredictionEngine::apply( Framebuffer& fb ) const;
```
Early-return if `display_preference == Never` OR not `(srtt_trigger || glitch_trigger || Always || Experimental)`. Then apply all cursor moves, then all overlay rows (passing `flagging`).

`ConditionalCursorMove::apply`: skip if `!active` or `tentative(confirmed_epoch)`; asserts row/col in-bounds and `!origin_mode`; `fb.ds.move_row(row,false); fb.ds.move_col(col,false,false);`.

`ConditionalOverlayCell::apply( fb, confirmed_epoch, row, flag )`:
- skip if `!active`, row/col OOB, or `tentative(confirmed_epoch)`.
- if both predicted `replacement` and actual cell are blank => `flag=false` (don't underline blanks).
- if `unknown`: if `flag` and not last column, set `Renditions::underlined` on the actual cell; return (don't overwrite contents).
- else if actual cell `!= replacement`: write `replacement` into the cell; if `flag`, set underline.

### 3.5 `cull()` — validate predictions when a NEW SERVER FRAME arrives
```cpp
void PredictionEngine::cull( const Framebuffer& fb );
```
Precise pseudocode:
```
if display_preference == Never: return
if fb height/width != last_height/last_width:        # window resized
    last_height = fb.height; last_width = fb.width
    reset()                                          # drop all predictions
now = timestamp()

# --- SRTT trigger (show-predictions) with hysteresis ---
if send_interval > SRTT_TRIGGER_HIGH (30): srtt_trigger = true
elif srtt_trigger and send_interval <= SRTT_TRIGGER_LOW (20) and not active():
    srtt_trigger = false                            # only cure when nothing is being shown

# --- flagging (underline) with hysteresis ---
if send_interval > FLAG_TRIGGER_HIGH (80): flagging = true
elif send_interval <= FLAG_TRIGGER_LOW (50): flagging = false
if glitch_trigger > GLITCH_REPAIR_COUNT (10): flagging = true   # big glitches also underline

# --- cell predictions ---
for each row in overlays:                            # (iterate with erase-safe next ptr)
    if row.row_num < 0 or >= fb.height: erase row; continue
    for each cell j in row.overlay_cells:
        switch j.get_validity(fb, row.row_num, local_frame_acked, local_frame_late_acked):
          IncorrectOrExpired:
              if j.tentative(confirmed_epoch):        # mis-predicted in an unconfirmed epoch
                  if Experimental: j.reset()
                  else: kill_epoch(j.tentative_until_epoch, fb)
              else:                                   # mis-predicted in a confirmed epoch (bad!)
                  if Experimental: j.reset()
                  else: reset(); return               # nuke everything, bail
          Correct:
              if j.tentative_until_epoch > confirmed_epoch:
                  confirmed_epoch = j.tentative_until_epoch       # advance confirmation
              # reward fast confirmations: slowly cure the glitch trigger
              if now - j.prediction_time < GLITCH_THRESHOLD (250)
                 and glitch_trigger > 0
                 and now - GLITCH_REPAIR_MININTERVAL (150) >= last_quick_confirmation:
                     glitch_trigger--; last_quick_confirmation = now
              # propagate the server's actual renditions to the rest of the row's predictions
              actual_renditions = fb.get_cell(row.row_num, j.col).get_renditions()
              for k from j to end of row: k.replacement.get_renditions() = actual_renditions
              # fallthrough into CorrectNoCredit:
          CorrectNoCredit:
              j.reset()                               # confirmed: stop predicting this cell
          Pending:
              # long-pending => activate predictions even if SRTT is low (glitch)
              if now - j.prediction_time >= GLITCH_FLAG_THRESHOLD (5000):
                  glitch_trigger = GLITCH_REPAIR_COUNT * 2   # = 20: display AND underline
              elif now - j.prediction_time >= GLITCH_THRESHOLD (250)
                   and glitch_trigger < GLITCH_REPAIR_COUNT (10):
                  glitch_trigger = GLITCH_REPAIR_COUNT       # = 10: just display
          default: pass

# --- cursor predictions ---
if cursors nonempty and cursor().get_validity(fb, local_frame_acked, local_frame_late_acked) == IncorrectOrExpired:
    if Experimental: cursors.clear()
    else: reset(); return
# drop every cursor prediction that is no longer Pending (resolved)
for it in cursors:
    if it.get_validity(...) != Pending: erase it
    else: ++it
```

`ConditionalOverlayCell::get_validity( fb, row, early_ack(unused), late_ack )`:
```
if !active: return Inactive
if row OOB or col OOB: return IncorrectOrExpired
if late_ack < expiration_frame: return Pending          # not confirmed yet
if unknown: return CorrectNoCredit
if replacement.is_blank(): return CorrectNoCredit        # "too easy for this to trigger falsely"
if current.contents_match(replacement):
    if replacement matches any original_contents entry: return CorrectNoCredit  # no credit—looked same before
    else: return Correct
return IncorrectOrExpired
```
`ConditionalCursorMove::get_validity( fb, early_ack(unused), late_ack )`:
```
if !active: return Inactive
if row OOB or col OOB: return IncorrectOrExpired
if late_ack >= expiration_frame:
    return (fb cursor col==col && row==row) ? Correct : IncorrectOrExpired
return Pending
```
Note: `early_ack` (`local_frame_acked`) is passed but UNUSED in both validity functions; only `late_ack` (`local_frame_late_acked`, i.e. the server's `echo_ack`) gates confirmation. Confirmation is therefore driven by the server's 50 ms-debounced echo-ack, not the raw network ack.

`kill_epoch( epoch, fb )`: erase every cursor that is `tentative(epoch-1)`; push a fresh authoritative cursor at the real `fb` cursor pos tagged `prediction_epoch`; reset every overlay cell that is `tentative(epoch-1)`; then `become_tentative()`. Effectively: throw away the speculative batch from that epoch, snap cursor back to truth, open a new epoch.

### 3.6 `new_user_byte()` — predict for one typed byte
```cpp
void PredictionEngine::new_user_byte( char the_byte, const Framebuffer& fb );
```
Precise pseudocode:
```
if display_preference == Never: return
if display_preference == Experimental: prediction_epoch = confirmed_epoch
cull(fb)                                  # validate first against current truth
now = timestamp()

# application-mode arrow translation: ESC O  =>  ESC [
if last_byte == 0x1b and the_byte == 'O': the_byte = '['
last_byte = the_byte

parser.input(the_byte, actions)           # UTF8 -> Parser::Action(s)
for act in actions:
  if act is Parser::Print:                 # a printable / candidate-echo char
      init_cursor(fb)                      # ensure a live cursor prediction exists in this epoch
      ch = act.ch                          # (assert act.char_present)

      if ch == 0x7f:                       # BACKSPACE
          the_row = get_or_make_row(cursor().row, width)
          if cursor().col > 0:
              cursor().col--
              cursor().expire(local_frame_sent+1, now)
              if predict_overwrite:
                  cell = the_row[cursor().col]
                  cell.reset_with_orig(); cell.active=true
                  cell.tentative_until_epoch=prediction_epoch; cell.expire(...)
                  cell.original_contents.push_back( *fb.get_cell() )   # current cursor cell
                  cell.replacement = that cell; clear(); append(' ')   # predict a space
              else:                                                    # INSERT/delete-shift mode
                  for i from cursor().col to width-1:                  # shift left, fill from i+1
                      cell = the_row[i]
                      cell.reset_with_orig(); cell.active=true
                      cell.tentative_until_epoch=prediction_epoch; cell.expire(...)
                      cell.original_contents.push_back( *fb.get_cell(row,i) )
                      if i+2 < width:
                          next = the_row[i+1]; next_actual = fb.get_cell(row,i+1)
                          if next.active:
                              if next.unknown: cell.unknown=true
                              else: cell.unknown=false; cell.replacement=next.replacement
                          else: cell.unknown=false; cell.replacement=*next_actual
                      else: cell.unknown=true

      elif ch < 0x20 or wcwidth(ch) != 1:  # control char OR wide/zero-width => can't predict cleanly
          become_tentative()               # open new epoch; predict nothing concrete

      else:                                # ORDINARY PRINTABLE CHARACTER
          # asserts cursor row/col in-bounds
          the_row = get_or_make_row(cursor().row, width)
          if cursor().col + 1 >= width:    # last column is ambiguous (emacs wrap vs shell)
              become_tentative()
          # shift cells right to make room (insert), or just overwrite the one cell
          rightmost = predict_overwrite ? cursor().col : width-1
          for i from rightmost down to cursor().col+1:
              cell = the_row[i]
              cell.reset_with_orig(); cell.active=true
              cell.tentative_until_epoch=prediction_epoch; cell.expire(local_frame_sent+1, now)
              cell.original_contents.push_back( *fb.get_cell(row,i) )
              prev = the_row[i-1]; prev_actual = fb.get_cell(row,i-1)
              if i == width-1: cell.unknown=true
              elif prev.active: cell.unknown = prev.unknown; if !unknown cell.replacement=prev.replacement
              else: cell.unknown=false; cell.replacement=*prev_actual
          # the predicted cell itself:
          cell = the_row[cursor().col]
          cell.reset_with_orig(); cell.active=true
          cell.tentative_until_epoch=prediction_epoch; cell.expire(local_frame_sent+1, now)
          cell.replacement.get_renditions() = fb.ds.get_renditions()
          # heuristic: copy renditions of the char to the left
          if cursor().col > 0:
              prev = the_row[cursor().col-1]; prev_actual = fb.get_cell(row,col-1)
              cell.replacement.renditions = (prev.active && !prev.unknown)
                                            ? prev.replacement.renditions
                                            : prev_actual.renditions
          cell.replacement.clear(); cell.replacement.append(ch)
          cell.original_contents.push_back( *fb.get_cell(row, col) )
          cursor().expire(local_frame_sent+1, now)
          # advance predicted cursor, wrapping if needed
          if cursor().col < width-1: cursor().col++
          else: become_tentative(); newline_carriage_return(fb)

  elif act is Parser::Execute:             # C0 control executed
      if act.char_present and act.ch == 0x0d:   # CR
          become_tentative(); newline_carriage_return(fb)
      else: become_tentative()                  # other control => give up predicting this batch

  elif act is Parser::Esc_Dispatch:        # ESC sequence => can't predict
      become_tentative()

  elif act is Parser::CSI_Dispatch:
      if act.ch == 'C':                     # RIGHT arrow
          init_cursor(fb); if cursor().col < width-1: cursor().col++; cursor().expire(...)
      elif act.ch == 'D':                   # LEFT arrow
          init_cursor(fb); if cursor().col > 0: cursor().col--; cursor().expire(...)
      else: become_tentative()
```

Helper behaviors:
- `init_cursor(fb)`: if no cursor, push a `ConditionalCursorMove(local_frame_sent+1, fb cursor row, fb cursor col, prediction_epoch)`, set active. Else if `cursor().tentative_until_epoch != prediction_epoch`, push a new cursor at the *current predicted* row/col tagged with `prediction_epoch` (carries the predicted position into the new epoch).
- `get_or_make_row(row_num, num_cols)`: find existing row, else create one with `num_cols` `ConditionalOverlayCell(0, i, prediction_epoch)` (one inactive slot per column).
- `newline_carriage_return(fb)`: `init_cursor`; `cursor().col = 0`; if cursor is on the last row, make a *blank* prediction for the whole last row (each cell active, `tentative_until_epoch=prediction_epoch`, expire, `replacement.clear()`) — does NOT predict scroll; else `cursor().row++`.
- `become_tentative()`: `if not Experimental: prediction_epoch++`.

When a new prediction starts: effectively every time we make a concrete cell/cursor change after `init_cursor`. A *new epoch* starts on `become_tentative()` (control chars, CR/LF, escape/CSI we can't model, last-column ambiguity, wide/zero-width chars) — predictions in that new epoch stay tentative (hidden) until a later confirmation advances `confirmed_epoch`.

### 3.7 PASSWORD / no-echo detection (how it stops predicting)
Mosh does NOT special-case password prompts explicitly. The suppression is emergent from the validation loop:
- When the server is *not* echoing (e.g. `sudo`/ssh password prompt), each predicted character `cull()`s to `IncorrectOrExpired` once the server frame for that input arrives (the cell stays blank / unchanged, so `contents_match(replacement)` fails). In non-Experimental mode this calls `reset()` (or `kill_epoch`) and `return`s — i.e. predictions are wiped and, crucially, the *epoch never gets confirmed*, so subsequent predictions remain tentative (hidden) by the `tentative(confirmed_epoch)` gate in `apply`. Net effect: nothing is drawn for non-echoed input.
- Blank predictions and `unknown` cells are deliberately graded `CorrectNoCredit` (`"too easy for this to trigger falsely"`), so a blank password field cannot falsely confirm an epoch.
So "the server isn't echoing" is detected as a stream of mis-validations that kill the epoch and keep new predictions tentative — there is no explicit password heuristic.

### 3.8 Display policy summary (Adaptive)
Predictions are drawn (`apply`) only if `srtt_trigger || glitch_trigger || Always || Experimental`:
- `srtt_trigger` turns ON when SRTT (`send_interval`) `> 30 ms`, OFF (hysteresis) when `<= 20 ms` and nothing is currently shown.
- `flagging` (underline) turns ON when SRTT `> 80 ms` (or `glitch_trigger > 10`), OFF when SRTT `<= 50 ms`.
- `glitch_trigger`: set to `10` (display only) when a prediction is Pending ≥ 250 ms; set to `20` (display + underline via the `>10` flagging rule) when Pending ≥ 5000 ms; decremented one notch per fast (`<250 ms`) confirmation, no faster than once per 150 ms; cured to 0 over `~GLITCH_REPAIR_COUNT` good confirmations.
- The "glitch/confirmation window": a prediction is shown only while Pending; once the server's late-ack (echo_ack) reaches its `expiration_frame` it is confirmed-and-cleared or killed. Long-pending predictions (≥250 ms / ≥5000 ms) escalate visibility (show, then underline). On a low-latency link (SRTT ≤ ~20–30 ms) predictions are effectively never shown because the real echo beats the trigger.

### 3.9 Underlying framebuffer accessors the predictor relies on (vt100 mapping)
```cpp
// terminalframebuffer.h
int  DrawState::get_cursor_row() const;  int get_cursor_col() const;
int  DrawState::get_width() const;       int get_height() const;
void DrawState::move_row(int N, bool relative=false);
void DrawState::move_col(int N, bool relative=false, bool implicit=false);
const Renditions& DrawState::get_renditions() const;
bool DrawState::origin_mode; bool cursor_visible;
const Cell* Framebuffer::get_cell(int row=-1,int col=-1) const;   // -1 => cursor pos
Cell*       Framebuffer::get_mutable_cell(int row=-1,int col=-1);
void        Framebuffer::reset_cell(Cell* c);                     // reset to bg rendition
// Cell:
bool Cell::is_blank() const;                  // empty || " " || NBSP
bool Cell::contents_match(const Cell&) const; // both blank, or identical contents bytes
bool Cell::operator==/!=(const Cell&) const;  // contents+fallback+wide+renditions+hyperlink+wrap
void Cell::clear(); void Cell::append(wchar_t);
Renditions& Cell::get_renditions();
```
For the Rust/vt100 port: `Cell::contents_match` ≈ "same grapheme (treating blank-equivalents as equal)"; `Cell::operator==` ≈ "same grapheme AND same style". `Display::new_frame(true, last, cur)` ≈ `vt100::Screen::contents_diff(&last)`.

---

## 4. Implementer takeaways / surprising bits

- **echo_ack drives confirmation, not the QUIC ack.** The predictor's `local_frame_late_acked` comes from the server's `Complete::echo_ack`, which is itself debounced by `ECHO_TIMEOUT = 50 ms` after input arrival. Reproduce this server-side debounce or predictions will confirm/kill too eagerly.
- **`Complete::subtract` is a no-op; `UserStream::subtract` pops a prefix.** Screen state is absolute; keystroke state is a prefix-stackable log.
- **Keystroke coalescing:** consecutive `UserByte`s pack into one protobuf `keystroke.keys` blob; resizes never coalesce and preserve ordering w.r.t. keys.
- **`early_ack` is dead.** Both `get_validity` functions ignore `local_frame_acked`; only late-ack matters.
- **Last column is always ambiguous** — typing into `width-1` forces `become_tentative()` (emacs shows wrap glyph, shells just place the char), so those predictions are hidden until confirmed.
- **Scroll is never predicted.** On the last row, CR/LF predicts a blank last row instead of scrolling.
- **Renditions heuristic:** a new predicted glyph copies the style of the cell to its left (or the DrawState's current renditions); on confirmation, the *actual* server renditions are back-propagated to the rest of the row's predictions.
- **`init_cursor` snapshots `local_frame_sent+1` as `expiration_frame`** — set `local_frame_sent` (via `set_local_frame_sent`) to the frame number you are about to send *before* feeding bytes, or expirations will be off-by-one.
- **Constants (ms unless noted):** SRTT_TRIGGER_LOW=20, SRTT_TRIGGER_HIGH=30, FLAG_TRIGGER_LOW=50, FLAG_TRIGGER_HIGH=80, GLITCH_THRESHOLD=250, GLITCH_REPAIR_COUNT=10 (count), GLITCH_REPAIR_MININTERVAL=150, GLITCH_FLAG_THRESHOLD=5000; ECHO_TIMEOUT=50; predictor `wait_time` polling = 50 ms; default `send_interval`=250; `prediction_epoch` init 1, `confirmed_epoch` init 0; `display_preference` default Adaptive.

---

## 5. Minimal happy-path usage (stock-mosh C++ shape, for porting reference)

```cpp
// ---- SERVER: maintain screen state, produce diff for the client ----
Terminal::Complete cur( 80, 24 ), last( 80, 24 );
std::string to_host = cur.act( bytes_from_pty );          // feed host output into the screen
cur.register_input_frame( /*input frame n*/ n, now_ms );  // remember when client input n arrived
cur.set_echo_ack( now_ms );                               // debounce-confirm input that's now reflected
std::string diff = cur.diff_from( last );                 // wire bytes: morph last -> cur (+resize/+echoack)
// ... send `diff` over iroh; on ack, last = cur;

// ---- CLIENT: apply server diff, then overlay local prediction ----
Terminal::Complete screen( 80, 24 );
screen.apply_string( diff_from_server );                  // authoritative framebuffer updated
const Framebuffer& fb = screen.get_fb();

Overlay::PredictionEngine pe;                             // Adaptive by default
pe.set_display_preference( Overlay::PredictionEngine::Adaptive );
pe.set_local_frame_sent( next_frame_to_send );
pe.set_local_frame_acked( early_ack );
pe.set_local_frame_late_acked( screen.get_echo_ack() );   // from server
pe.set_send_interval( srtt_ms );

for ( char b : typed_bytes ) {
    user_stream.push_back( Parser::UserByte( b ) );       // queue keystroke for transport
    pe.new_user_byte( b, fb );                            // speculate locally
}
// each render tick:
Framebuffer render_fb = fb;       // copy authoritative state
pe.cull( render_fb );             // validate predictions against truth (also done inside new_user_byte)
pe.apply( render_fb );            // draw confirmed/pending predictions onto the copy
// ... paint render_fb to the screen ...

// ---- CLIENT->SERVER keystroke diff ----
std::string user_diff = user_stream.diff_from( last_acked_user_stream );  // only new keys/resizes
// send user_diff; on ack: user_stream.subtract( &acked_prefix );
```
(`OverlayManager::apply(fb)` wraps `predictions.cull(fb); predictions.apply(fb); notifications...; title...` in one call — order matters: cull before apply.)
