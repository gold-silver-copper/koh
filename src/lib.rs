//! # koh
//!
//! A remote shell over iroh: `koh serve` hosts a PTY for allowlisted peers and `koh connect`
//! renders it with predictive local echo, reconnecting transparently.
//!
//! ## Modules
//!
//! [`transport_iroh`] owns endpoint setup, the encrypted identity key file and connection
//! admission. [`identity`] loads identities and holds their reset leases; [`idcmd`] and
//! [`keycmd`] implement `koh id` and `koh key`. [`proto`] is the wire protocol: input messages
//! on one stream, screen frames on their own. [`terminal`], [`predict`] and [`pty`] implement the
//! remote-shell payload; [`server`] hosts detachable sessions and [`client`] renders them through
//! a terminal backend chosen by a `backend-*` feature. The `cli` feature adds clap and the binary.
//!
//! The library exists so the binary, its tests and the fuzz targets share code. Everything in it
//! is internal and may change in any release.

/// Declares modules whose production code is panic-free by construction.
///
/// The panic lints, and the lints for other silent failures (unused results, runaway recursion,
/// oversized stack frames, lossy time and integer operations), are `forbid` here, not just
/// Cargo.toml's `deny`, so no local `#[expect]`/`#[allow]` can carve out an exception. They are
/// applied per module rather than in `[lints]` or at the crate root because two things must stay
/// outside: tests, which panic on purpose (see clippy.toml), and the clap derives in [`args`], which
/// emit `#[allow(clippy::restriction)]` and so cannot compile under a `forbid`.
macro_rules! panic_free {
    ($($item:item)*) => {$(
        #[cfg_attr(
            not(test),
            forbid(
                clippy::unwrap_used,
                clippy::expect_used,
                clippy::panic,
                clippy::unreachable,
                clippy::todo,
                clippy::unimplemented,
                clippy::get_unwrap,
                clippy::unwrap_in_result,
                clippy::panic_in_result_fn,
                clippy::exit,
                clippy::indexing_slicing,
                clippy::string_slice,
                clippy::expect_fun_call,
                // Not panics, but the same class of silent failure, and already at zero here:
                // results that must be used, runaway recursion and loops, oversized stack frames,
                // lock guards held across a match, and time/integer ops that panic or truncate.
                unused_must_use,
                unconditional_recursion,
                clippy::suspicious,
                clippy::infinite_loop,
                clippy::large_stack_frames,
                clippy::large_stack_arrays,
                clippy::read_zero_byte_vec,
                clippy::debug_assert_with_mut_call,
                clippy::significant_drop_in_scrutinee,
                clippy::cast_lossless,
                clippy::unchecked_time_subtraction,
                clippy::unused_result_ok,
                clippy::mem_forget,
                clippy::integer_division,
                clippy::allow_attributes_without_reason,
                // Every match names the variants it handles, so a new variant is a compile error
                // at each match instead of silently taking a wildcard arm.
                clippy::wildcard_enum_match_arm,
                // No silent truncation or sign change: convert with `From`/`TryFrom` and say what
                // happens when the value does not fit.
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_possible_wrap,
                // Every `+`, `-`, `*` states its overflow behaviour (`checked_*`, `saturating_*`
                // or a construction that cannot overflow): release builds keep overflow checks,
                // so an unchecked operator is a potential panic.
                clippy::arithmetic_side_effects
            )
        )]
        $item
    )*};
}

panic_free! {
    pub mod client;
    pub mod identity;
    pub mod keycmd;
    pub mod predict;
    pub mod proto;
    pub mod pty;
    pub mod server;
    pub mod terminal;
    pub mod transport_iroh;
    pub mod idcmd;
}

#[cfg(feature = "cli")]
mod args;
