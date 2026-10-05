#![no_main]
//! Fuzz the untrusted SERVER->CLIENT history path: a server controls every history reply a client
//! keeps, and the history mark that says which rows its history holds.
//!
//! Arbitrary bytes are read as a mark, a view offset and a history reply (postcard, as the stream
//! carries it), the reply kept in a client's cache, and the cache shown as a scrolled-back view.
//! Keeping must never panic, must keep only rows the mark holds, and must stay within the cache's
//! bound however many replies come; the view must be a well-formed screen.

use koh::terminal::{
    HistoryCache, HistoryMark, HistoryReply, Size, TerminalScreen, HISTORY_CACHE_CELLS,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(((newest, len, offset), mut rest)) =
        postcard::take_from_bytes::<(u64, u32, u16)>(data)
    else {
        return;
    };
    let mark = HistoryMark { newest, len };
    let mut cache = HistoryCache::default();
    // As many replies as the bytes hold, each kept or dropped whole.
    while let Ok((reply, after)) = postcard::take_from_bytes::<HistoryReply>(rest) {
        rest = after;
        let before = cache.len();
        if let Some(kept) = cache.insert(&reply, mark, newest) {
            assert!(kept <= reply.rows.len());
            assert!(cache.len() <= before + kept);
        }
        assert!(cache.cells() <= HISTORY_CACHE_CELLS);
    }
    let _ = koh::proto::decode_server(data);
    let screen = TerminalScreen::from_bytes(24, 80, b"live\r\nscreen");
    let view = screen.scrolled_back(&cache, usize::from(offset));
    let Size { rows, cols } = view.size();
    for row in 0..rows {
        assert_eq!(
            view.screen().row(row).map(|cells| cells.len()),
            Some(usize::from(cols))
        );
    }
});
