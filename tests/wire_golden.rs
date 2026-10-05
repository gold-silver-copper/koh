//! The koh/3 encoding, pinned.
//!
//! Each value below is built the same way on every commit and encoded; the expected bytes were
//! captured by running the encoder, not written by hand. A change to the wire must change these
//! bytes in the same commit, deliberately.

use koh::proto::{
    decode_frame, decode_server, encode_client, encode_frame, encode_history, ClientDecoder,
    ClientMsg, Frame, FrameNum, InputSeq, ServerMsg,
};
use koh::terminal::{
    HistoryReply, HistoryRequest, ServerTerminal, Size, TerminalScreen, WireModes,
};

/// Terminal output exercising every part of a cell and of the side channels: runs, wide glyphs
/// and their continuations, a combining mark, a cluster too long to keep inline, every colour kind
/// on both layers and as an underline's colour, every style bit and both blinks, curly, double and
/// dashed underlines, a hyperlink, a soft wrap, the
/// title, icon, clipboard, bell and the input modes.
const OUTPUT: &[u8] = "\x1b]2;the title\x07\x1b]1;the icon\x07\x1b]52;c;aGVsbG8=\x07\x07\x07\
    aaaa日本e\u{301}  \r\n\
    \x1b[31mr\x1b[92mg\x1b[38;5;200mp\x1b[38;2;1;2;3mt\x1b[39m\
    \x1b[44mR\x1b[103mG\x1b[48;5;100mP\x1b[48;2;4;5;6mT\x1b[m\r\n\
    \x1b[1mB\x1b[m\x1b[2mD\x1b[m\x1b[3mI\x1b[m\x1b[4mU\x1b[m\x1b[7mV\x1b[m\
    \x1b[1;2;3;4;7mA\x1b[m\r\n\
    \x1b[5mK\x1b[6mk\x1b[8mH\x1b[9mS\x1b[m\x1b[4;58;5;9mu\x1b[58;2;7;8;9mv\x1b[m\
    \x1b[4:3mc\x1b[4:2md\x1b[4:5mw\x1b[m\x1b]8;id=k;https://koh.example/\x1b\\L\x1b]8;;\x1b\\\
    \u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}\u{200d}\u{1f466}\r\n\
    a line long enough to wrap\
    \x1b[?1h\x1b=\x1b[?2004h\x1b[?25l\x1b[?1002h\x1b[?1006h\x1b[3;5H"
    .as_bytes();

/// The screen [`OUTPUT`] draws on a 6×20 terminal whose program exited with status 3.
fn exited_screen() -> Result<TerminalScreen, fux_vt::Error> {
    let mut emu = ServerTerminal::new(6, 20, 0)?;
    emu.process(OUTPUT);
    emu.set_exit_code(3);
    Ok(emu.snapshot())
}

/// A resize, every row kind, the side channels and the exit code, from the blank screen.
fn full_frame() -> Result<Frame, fux_vt::Error> {
    Ok(Frame {
        num: FrameNum(300),
        base: FrameNum::BLANK,
        echo_ack: InputSeq(129),
        diff: exited_screen()?.diff_from(&TerminalScreen::default()),
    })
}

/// An incremental frame: one row changed, no resize, the side channels unchanged.
fn incremental_frame() -> Result<Frame, fux_vt::Error> {
    let mut emu = ServerTerminal::new(6, 20, 0)?;
    emu.process(OUTPUT);
    let base = emu.snapshot();
    emu.process(b"\x1b[6;1Hlast row");
    Ok(Frame {
        num: FrameNum(301),
        base: FrameNum(300),
        echo_ack: InputSeq(130),
        diff: emu.snapshot().diff_from(&base),
    })
}

/// A frame that scrolls: the screen scrolled up a line and a line written at the bottom, the rest
/// moved rather than sent, and the line scrolled off kept in history.
fn scrolled_frame() -> Result<Frame, fux_vt::Error> {
    let mut emu = ServerTerminal::new(6, 20, 10)?;
    emu.process(OUTPUT);
    let base = emu.snapshot();
    emu.process(b"\x1b[6;1H\r\nscrolled in");
    Ok(Frame {
        num: FrameNum(302),
        base: FrameNum(301),
        echo_ack: InputSeq(130),
        diff: emu.snapshot().diff_from(&base),
    })
}

/// The history the scrolled frame's server holds: the two rows its output scrolled off.
fn history_reply() -> Result<HistoryReply, fux_vt::Error> {
    let mut emu = ServerTerminal::new(6, 20, 10)?;
    emu.process(OUTPUT);
    emu.process(b"\x1b[6;1H\r\nscrolled in\r\n");
    let mark = emu.snapshot().history();
    Ok(emu.history(HistoryRequest {
        newest: mark.newest,
        count: 5,
    }))
}

/// The modes for every mouse mode (with the default encoding) and every mouse encoding (with
/// press/release reporting).
fn modes() -> Vec<WireModes> {
    let sequences: [&[u8]; 8] = [
        b"",
        b"\x1b[?9h",
        b"\x1b[?1000h",
        b"\x1b[?1002h",
        b"\x1b[?1003h",
        b"\x1b[?1000h\x1b[?1005h",
        b"\x1b[?1000h\x1b[?1006h",
        b"\x1b[?1h\x1b=\x1b[?2004h\x1b[?25l",
    ];
    sequences
        .iter()
        .map(|seq| {
            TerminalScreen::from_bytes(4, 4, seq)
                .diff_from(&TerminalScreen::default())
                .modes
        })
        .collect()
}

/// One message of each kind, with varints of one and several bytes.
fn client_msgs() -> Vec<ClientMsg> {
    vec![
        ClientMsg::Input {
            seq: InputSeq(1),
            bytes: b"ls -la\r".to_vec(),
        },
        ClientMsg::Input {
            seq: InputSeq(300),
            bytes: (0..200_u8).collect(),
        },
        ClientMsg::Resize(Size::new(50, 132)),
        ClientMsg::Resize(Size::new(1000, 1000)),
        ClientMsg::Ack {
            frame: FrameNum(70_000),
        },
        ClientMsg::Resync,
        ClientMsg::History(HistoryRequest {
            newest: 70_000,
            count: 256,
        }),
    ]
}

/// `hex` as bytes, or `None` if it is not an even run of hex digits.
fn unhex(hex: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = hex.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            (pair.len() == 2).then_some(())?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

/// `bytes` as lowercase hex, for readable failures.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The postcard encoding of [`full_frame`].
const FULL_FRAME: &str =
    "ac020081010106140109746865207469746c6501087468652069636f6e0108614756736247383d02010300020401\
    010101030200060000080401610000000000000103e697a501000000000001000200000000000103e69cac010000\
    0000000100020000000000010365cc81000000000000020120000000000000090000000000000000010009010172\
    0001010000000001016700010a000000000101700001c80000000001017400020102030000000001015200000104\
    0000000101470000010b000000010150000001640000000101540000020405060000000c00000000000000000200\
    07010142000000000100010144000000000200010149000000000400010155000000000800010156000000001000\
    010141000000001f000e000000000000000003000d01014b0000000080010001016b000000008002000101480000\
    0000a0020001015300000000e0020001017500000001090800010176000000020708090800010163000000008808\
    00010164000000008804000101770000000088100001014c0000000000010119f09f91a8e2808df09f91a9e2808d\
    f09f91a7e2808df09f91a601000000000001000200000000000800000000000000011468747470733a2f2f6b6f68\
    2e6578616d706c652f016b04011401016100000000000001012000000000000001016c0000000000000101690000\
    0000000001016e00000000000001016500000000000001012000000000000001016c00000000000001016f000000\
    00000001016e00000000000001016700000000000001012000000000000001016500000000000001016e00000000\
    000001016f0000000000000101750000000000000101670000000000000101680000000000000101200000000000\
    000101740000000000000005000701016f0000000000000101200000000000000101770000000000000101720000\
    000000000101610000000000000101700000000000000e0000000000000000";

/// [`full_frame`] as its stream carries it, compressed.
const FULL_FRAME_STREAM: &str =
    "75d1bd4ec3301007f0fb3b699bf025862e4cf409e88a9018404805c180f8e85e5aaba91a9aa8752963bbb13030b1\
    20c1c297d40761e0211003338f80cfae23418407fb27c777179f692a680214cb0855242baaa3628980d969263d04\
    8d5a7d70565bdf14f048f8d0c31354240a7c34c80c785fb78fb024e1b6eea67fb7e4fbc40608542c429a0d5008f4\
    0926046813e6ac52c29b95d261c2b33ed2936f54d3d3bcd1a19e5a4627ba825fd0bf480b2ebfa012b06d2b013b76\
    0bd863f81aa78c40a3ce58d6d862acd292cbe0d122b0cf1a738aae11e7d8653db08e591fac21170a39df05572a05\
    c64dfe7ec56a1971e19111173cb08dc0caf7fdcdcbe7f85a2faf7679b6cbd3ef7e06ae75e548a974b051ad769368\
    4d5e36ced35856d1f55146f642aee140ecd071e839c8ff0f27b9c3eddc61993b93450d7351512e5ccdee53e0a74a\
    729f470e7d87ec6ea945f6543f";

/// The postcard encoding of [`incremental_frame`].
const INCREMENTAL_FRAME: &str =
    "ad02ac028201000000000200000508010101010302000105000901016c0000000000000101610000000000000101\
    7300000000000001017400000000000001012000000000000001017200000000000001016f000000000000010177\
    0000000000000c0000000000000000";

/// [`incremental_frame`] as its stream carries it, compressed.
const INCREMENTAL_FRAME_STREAM: &str =
    "35c6c109c0201004c0dd0b42022922ade52f082af8b71eed5151775e836ecd2a3119e06e4e97810e0fe9b190bf92\
    94ac7c4a548252765e1c03";

/// The postcard encoding of each of [`modes`].
const MODES: [&str; 8] = [
    "000000000000",
    "000000000100",
    "000000000200",
    "000000000300",
    "000000000400",
    "000000000201",
    "000000000202",
    "010101010000",
];

/// Each of [`client_msgs`] as the client's stream carries it, length prefix included.
const CLIENT_MSGS: [&str; 7] = [
    "0000000a0001076c73202d6c610d",
    "000000cd00ac02c801000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324\
        25262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152\
        535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80\
        8182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadae\
        afb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7",
    "0000000401328401",
    "0000000501e807e807",
    "0000000402f0a204",
    "0000000103",
    "0000000604f0a2048002",
];

/// The postcard encoding of [`scrolled_frame`].
const SCROLLED_FRAME: &str =
    "ae02ad028201000000000200010101050b010101010302010105010105000b010173000000000000010163000000\
    00000001017200000000000001016f00000000000002016c00000000000001016500000000000001016400000000\
    000001012000000000000001016900000000000001016e000000000000090000000000000000";

/// [`scrolled_frame`] as its stream carries it, compressed.
const SCROLLED_FRAME_STREAM: &str =
    "35c8c10980401043d124e2416cc2ded483200ada81fd688d86ddcd6718de0c3ebd7a082790ec472f76b23cf075a3\
    44cec1159c15e29ecf1a2cc1146cc15131a0f503";

/// The postcard encoding of [`history_reply`], as a server message.
const HISTORY_REPLY: &str =
    "01020100080401610000000000000103e697a501000000000001000200000000000103e69cac0100000000000100\
    020000000000010365cc810000000000000201200000000000000900000000000000000200090101720001010000\
    000001016700010a000000000101700001c800000000010174000201020300000000010152000001040000000101\
    470000010b000000010150000001640000000101540000020405060000000c0000000000000000";

#[test]
fn history_rows_encode_as_pinned() {
    let reply = history_reply().expect("reply");
    assert_eq!(reply.rows.len(), 2, "two rows scrolled off");
    let pinned = unhex(HISTORY_REPLY).expect("hex");
    let msg = ServerMsg::History(reply.clone());
    let encoded = encode_history(&reply).expect("encodes");
    assert_eq!(decode_server(&encoded).expect("decodes"), msg);
    let raw = miniz_oxide::inflate::decompress_to_vec(&encoded).expect("inflates");
    assert_eq!(hex(&raw), hex(&pinned));
    assert!(
        decode_frame(&encoded).is_err(),
        "history rows are not a frame"
    );
}

#[test]
#[ignore = "prints the pinned values, to paste after a deliberate change to the wire"]
fn print_pinned() {
    for (name, frame) in [
        ("FULL_FRAME", full_frame().expect("frame")),
        ("INCREMENTAL_FRAME", incremental_frame().expect("frame")),
        ("SCROLLED_FRAME", scrolled_frame().expect("frame")),
    ] {
        println!(
            "{name} {}",
            hex(&postcard::to_allocvec(&frame).expect("encodes"))
        );
        println!(
            "{name}_STREAM {}",
            hex(&encode_frame(&frame).expect("encodes"))
        );
    }
    let reply = history_reply().expect("reply");
    let raw = miniz_oxide::inflate::decompress_to_vec(&encode_history(&reply).expect("encodes"))
        .expect("inflates");
    println!("HISTORY_REPLY {}", hex(&raw));
    for msg in client_msgs() {
        println!("CLIENT {}", hex(&encode_client(&msg).expect("encodes")));
    }
}

#[test]
fn a_scrolled_frame_moves_rows() {
    let frame = scrolled_frame().expect("frame");
    let shifts: Vec<_> = frame.diff.shifts.iter().collect();
    assert_eq!(shifts.len(), 1);
    assert_eq!(
        (shifts[0].top, shifts[0].len.get(), shifts[0].by.get()),
        (1, 5, -1)
    );
    assert_eq!(frame.diff.rows.len(), 1, "only the new line is sent");
}

#[test]
fn client_messages_encode_as_pinned() {
    let msgs = client_msgs();
    assert_eq!(msgs.len(), CLIENT_MSGS.len());
    for (msg, pinned) in msgs.iter().zip(CLIENT_MSGS) {
        let pinned = unhex(pinned).expect("hex");
        assert_eq!(
            hex(&encode_client(msg).expect("encodes")),
            hex(&pinned),
            "{msg:?}"
        );
        let mut decoder = ClientDecoder::default();
        decoder.push(&pinned);
        assert_eq!(decoder.next_msg().expect("decodes").as_ref(), Some(msg));
        decoder.finish().expect("nothing left over");
    }
}

#[test]
fn frames_encode_as_pinned() {
    for (frame, pinned, stream) in [
        (full_frame().expect("frame"), FULL_FRAME, FULL_FRAME_STREAM),
        (
            incremental_frame().expect("frame"),
            INCREMENTAL_FRAME,
            INCREMENTAL_FRAME_STREAM,
        ),
        (
            scrolled_frame().expect("frame"),
            SCROLLED_FRAME,
            SCROLLED_FRAME_STREAM,
        ),
    ] {
        let pinned = unhex(pinned).expect("hex");
        assert_eq!(
            hex(&postcard::to_allocvec(&frame).expect("encodes")),
            hex(&pinned),
            "frame {:?}",
            frame.num
        );
        assert_eq!(
            postcard::from_bytes::<Frame>(&pinned).expect("decodes"),
            frame
        );
        // The compressed stream is pinned only through decoding: DEFLATE may pick other bytes
        // for the same body.
        let stream = unhex(stream).expect("hex");
        assert_eq!(decode_frame(&stream).expect("decodes"), frame);
        assert_eq!(
            decode_frame(&encode_frame(&frame).expect("encodes")).expect("decodes"),
            frame
        );
    }
}

#[test]
fn a_control_character_in_a_cell_fails_to_decode() {
    // The first run of the full frame is four 'a's: count 4, then the 1-byte text 'a'. The same
    // frame with ESC in place of the 'a' must be refused, not printed to the user's terminal.
    let pinned = unhex(FULL_FRAME).expect("hex");
    let run = [4, 1, b'a'];
    let at = pinned
        .windows(run.len())
        .position(|window| window == run)
        .expect("the first run");
    let mut escaped = pinned.clone();
    escaped[at + 2] = 0x1b;
    assert!(postcard::from_bytes::<Frame>(&pinned).is_ok());
    assert!(postcard::from_bytes::<Frame>(&escaped).is_err());
}

#[test]
fn modes_encode_as_pinned() {
    let modes = modes();
    assert_eq!(modes.len(), MODES.len());
    for (modes, pinned) in modes.iter().zip(MODES) {
        let pinned = unhex(pinned).expect("hex");
        assert_eq!(
            hex(&postcard::to_allocvec(modes).expect("encodes")),
            hex(&pinned),
            "{modes:?}"
        );
        assert_eq!(
            &postcard::from_bytes::<WireModes>(&pinned).expect("decodes"),
            modes
        );
    }
}
