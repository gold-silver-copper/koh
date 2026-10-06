//! The koh/3 encoding, pinned.
//!
//! Each value below is built the same way on every commit and encoded; the expected bytes were
//! captured by running the encoder, not written by hand. A change to the wire must change these
//! bytes in the same commit, deliberately.

use koh::events::{
    InputEvent, WireButton, WireColours, WireKey, WireKeyCode, WireKitty, WireMouse,
    WireMouseAction, WireScheme,
};
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
fn full_frame() -> Result<(Frame, TerminalScreen), fux_vt::Error> {
    let base = TerminalScreen::default();
    let frame = Frame {
        num: FrameNum(300),
        base: FrameNum::BLANK,
        echo_ack: InputSeq(129),
        diff: exited_screen()?.diff_from(&base),
    };
    Ok((frame, base))
}

/// An incremental frame: one row changed, no resize, the side channels unchanged.
fn incremental_frame() -> Result<(Frame, TerminalScreen), fux_vt::Error> {
    let mut emu = ServerTerminal::new(6, 20, 0)?;
    emu.process(OUTPUT);
    let base = emu.snapshot();
    emu.process(b"\x1b[6;1Hlast row");
    let frame = Frame {
        num: FrameNum(301),
        base: FrameNum(300),
        echo_ack: InputSeq(130),
        diff: emu.snapshot().diff_from(&base),
    };
    Ok((frame, base))
}

/// A frame that scrolls: the screen scrolled up a line and a line written at the bottom, the rest
/// moved rather than sent, and the line scrolled off kept in history.
fn scrolled_frame() -> Result<(Frame, TerminalScreen), fux_vt::Error> {
    let mut emu = ServerTerminal::new(6, 20, 10)?;
    emu.process(OUTPUT);
    let base = emu.snapshot();
    emu.process(b"\x1b[6;1H\r\nscrolled in");
    let frame = Frame {
        num: FrameNum(302),
        base: FrameNum(301),
        echo_ack: InputSeq(130),
        diff: emu.snapshot().diff_from(&base),
    };
    Ok((frame, base))
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
        ClientMsg::Keys {
            seq: InputSeq(2),
            events: vec![
                InputEvent::Key(WireKey {
                    key: WireKeyCode::Char('é'),
                    mods: 5,
                    kitty: None,
                }),
                InputEvent::Key(WireKey {
                    key: WireKeyCode::F(12),
                    mods: 0,
                    kitty: Some(WireKitty {
                        code: Some(57_399),
                        shifted: Some(65),
                        base: None,
                        mods: 0x84,
                    }),
                }),
                InputEvent::Mouse(WireMouse {
                    action: WireMouseAction::Release,
                    button: Some(WireButton::WheelDown),
                    mods: 2,
                    row: 300,
                    col: 7,
                }),
                InputEvent::Focus(true),
                InputEvent::Paste {
                    text: "hi".to_owned(),
                    first: true,
                    last: false,
                },
            ],
        },
        ClientMsg::Colours(WireColours {
            foreground: Some([0xdd, 0xdd, 0xdd]),
            background: None,
            palette: vec![None, Some([0xcd, 0, 0])],
            scheme: Some(WireScheme::Light),
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
    "ac020081010106140109746865207469746c6501087468652069636f6e0108614756736247383d02010300000204\
    01010101030200060000050401610000000000000206e697a5e69cac040000000000010365cc8100000000000002\
    01200000000000000900000000000000000100090101720001010000000001016700010a000000000101700001c8\
    00000000010174000201020300000000010152000001040000000101470000010b00000001015000000164000000\
    0101540000020405060000000c000000000000000002000701014200000000010001014400000000020001014900\
    0000000400010155000000000800010156000000001000010141000000001f000e000000000000000003000d0101\
    4b0000000080010001016b0000000080020001014800000000a0020001015300000000e002000101750000000109\
    08000101760000000207080908000101630000000088080001016400000000880400010177000000008810000101\
    4c0000000000010119f09f91a8e2808df09f91a9e2808df09f91a7e2808df09f91a6010000000000010002000000\
    00000800000000000000011468747470733a2f2f6b6f682e6578616d706c652f016b040101141461206c696e6520\
    6c6f6e6720656e6f75676820740300000000000005000206066f20777261700300000000000e0000000000000000";

/// [`full_frame`] as its stream carries it, compressed.
const FULL_FRAME_STREAM: &str =
    "0000060001020304053dd1bb4ec3301406e0f33b6948b889210b137e02ba22240610524130202edd436b35554312\
    b52e656c37160626162458b8497d10061e023174e611f0b1533cd89f6df91cfb782a68020431229d2aa9bb3a5308\
    99dd5691234c1acdc165636b47c023123e4cf3040544351f09d92682d9c3cbec71eadb193cf535a936201d22aa1a\
    2802fa04d8093a8445a792f0e9a4cd31e1399f9aceb76a986ec9eac4746dab73be50cd5c8596e7f1052d007b2e13\
    b0ef968043866f70c1080d9a8c35835dc606adce2378b4021cb1c61ca267c5310e58cfac33d6376bc889228e77cd\
    991642eb16efdfb2da569c7864c5098f5d21b0fefb74fffe33be33c3871bdedcf08aaa5482dc6dabd2c5a9d6e560\
    bb5eef15e9a6ba49aeca4cd5d1335f12c789ccbab992599177a4ca8b612795da73e76ae67f82428efa49e956fe9f\
    fa07";

/// The postcard encoding of [`incremental_frame`].
const INCREMENTAL_FRAME: &str =
    "ad02ac02820100000000020000000508010101010302000105000208086c61737420726f770300000000000c0000\
    000000000000";

/// [`incremental_frame`] as its stream carries it, compressed.
const INCREMENTAL_FRAME_STREAM: &str =
    "00ac02010535ccb10900200c0440f310f8c2215ccd5e1054b0771eddd122497bc53d5c1c0957ba8b2690adce5546\
    dfb6e4183e";

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
const CLIENT_MSGS: [&str; 9] = [
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
    "00000027050205000002c3a90500000f0c000101b7c003014100840101010402ac02070201030268690100",
    "0000000e0601dddddd00020001cd00000101",
];

/// The postcard encoding of [`scrolled_frame`].
const SCROLLED_FRAME: &str =
    "ae02ad02820100000000020001010100050b01010101030201010501010500020b0b7363726f6c6c656420696e03\
    0000000000090000000000000000";

/// [`scrolled_frame`] as its stream carries it, compressed.
const SCROLLED_FRAME_STREAM: &str =
    "00ad020105358cc1090020080055f0112ed16ed5239082daa07d6ac60411ee7507f7e8d241f7a680c50b221b4022\
    bbaca9da6aeec36f294e1f";

/// The postcard encoding of [`history_reply`], as a server message.
const HISTORY_REPLY: &str =
    "020100050401610000000000000206e697a5e69cac040000000000010365cc810000000000000201200000000000\
    000900000000000000000200090101720001010000000001016700010a000000000101700001c800000000010174\
    000201020300000000010152000001040000000101470000010b0000000101500000016400000001015400000204\
    05060000000c0000000000000000";

#[test]
fn history_rows_encode_as_pinned() {
    let reply = history_reply().expect("reply");
    assert_eq!(reply.rows.len(), 2, "two rows scrolled off");
    let pinned = unhex(HISTORY_REPLY).expect("hex");
    let msg = ServerMsg::History(reply.clone());
    let encoded = encode_history(&reply).expect("encodes");
    assert_eq!(decode_server(&encoded).expect("decodes"), msg);
    let raw = miniz_oxide::inflate::decompress_to_vec(&encoded[1..]).expect("inflates");
    assert_eq!(hex(&raw), hex(&pinned));
    assert!(
        decode_frame(&encoded, &TerminalScreen::default()).is_err(),
        "history rows are not a frame"
    );
}

#[test]
#[ignore = "prints the pinned values, to paste after a deliberate change to the wire"]
fn print_pinned() {
    for (name, (frame, base)) in [
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
            hex(&encode_frame(&frame, &base).expect("encodes"))
        );
    }
    let reply = history_reply().expect("reply");
    let raw =
        miniz_oxide::inflate::decompress_to_vec(&encode_history(&reply).expect("encodes")[1..])
            .expect("inflates");
    println!("HISTORY_REPLY {}", hex(&raw));
    for msg in client_msgs() {
        println!("CLIENT {}", hex(&encode_client(&msg).expect("encodes")));
    }
}

#[test]
fn a_scrolled_frame_moves_rows() {
    let (frame, _) = scrolled_frame().expect("frame");
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
    for ((frame, base), pinned, stream) in [
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
        // for the same body. It inflates only against its base's dictionary.
        let stream = unhex(stream).expect("hex");
        assert_eq!(decode_frame(&stream, &base).expect("decodes"), frame);
        assert_eq!(
            decode_frame(&encode_frame(&frame, &base).expect("encodes"), &base).expect("decodes"),
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
