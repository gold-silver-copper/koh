//! The koh/3 encoding, pinned.
//!
//! Each value below is built the same way on every commit and encoded; the expected bytes were
//! captured by running the encoder, not written by hand. A change to the wire must change these
//! bytes in the same commit, deliberately.

use koh::proto::{
    decode_frame, encode_client, encode_frame, ClientDecoder, ClientMsg, Frame, FrameNum, InputSeq,
};
use koh::terminal::{ServerTerminal, Size, TerminalScreen, WireModes};

/// Terminal output exercising every part of a cell and of the side channels: runs, wide glyphs
/// and their continuations, a combining mark, a cluster too long to keep inline, every colour kind
/// on both layers and as an underline's colour, every style bit and both blinks, curly, double and
/// dashed underlines, a soft wrap, the
/// title, icon, clipboard, bell and the input modes.
const OUTPUT: &[u8] = "\x1b]2;the title\x07\x1b]1;the icon\x07\x1b]52;c;aGVsbG8=\x07\x07\x07\
    aaaa日本e\u{301}  \r\n\
    \x1b[31mr\x1b[92mg\x1b[38;5;200mp\x1b[38;2;1;2;3mt\x1b[39m\
    \x1b[44mR\x1b[103mG\x1b[48;5;100mP\x1b[48;2;4;5;6mT\x1b[m\r\n\
    \x1b[1mB\x1b[m\x1b[2mD\x1b[m\x1b[3mI\x1b[m\x1b[4mU\x1b[m\x1b[7mV\x1b[m\
    \x1b[1;2;3;4;7mA\x1b[m\r\n\
    \x1b[5mK\x1b[6mk\x1b[8mH\x1b[9mS\x1b[m\x1b[4;58;5;9mu\x1b[58;2;7;8;9mv\x1b[m\
    \x1b[4:3mc\x1b[4:2md\x1b[4:5mw\x1b[m\
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
/// moved rather than sent.
fn scrolled_frame() -> Result<Frame, fux_vt::Error> {
    let mut emu = ServerTerminal::new(6, 20, 0)?;
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
    "ac020081010106140109746865207469746c6501087468652069636f6e0108614756736247383d02010302040101\
    01010302000600000804016100000000000103e697a50100000000010002000000000103e69cac01000000000100\
    0200000000010365cc81000000000002012000000000000900000000000001000901017200010100000001016700\
    010a0000000101700001c800000001017400020102030000000101520000010400000101470000010b0000010150\
    00000164000001015400000204050600000c00000000000002000701014200000000010101440000000002010149\
    000000000401015500000000080101560000000010010141000000001f0e00000000000003000c01014b00000000\
    800101016b00000000800201014800000000a00201015300000000e0020101750000000109080101760000000207\
    0809080101630000000088080101640000000088040101770000000088100119f09f91a8e2808df09f91a9e2808d\
    f09f91a7e2808df09f91a60100000000010002000000000900000000000004011401016100000000000101200000\
    00000001016c0000000000010169000000000001016e00000000000101650000000000010120000000000001016c\
    000000000001016f000000000001016e000000000001016700000000000101200000000000010165000000000001\
    016e000000000001016f000000000001017500000000000101670000000000010168000000000001012000000000\
    00010174000000000005000701016f00000000000101200000000000010177000000000001017200000000000101\
    61000000000001017000000000000e000000000000";

/// [`full_frame`] as its stream carries it, compressed.
const FULL_FRAME_STREAM: &str =
    "7590bb4ec3401045e7ae9dc48608a54843453e8386028464100de2913e24566211c55170489b743414543448d0f0\
    92f221147c04a2a0e61398995d4bb0122ef61cedde995dcfd2d002a836111783b45564c53045249a75f311a24ed2\
    be384b36b70c021382bfc05095280ad121f9107cdd3e428d8cdbb85bfedd48df179a35682963b2a5140313828481\
    3e6145654c785329b8c004aa47bc8422092fab2287bcf4444eb86f58e127d56d5743356047fb03bbf65aec0bf9f9\
    a7c208680b1bc0b67063cd560654070ec4e65c7aaec2b57b220f2cc7221f2c53691e739b4be95e8b44bb7278c5d2\
    53e1bb662a0dac7fdfdfbc7cceaf19af16cf164fbfa7e46612a28972b26e5ac0d031731c39a6ffe4722fd7f772a9\
    775ee6a75e7ee0d515ca8a0c38f78e668e13c7f217c64a37e01f";

/// The postcard encoding of [`incremental_frame`].
const INCREMENTAL_FRAME: &str =
    "ad02ac0282010000000002000508010101010302000105000901016c000000000001016100000000000101730000\
    00000001017400000000000101200000000000010172000000000001016f000000000001017700000000000c0000\
    00000000";

/// [`incremental_frame`] as its stream carries it, compressed.
const INCREMENTAL_FRAME_STREAM: &str =
    "2dc8cb0900211443d1e40dc20c4c11b6e65e1054706f3ddaa31f7217399069c33ab133b897bbc740878f8ce70519\
    6491557a996592edfadfc502";

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
const CLIENT_MSGS: [&str; 6] = [
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
];

/// The postcard encoding of [`scrolled_frame`].
const SCROLLED_FRAME: &str =
    "ae02ad028201000000000200050b010101010302010105010105000b010173000000000001016300000000000101\
    72000000000001016f000000000002016c0000000000010165000000000001016400000000000101200000000000\
    010169000000000001016e000000000009000000000000";

/// [`scrolled_frame`] as its stream carries it, compressed.
const SCROLLED_FRAME_STREAM: &str =
    "2dc9d10980301003d024d20f710977533f0451d00ddca79db1d723e1b8474853d54f4484b23032892c7188f68d01\
    e4665ffba4e2e57ed8ddaef6b4773ae74707";

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
