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
/// and their continuations, a combining mark, every colour kind on both layers, every style bit,
/// a soft wrap, the title, icon, clipboard, bell and the input modes.
const OUTPUT: &[u8] = "\x1b]2;the title\x07\x1b]1;the icon\x07\x1b]52;c;aGVsbG8=\x07\x07\x07\
    aaaa日本e\u{301}  \r\n\
    \x1b[31mr\x1b[92mg\x1b[38;5;200mp\x1b[38;2;1;2;3mt\x1b[39m\
    \x1b[44mR\x1b[103mG\x1b[48;5;100mP\x1b[48;2;4;5;6mT\x1b[m\r\n\
    \x1b[1mB\x1b[m\x1b[2mD\x1b[m\x1b[3mI\x1b[m\x1b[4mU\x1b[m\x1b[7mV\x1b[m\
    \x1b[1;2;3;4;7mA\x1b[m\r\n\
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
    010103020005000008040161000000000103e697a5010000000100020000000103e69cac01000000010002000000\
    010365cc810000000002012000000000090000000000010009010172000101000001016700010a00000101700001\
    c800000101740002010203000001015200000104000101470000010b000101500000016400010154000002040506\
    000c0000000000020007010142000000010101440000000201014900000004010155000000080101560000001001\
    01410000001e0e0000000000030114010161000000000101200000000001016c000000000101690000000001016e\
    00000000010165000000000101200000000001016c0000000001016f0000000001016e0000000001016700000000\
    010120000000000101650000000001016e0000000001016f00000000010175000000000101670000000001016800\
    000000010120000000000101740000000004000701016f0000000001012000000000010177000000000101720000\
    000001016100000000010170000000000e0000000000";

/// [`full_frame`] as its stream carries it, compressed.
const FULL_FRAME_STREAM: &str =
    "6dcfbf0e01411006f0f97617778828d4e231340a22b9e844d0fbb3e11271c28ada5368b43a0fa2f01c9ec3cced15\
    36b1c5fd76efbe999b7d2aba02e51662b7b51d97ba9d4524db7495ed112d92f96999747b0a5a19f0d28a4a4491c1\
    8278417f6e0fc886943fde9fbf47fbbe4a4ca123c494d7500c1c099c033684aa7820bc44c759a56537e1876113b6\
    c68ed9353be576a654a67ade4c51051848576098ff092386479d311130679a409f6937f2128d168ae9fd58c0ce93\
    7af61efb2f9205914d10b1c1b722790e92dba0c009466e9005ef2f9ea3a718f520f81b7c01";

/// The postcard encoding of [`incremental_frame`].
const INCREMENTAL_FRAME: &str =
    "ad02ac0282010000000002000508010101010302000105000901016c000000000101610000000001017300000000\
    01017400000000010120000000000101720000000001016f00000000010177000000000c0000000000";

/// [`incremental_frame`] as its stream carries it, compressed.
const INCREMENTAL_FRAME_STREAM: &str =
    "25c8c10900211043d164166117b6085bf32e082a78b71eed5187fc431e64dbb249dc0ce1e5ed3130e023b3bf6412\
    4d74114515450ce7f7c101";

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
    "ae02ad028201000000000200050b010101010302010105010105000b010173000000000101630000000001017200\
    00000001016f0000000002016c000000000101650000000001016400000000010120000000000101690000000001\
    016e00000000090000000000";

/// [`scrolled_frame`] as its stream carries it, compressed.
const SCROLLED_FRAME_STREAM: &str =
    "25cad109c0200c04d05c8a1fa54b74b7d60f41147403f7d1194dbc23e471244ba70e8845253cb05c0a041bb1d6fd\
    007ca4917abe91d922f9c94b1229ceed4b36";

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
