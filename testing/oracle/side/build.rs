//! What koh at this tree does, for a side that builds at any commit: `koh_frame_base` when it
//! compresses frames against their base (`encode_frame(frame, base)`), and `koh_delivery_ack`
//! when the server takes a frame's delivery as its acknowledgement (the client sends none).

fn main() {
    let proto = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../src/proto.rs");
    println!("cargo::rerun-if-changed={}", proto.display());
    println!("cargo::rustc-check-cfg=cfg(koh_frame_base)");
    println!("cargo::rustc-check-cfg=cfg(koh_delivery_ack)");
    let source = std::fs::read_to_string(&proto).unwrap_or_default();
    if source.contains("pub fn encode_frame(frame: &Frame, base: &TerminalScreen)") {
        println!("cargo::rustc-cfg=koh_frame_base");
    }
    if source.contains("pub const ACK_DELAY") {
        println!("cargo::rustc-cfg=koh_delivery_ack");
    }
}
