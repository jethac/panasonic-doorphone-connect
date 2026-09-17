//! Media-path crate. RTP framing, the 8-byte-repeating XOR transform,
//! G.711 PCMA codec, H.264 depacketization, and the challenge response.
//! See `docs/PROTOCOL.md`.

pub mod rtp;
pub mod xor;
pub mod pcma;
pub mod challenge;
pub mod h264;
