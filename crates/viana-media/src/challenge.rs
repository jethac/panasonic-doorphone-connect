//! `CreateResponsePakcet` challenge-response handler.
//!
//! At the start of every base→bridge media flow the base sends a 56-byte
//! challenge packet (`bit-4` in byte 0, halfword `0x0100` at +0x0c, halfword
//! `0x2800` at +0x0e in WIRE form, body size 0x28). The bridge must reply
//! with a 58-byte response computed from the per-call `xorAuthA` and
//! `xorAuthB` from the kick-channel SDP. Without the response, the base
//! keeps sending challenges every ~500ms and never advances to media.
//!
//! Algorithm reverse-engineered from a paired capture
//! (challenge then response):
//!   - bytes 0-15: copy from challenge, except byte 0 has its low nibble set
//!     to 1 (RTP `CC` field becomes 1 — Panasonic uses this as the
//!     "is-response" marker)
//!   - bytes 16-55: challenge[16..56] XOR repeating-8-byte (AuthA XOR AuthB)
//!   - bytes 56-57: trailing `0x01 0x00`
//!
//! The bytes operated on are WIRE-form (i.e. with the per-call XOR layer
//! still applied). In the bridge's receive loop the simplest place to apply
//! this transform is BEFORE the standard XOR-decrypt step.

/// Returns true if `wire_packet` is a challenge that needs a response.
/// We use the byte-0 X bit (0x10) as the cheap identification — it's on
/// challenge packets, off on actual media. Verified empirically.
pub fn is_challenge(wire_packet: &[u8]) -> bool {
    wire_packet.len() == 56 && (wire_packet[0] & 0x10) != 0
}

/// Build the 58-byte response to a 56-byte challenge.
///
/// `auth_a` and `auth_b` come from the per-call SDP `a=key-mgmt:xorAuthA` and
/// `xorAuthB` lines (8 bytes each, Base64-decoded by the SDP parser).
pub fn build_response(
    wire_challenge: &[u8],
    auth_a: [u8; 8],
    auth_b: [u8; 8],
) -> Vec<u8> {
    assert_eq!(
        wire_challenge.len(),
        56,
        "challenge packet must be exactly 56 bytes"
    );
    let mut out = Vec::with_capacity(58);

    // Bytes 0..15: copy header + ext-header.
    out.extend_from_slice(&wire_challenge[..16]);
    // Byte 0: clear CC nibble, set to 1 (Panasonic's "is-response" marker).
    out[0] = (out[0] & 0xF0) | 0x01;

    // Bytes 16..55: challenge body XOR (AuthA XOR AuthB), 8-byte repeating.
    let key_xor: [u8; 8] = std::array::from_fn(|i| auth_a[i] ^ auth_b[i]);
    for i in 0..40 {
        out.push(wire_challenge[16 + i] ^ key_xor[i & 7]);
    }

    // Bytes 56..57: fixed trailer.
    out.extend_from_slice(&[0x01, 0x00]);

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured 56-byte UDP challenge from a live call (protocol fixture).
    const WIRE_CHALLENGE: &[u8] = &[
        0x90, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x86, 0x91, 0xa7, 0x80, 0x00, 0x01, 0x00, 0x28,
        0x2e, 0x6f, 0x49, 0x04, 0x88, 0x47, 0xac, 0x0d,
        0x86, 0x93, 0x24, 0x49, 0xef, 0x5b, 0x50, 0x77,
        0x0f, 0x4d, 0xb3, 0x98, 0x4d, 0x0e, 0x42, 0xf1,
        0x78, 0x50, 0xce, 0x83, 0xae, 0x9d, 0xb8, 0xa5,
        0x34, 0xbb, 0xa9, 0x93, 0x0e, 0x14, 0xdb, 0x3d,
    ];

    /// The phone's response — captured frame 166. 58 bytes.
    const WIRE_RESPONSE: &[u8] = &[
        0x91, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x86, 0x91, 0xa7, 0x80, 0x00, 0x01, 0x00, 0x28,
        0x2d, 0x8b, 0x9e, 0x4c, 0x30, 0x2c, 0xeb, 0x4b,
        0x85, 0x77, 0xf3, 0x01, 0x57, 0x30, 0x17, 0x31,
        0x0c, 0xa9, 0x64, 0xd0, 0xf5, 0x65, 0x05, 0xb7,
        0x7b, 0xb4, 0x19, 0xcb, 0x16, 0xf6, 0xff, 0xe3,
        0x37, 0x5f, 0x7e, 0xdb, 0xb6, 0x7f, 0x9c, 0x7b,
        0x01, 0x00,
    ];

    /// xorAuthA + xorAuthB for the same call, captured from logcat at
    /// 2026-05-06 15:31:32 (`StreamManager.setVideoCrypt`):
    ///   xorAuthA: J9vx5tDu6XM=  →  27 db f1 e6 d0 ee e9 73
    ///   xorAuthB: JD8mrmiFrjU=  →  24 3f 26 ae 68 85 ae 35
    const AUTH_A: [u8; 8] = [0x27, 0xdb, 0xf1, 0xe6, 0xd0, 0xee, 0xe9, 0x73];
    const AUTH_B: [u8; 8] = [0x24, 0x3f, 0x26, 0xae, 0x68, 0x85, 0xae, 0x35];

    #[test]
    fn detects_challenge_packet() {
        assert!(is_challenge(WIRE_CHALLENGE));
    }

    #[test]
    fn produces_captured_response_byte_for_byte() {
        let resp = build_response(WIRE_CHALLENGE, AUTH_A, AUTH_B);
        assert_eq!(resp.len(), 58);
        assert_eq!(
            resp.as_slice(),
            WIRE_RESPONSE,
            "response must match the legitimate phone's bytes"
        );
    }

    #[test]
    fn ignores_non_challenge_packets() {
        // A 24-byte media packet from frame 168, X bit clear (byte 0 = 0x80).
        let media = [
            0x80, 0x61, 0x00, 0x01, 0x91, 0x2c, 0x5b, 0xb7,
            0x86, 0x91, 0xa7, 0x80, 0xee, 0xba, 0xea, 0xd5,
        ];
        assert!(!is_challenge(&media));
    }
}
