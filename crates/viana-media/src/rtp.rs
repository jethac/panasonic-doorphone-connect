//! RTP framing — outbound packet builder.
//!
//! For inbound, the daemon does ad-hoc parsing inline (see
//! `viana-ha::receive_rtp_loop`); the receiver doesn't need a full
//! parser since the only field it cares about beyond payload is the
//! challenge marker (bit-4 in byte 0). Outbound we need a real frame
//! builder so the base accepts our packets.
//!
//! Reference: RFC 3550 §5.1 (the fixed 12-byte header). No CSRCs,
//! no extension, no padding. Layout:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|X|  CC=0 |M|     PT      |       sequence number         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           timestamp                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            SSRC                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! After this header the Panasonic base expects payload bytes that have
//! been XOR-encrypted by `viana_media::xor::unwrap_in_place` starting
//! at offset 12 (i.e. the payload, NOT the header).

/// Stateful outbound RTP sequencer. One per outbound stream (e.g. one
/// for the audio-back-to-base path). Sequence wraps at u16::MAX.
pub struct RtpSender {
    pub payload_type: u8,
    pub ssrc: u32,
    pub seq: u16,
    pub timestamp: u32,
}

impl RtpSender {
    pub fn new(payload_type: u8, ssrc: u32) -> Self {
        Self {
            payload_type,
            ssrc,
            seq: 0,
            timestamp: 0,
        }
    }

    /// Build one outbound RTP packet wrapping `payload` (already-encoded
    /// PCMA bytes for audio, or NALU bytes for video). Returns 12 +
    /// payload.len() bytes. Payload is NOT XOR-encrypted here — caller
    /// applies `viana_media::xor::unwrap_in_place(..., 12)` after.
    pub fn build(&mut self, payload: &[u8], timestamp_step: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + payload.len());
        // V=2, P=0, X=0, CC=0 → 0x80
        buf.push(0x80);
        // M=0, PT
        buf.push(self.payload_type & 0x7F);
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        buf.extend_from_slice(payload);
        self.seq = self.seq.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(timestamp_step);
        buf
    }
}

/// Parse just enough of an inbound RTP packet to expose the payload
/// offset. RFC says the fixed header is 12 bytes plus 4 × CC for CSRC
/// list. The Panasonic base sends CC=0 in practice so the payload
/// starts at byte 12, but we honour the field for safety.
pub fn payload_offset(packet: &[u8]) -> Option<usize> {
    if packet.len() < 12 {
        return None;
    }
    let cc = (packet[0] & 0x0F) as usize;
    let off = 12 + cc * 4;
    if packet.len() < off {
        return None;
    }
    Some(off)
}
