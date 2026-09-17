//! Minimal RFC 6184 RTP H.264 depacketizer.
//!
//! Input: a sequence of RTP payload byte slices (the bytes AFTER the
//! 12-byte RTP header has been stripped). One slice per inbound RTP
//! packet, in receive order.
//!
//! Output: zero or more Annex-B-formatted NAL units. Each output buffer
//! is `00 00 00 01 <NALU bytes>` so an `ffmpeg -f h264` consumer can
//! demux directly. Multiple NAL units in one input packet (STAP-A) are
//! emitted as separate outputs in order.
//!
//! Supports the three formats actually seen in Panasonic VIANA video
//! streams:
//!   - Single NAL Unit Packet (NAL types 1..=23): the payload IS the
//!     NAL unit. Pass through with start code prepended.
//!   - STAP-A (NAL type 24): an aggregation of complete NAL units, each
//!     16-bit length-prefixed. Split and emit each.
//!   - FU-A (NAL type 28): fragmentation across multiple RTP packets.
//!     Reassembled into a single NAL unit at the End-fragment.
//!
//! Skipped (not seen in our captures so far): STAP-B (25), MTAP16 (26),
//! MTAP24 (27), FU-B (29). If we hit them the depacketizer logs a
//! warning and drops the packet.

const ANNEX_B_START: &[u8] = &[0x00, 0x00, 0x00, 0x01];

#[derive(Default)]
pub struct H264Depacketizer {
    /// Accumulating buffer for the current FU-A NAL unit. Holds the
    /// reconstructed NAL header byte at index 0 plus all fragment
    /// payloads. Cleared on each completed NALU.
    fua_buffer: Vec<u8>,
    /// True between FU-A Start and FU-A End. If End never arrives
    /// (packet loss), the partial NALU is discarded on the next Start.
    in_fua: bool,
}

impl H264Depacketizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one RTP payload. Returns the Annex-B NAL units (already
    /// prefixed with start codes) extracted from this packet, if any.
    /// Most packets yield 0 or 1 NAL units; STAP-A can yield many.
    pub fn push(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        if payload.is_empty() {
            return Vec::new();
        }
        let nal_header = payload[0];
        let nal_type = nal_header & 0x1F;
        match nal_type {
            1..=23 => {
                // Single NAL Unit Packet. If we were in FU-A mid-stream,
                // discard the partial — packet loss likely.
                self.reset_fua();
                let mut out = Vec::with_capacity(ANNEX_B_START.len() + payload.len());
                out.extend_from_slice(ANNEX_B_START);
                out.extend_from_slice(payload);
                vec![out]
            }
            24 => {
                // STAP-A: skip the 1-byte STAP header, then walk
                // [size:u16][NALU bytes][size:u16][NALU bytes]...
                self.reset_fua();
                let mut out = Vec::new();
                let body = &payload[1..];
                let mut i = 0;
                while i + 2 <= body.len() {
                    let sz = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
                    i += 2;
                    if i + sz > body.len() {
                        // Malformed; bail out without yielding more.
                        break;
                    }
                    let nalu = &body[i..i + sz];
                    let mut buf = Vec::with_capacity(ANNEX_B_START.len() + nalu.len());
                    buf.extend_from_slice(ANNEX_B_START);
                    buf.extend_from_slice(nalu);
                    out.push(buf);
                    i += sz;
                }
                out
            }
            28 => {
                // FU-A. Need at least 2 bytes (FU indicator + FU header).
                if payload.len() < 2 {
                    return Vec::new();
                }
                let fu_indicator = payload[0];
                let fu_header = payload[1];
                let start = (fu_header & 0x80) != 0;
                let end = (fu_header & 0x40) != 0;
                let original_type = fu_header & 0x1F;
                let frag = &payload[2..];

                if start {
                    // Reset and write the reconstructed NAL header byte.
                    self.fua_buffer.clear();
                    self.fua_buffer
                        .push((fu_indicator & 0xE0) | original_type);
                    self.in_fua = true;
                }
                if !self.in_fua {
                    // Middle/end fragment without seeing Start —
                    // packet loss, drop.
                    return Vec::new();
                }
                self.fua_buffer.extend_from_slice(frag);
                if end {
                    let mut out = Vec::with_capacity(
                        ANNEX_B_START.len() + self.fua_buffer.len(),
                    );
                    out.extend_from_slice(ANNEX_B_START);
                    out.extend_from_slice(&self.fua_buffer);
                    self.reset_fua();
                    return vec![out];
                }
                Vec::new()
            }
            _ => {
                // Unsupported (STAP-B, MTAP, FU-B). Drop silently;
                // these are rare in the wild and not seen in our
                // VIANA captures.
                Vec::new()
            }
        }
    }

    fn reset_fua(&mut self) {
        self.fua_buffer.clear();
        self.in_fua = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_nalu_passthrough() {
        let mut d = H264Depacketizer::new();
        // NAL type 5 (IDR slice), nri=3
        let pkt = vec![0x65, 0xAA, 0xBB, 0xCC];
        let out = d.push(&pkt);
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0][..4], &[0x00, 0x00, 0x00, 0x01]);
        assert_eq!(&out[0][4..], &pkt[..]);
    }

    #[test]
    fn fua_reassembly() {
        let mut d = H264Depacketizer::new();
        // FU indicator: type 28, NRI 3 → 0x7C
        // FU header start: S=1 E=0 type=5 → 0x85
        // FU header mid:   S=0 E=0 type=5 → 0x05
        // FU header end:   S=0 E=1 type=5 → 0x45
        let s = vec![0x7C, 0x85, 0x11, 0x22];
        let m = vec![0x7C, 0x05, 0x33, 0x44];
        let e = vec![0x7C, 0x45, 0x55, 0x66];
        assert!(d.push(&s).is_empty());
        assert!(d.push(&m).is_empty());
        let out = d.push(&e);
        assert_eq!(out.len(), 1);
        // Reconstructed NAL header: NRI 3 + type 5 → 0x65
        assert_eq!(&out[0][..5], &[0x00, 0x00, 0x00, 0x01, 0x65]);
        // Concatenated payload bytes
        assert_eq!(&out[0][5..], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn stap_a_split() {
        let mut d = H264Depacketizer::new();
        // STAP-A header (type 24, nri 3)
        // First NALU size 2: [0x67, 0x42]
        // Second NALU size 1: [0x68]
        let pkt = vec![0x78, 0x00, 0x02, 0x67, 0x42, 0x00, 0x01, 0x68];
        let out = d.push(&pkt);
        assert_eq!(out.len(), 2);
        assert_eq!(&out[0], &[0x00, 0x00, 0x00, 0x01, 0x67, 0x42]);
        assert_eq!(&out[1], &[0x00, 0x00, 0x00, 0x01, 0x68]);
    }
}
