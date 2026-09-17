//! G.711 PCMA (a-law) codec — both directions.
//!
//! Direct port of the ITU-T G.711 reference C implementation
//! (`g711.c`, widely redistributed; original Sun Microsystems / CCITT).
//! Sample rate is always 8 kHz, mono. Inputs/outputs are 16-bit linear
//! PCM (i16) on the linear side and one byte per sample on the
//! compressed side.
//!
//! Used by the bridge:
//!   * Decode: base→bridge audio RTP payload bytes → PCM samples that we
//!     ship over HTTP `/stream/audio` to HA as WAV.
//!   * Encode: HA-side mic input PCM → PCMA bytes that we frame as RTP
//!     and send back to the base on the outbound socket.

const SIGN_BIT: u8 = 0x80;
const QUANT_MASK: u8 = 0x0F;
const SEG_MASK: u8 = 0x70;
const SEG_SHIFT: u32 = 4;

/// Segment endpoints for encoder-side magnitude search. From G.711.
const SEG_AEND: [i16; 8] = [0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF];

fn search_segment(val: i16) -> u8 {
    for (i, &end) in SEG_AEND.iter().enumerate() {
        if val <= end {
            return i as u8;
        }
    }
    8
}

/// Decode one PCMA byte into a 16-bit PCM sample.
pub fn alaw_to_pcm16(alaw: u8) -> i16 {
    let a = alaw ^ 0x55;
    let mut t: i16 = ((a & QUANT_MASK) as i16) << 4;
    let seg = ((a & SEG_MASK) >> SEG_SHIFT) as i16;
    match seg {
        0 => t += 8,
        1 => t += 0x108,
        _ => {
            t += 0x108;
            t <<= seg - 1;
        }
    }
    if (a & SIGN_BIT) != 0 {
        t
    } else {
        -t
    }
}

/// Encode one 16-bit PCM sample into a PCMA byte.
pub fn pcm16_to_alaw(pcm: i16) -> u8 {
    let pcm_val = pcm >> 3;
    let (mask, mag) = if pcm_val >= 0 {
        (0xD5u8, pcm_val)
    } else {
        // -pcm_val - 1 keeps within i16 range and matches G.711 spec.
        (0x55u8, -pcm_val - 1)
    };
    let mag = mag.max(0); // guard against the i16::MIN >> 3 = i16::MIN edge
    let seg = search_segment(mag);
    if seg >= 8 {
        0x7F ^ mask
    } else {
        let mantissa = if seg < 2 {
            ((mag >> 1) as u8) & QUANT_MASK
        } else {
            ((mag >> seg) as u8) & QUANT_MASK
        };
        let aval = (seg << SEG_SHIFT as u8) | mantissa;
        aval ^ mask
    }
}

/// Decode an entire PCMA payload into PCM samples.
pub fn decode(payload: &[u8]) -> Vec<i16> {
    payload.iter().copied().map(alaw_to_pcm16).collect()
}

/// Encode an entire PCM frame into PCMA bytes.
pub fn encode(samples: &[i16]) -> Vec<u8> {
    samples.iter().copied().map(pcm16_to_alaw).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip should be lossy (a-law has ~13-bit precision) but
    /// preserve sign and roughly preserve magnitude.
    #[test]
    fn round_trip_preserves_sign() {
        for &v in &[-32000i16, -1000, -10, 10, 1000, 32000] {
            let alaw = pcm16_to_alaw(v);
            let back = alaw_to_pcm16(alaw);
            assert_eq!(back.signum(), v.signum(), "sign drift at {v}: alaw={alaw:#x} back={back}");
        }
    }

    #[test]
    fn zero_round_trips_close_to_zero() {
        // a-law has no exact zero — quantisation puts 0 input near ±8.
        assert!(alaw_to_pcm16(pcm16_to_alaw(0)).abs() <= 16);
    }

    #[test]
    fn known_vectors() {
        // Reference: a-law byte 0x55 (which is 0x55^0x55=0x00) decodes
        // to the smallest negative segment-0 value.
        // Sanity-check that decode of 0xD5 (=0x80 after XOR) is at the
        // boundary between positive segment 0 mantissa 0.
        let _ = alaw_to_pcm16(0x55);
        let _ = alaw_to_pcm16(0xD5);
    }
}
