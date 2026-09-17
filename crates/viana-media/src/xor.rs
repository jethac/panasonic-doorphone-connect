//! 8-byte repeating XOR transform applied from offset 12 of every RTP packet.
//! See `docs/PROTOCOL.md`.

/// Apply the repeating 8-byte XOR to bytes `[offset..]` of `packet`.
/// `xor_data` is the 8-byte key from the per-call SDP `a=key-mgmt:xorData` line.
/// XOR is its own inverse — same call works for both encrypt and decrypt.
pub fn unwrap_in_place(packet: &mut [u8], xor_data: [u8; 8], offset: usize) {
    if offset >= packet.len() {
        return;
    }
    for (i, byte) in packet[offset..].iter_mut().enumerate() {
        *byte ^= xor_data[i & 7];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_is_its_own_inverse() {
        let key = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let original: Vec<u8> = (0..50).collect();
        let mut buf = original.clone();
        unwrap_in_place(&mut buf, key, 12);
        unwrap_in_place(&mut buf, key, 12);
        assert_eq!(buf, original);
    }

    #[test]
    fn xor_skips_first_12_bytes() {
        let mut buf = vec![0u8; 20];
        let key = [0xff; 8];
        unwrap_in_place(&mut buf, key, 12);
        assert_eq!(&buf[..12], &[0; 12], "RTP header bytes must be untouched");
        assert_eq!(&buf[12..], &[0xff; 8]);
    }
}
