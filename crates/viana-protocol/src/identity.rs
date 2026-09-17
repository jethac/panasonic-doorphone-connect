//! VIANA self-ID derivation, mirroring `tools/decode_kiki_dat.py`.
//!
//! On-disk `kiki.dat` is the bytewise-NOT of the printable Base64 wire form
//! of an AES-256-CBC ciphertext. The first 0x119 (281) bytes of plaintext are
//! the printable ASCII string `<USER_HEX>:<PW_HEX>` (24 + 1 + 256 chars), and
//! Base64-encoding that string produces the `signatureDeviceId` that the ELB
//! and Broadcast auth handshakes use verbatim as the HTTP Basic-Auth value.
//!
//! AES key + IV: rodata at offset `0x53d5d0` of `libp2papl_api.so` is the
//! bytewise-NOT'd form of the actual key; the live VIANA_COM_DecryptMsg path
//! NOT's it back. The IV is `0x55 * 16` (a.k.a. `NOT(0xaa * 16)`). Same
//! key+IV used for the mint-side `userAgent` encrypt — see [`crate::mint`].
//!
//! Verified against the official app's `VIANA_COM_DecryptMsg` path.

use aes::Aes256;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use cbc::Decryptor;
use cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};

use crate::error::{Error, Result};

/// Bytewise-NOT'd form of the AES-256 key as it appears in
/// `libp2papl_api.so` rodata at file offset `0x53d5d0`.
pub const KIKI_AES_KEY_RODATA: [u8; 32] = [
    0x7c, 0x6f, 0x4b, 0xf1, 0xf7, 0x4a, 0x10, 0x5a, 0x8d, 0xc0, 0xd6, 0xb1, 0xa2, 0x97, 0xfc,
    0xdb, 0x02, 0x72, 0xb9, 0xa7, 0xcb, 0x64, 0x8c, 0x6f, 0x1b, 0xb3, 0xa5, 0xde, 0x60, 0x58,
    0x9c, 0x37,
];

/// The actual AES-256-CBC key: bitwise-NOT of the rodata constant.
pub const KIKI_AES_KEY: [u8; 32] = {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = !KIKI_AES_KEY_RODATA[i];
        i += 1;
    }
    out
};

/// AES-256-CBC IV: sixteen bytes of `0x55` (`NOT(0xaa * 16)`).
pub const KIKI_AES_IV: [u8; 16] = [0x55; 16];

/// Number of plaintext bytes Base64-encoded into `signatureDeviceId`.
pub const SELF_ID_RECORD_LEN: usize = 0x119;

type Aes256CbcDec = Decryptor<Aes256>;

/// Result of decoding a `kiki.dat` blob.
#[derive(Clone, Debug)]
pub struct DecodedKiki {
    /// AES ciphertext (after `bitwise-NOT(raw) → Base64-decode`). Always 16-byte
    /// aligned. 288 bytes for the 389-byte on-disk format.
    pub ciphertext: Vec<u8>,
    /// AES plaintext, same length as ciphertext (no PKCS#7 padding stripped —
    /// the layout is application-defined inside the first 0x119 bytes).
    pub plaintext: Vec<u8>,
    /// `signatureDeviceId`: Base64 of `plaintext[..0x119]`. 376 chars.
    pub signature_device_id: String,
}

/// Decode an on-disk `kiki.dat` file. Accepts either the binary-NOT'd form
/// (as written by the legitimate app) or the printable Base64 wire form
/// returned by the mint endpoint — call [`from_wire_form`] for the latter to
/// avoid the extra NOT round-trip.
pub fn decode_kiki(raw: &[u8]) -> Result<DecodedKiki> {
    let inverted: Vec<u8> = raw.iter().map(|b| !b).collect();
    decode_inner(&inverted)
}

/// Decode the printable Base64 wire form returned directly by the
/// `dipapp.bb-cygnus.jp` mint endpoint. Skips the NOT pass that the legitimate
/// app applies before writing to disk.
pub fn from_wire_form(printable_base64: &[u8]) -> Result<DecodedKiki> {
    decode_inner(printable_base64)
}

fn decode_inner(b64_text: &[u8]) -> Result<DecodedKiki> {
    // The Panasonic mint endpoint returns 76-char-wrapped MIME-style Base64
    // with embedded `\n` separators. Python's stdlib `b64decode` is lenient
    // and skips them; the `base64` crate v0.22 is strict and rejects them, so
    // we strip ASCII whitespace before decoding.
    let stripped: Vec<u8> = b64_text
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let mut ciphertext = B64.decode(&stripped)?;

    if ciphertext.len() % 16 != 0 {
        return Err(Error::UnalignedCiphertext { len: ciphertext.len() });
    }

    let original_ct = ciphertext.clone();

    let plaintext_view = Aes256CbcDec::new(&KIKI_AES_KEY.into(), &KIKI_AES_IV.into())
        .decrypt_padded_mut::<NoPadding>(&mut ciphertext)
        .map_err(|e| Error::AesDecrypt(e.to_string()))?;
    let plaintext = plaintext_view.to_vec();

    if plaintext.len() < SELF_ID_RECORD_LEN {
        return Err(Error::PlaintextTooShort {
            actual: plaintext.len(),
            required: SELF_ID_RECORD_LEN,
        });
    }

    let signature_device_id = B64.encode(&plaintext[..SELF_ID_RECORD_LEN]);

    Ok(DecodedKiki {
        ciphertext: original_ct,
        plaintext,
        signature_device_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::Encryptor;
    use cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};

    type Aes256CbcEnc = Encryptor<Aes256>;

    #[test]
    fn round_trips_synthetic_kiki() {
        // 281-byte USER:PW + padding to 288 (AES block aligned). All zeros
        // except the colon — no live identity material.
        let mut plaintext = vec![0u8; 288];
        let mut auth = vec![b'0'; SELF_ID_RECORD_LEN];
        auth[24] = b':';
        plaintext[..SELF_ID_RECORD_LEN].copy_from_slice(&auth);

        let mut buf = plaintext.clone();
        let ct = Aes256CbcEnc::new(&KIKI_AES_KEY.into(), &KIKI_AES_IV.into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, 288)
            .expect("encrypt");
        let wire = B64.encode(ct);
        let on_disk: Vec<u8> = wire.bytes().map(|b| !b).collect();

        let got = decode_kiki(&on_disk).expect("decode");
        assert_eq!(got.ciphertext.len(), 288);
        assert_eq!(&got.plaintext[..SELF_ID_RECORD_LEN], auth.as_slice());
        assert_eq!(got.signature_device_id, B64.encode(&auth));
    }
}
