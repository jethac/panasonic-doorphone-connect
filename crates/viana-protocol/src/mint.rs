//! VIANA identity-mint request derivation, mirroring `tools/empirical_mint_test.py`.
//!
//! Builds the three deterministic HTTP headers (`User-agent`, `X-DAC`, `X-PW`)
//! that the doorphoneconnect app's `P2PAPL_GetKikiId` sends to receive a fresh
//! `kiki.dat` body and `dispID` from `dipapp.bb-cygnus.jp`.
//!
//! Pure derivation; no I/O. The HTTP/TLS transport is wired in by the caller.

use aes::Aes256;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use cbc::Encryptor;
use cipher::{BlockEncryptMut, KeyIvInit, block_padding::NoPadding};
use reqwest::Client;
use sha1::{Digest, Sha1};

use crate::error::{Error, Result};

/// VIANA mint endpoint. TLS, public CA chain (no private cert needed).
pub const MINT_URL: &str = "https://dipapp.bb-cygnus.jp/servlet/getid?CMD=GETID&TYPE=RESET";

/// Product class, hardcoded across all installs of doorphoneconnect v6.7.
pub const PRODUCT_TYPE: &str = "INTERCOM16";

/// 32-character counting-digits prefix, hardcoded.
pub const PW_PREFIX: &str = "01234567890123456789012345678901";

/// Hardcoded ecosystem secret in `libp2papl_api.so` rodata. Mixed into the
/// SHA-1 that produces the `PW` tail. Load-bearing — if Panasonic ever
/// rotates this string, all clients (legitimate and ours) break simultaneously.
pub const COMMON_KEY: &str = "7BZBIxiL9IRE5bOAUCoTaJ9a0F7b";

/// Default `unique_id`: Android's privacy-MAC fallback `02:00:00:00:00:00`
/// formatted as `%020d`. Identical across all Android v6.7 installs; the
/// server doesn't dedupe on it.
pub const DEFAULT_UNIQUE_ID: &str = "00000002199023255552";

type Aes256CbcEnc = Encryptor<Aes256>;

/// Three deterministic header values for the mint request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintRequest {
    /// `X-DAC` header.
    pub dac: String,
    /// `User-agent` header.
    pub user_agent: String,
    /// `X-PW` header.
    pub pw: String,
}

/// Build the mint request from a 20-digit decimal `unique_id`. Use
/// [`DEFAULT_UNIQUE_ID`] for compatibility with the legitimate Android client.
pub fn build_mint_request(unique_id: &str) -> MintRequest {
    let dac = format!("{unique_id}{PRODUCT_TYPE}");
    let pw = derive_pw(&dac);
    let user_agent = derive_user_agent();
    MintRequest { dac, user_agent, pw }
}

/// `PW = prefix || hex(SHA1(prefix || DAC || COMMON_KEY))`.
fn derive_pw(dac: &str) -> String {
    let mut h = Sha1::new();
    h.update(PW_PREFIX.as_bytes());
    h.update(dac.as_bytes());
    h.update(COMMON_KEY.as_bytes());
    let digest = h.finalize();
    format!("{PW_PREFIX}{}", hex::encode(digest))
}

/// `userAgent = base64(AES-256-CBC(KIKI_AES_KEY, KIKI_AES_IV).encrypt(b"INTERCOM16" zero-padded to 16)[..10])`.
///
/// Same key + IV the kiki-decrypt uses.
fn derive_user_agent() -> String {
    let mut buf = [0u8; 16];
    let bytes = PRODUCT_TYPE.as_bytes();
    buf[..bytes.len()].copy_from_slice(bytes);
    // remaining 6 bytes already zero — matches the C zero-fill behaviour

    let ct = Aes256CbcEnc::new(&crate::identity::KIKI_AES_KEY.into(), &crate::identity::KIKI_AES_IV.into())
        .encrypt_padded_mut::<NoPadding>(&mut buf, 16)
        .expect("16-byte aligned input never fails NoPadding");
    B64.encode(&ct[..10])
}

/// Result of a successful mint round-trip.
#[derive(Clone, Debug)]
pub struct MintResponse {
    /// Printable Base64 wire form of the new `kiki.dat` content. Pass this
    /// directly to [`crate::identity::from_wire_form`] to derive
    /// `signatureDeviceId`. Save it as `kiki.dat` after one bitwise-NOT pass
    /// if you want byte-for-byte parity with the legitimate Android client's
    /// on-disk format.
    pub kiki_wire_bytes: Vec<u8>,
    /// New 16-digit decimal `viana_id` allocated by the server (a.k.a. `dispID`).
    pub disp_id: String,
}

/// Send the mint request to `dipapp.bb-cygnus.jp` and parse the response.
///
/// Public CA chain — the default reqwest TLS verifier (`webpki-roots` via
/// rustls) accepts the server's cert without any pinning configuration.
///
/// On the wire this is a single HTTPS GET with three custom headers
/// (`User-agent`, `X-DAC`, `X-PW`) and a comma-separated body in the response.
/// See `docs/PROTOCOL.md`.
pub async fn send_request(client: &Client, req: &MintRequest) -> Result<MintResponse> {
    let resp = client
        .get(MINT_URL)
        .header("User-agent", &req.user_agent)
        .header("X-DAC", &req.dac)
        .header("X-PW", &req.pw)
        .send()
        .await?;

    let status = resp.status();
    let body = resp.bytes().await?;

    if !status.is_success() {
        return Err(Error::ServerError {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }

    parse_response(&body)
}

/// Split the comma-separated mint response into its kiki body + dispID parts.
fn parse_response(body: &[u8]) -> Result<MintResponse> {
    let last_comma = body
        .iter()
        .rposition(|&b| b == b',')
        .ok_or_else(|| Error::BadResponse("missing comma separator".into()))?;

    let kiki_wire_bytes = body[..last_comma].to_vec();
    let disp_id = String::from_utf8(body[last_comma + 1..].to_vec())
        .map_err(|_| Error::BadResponse("dispID was not valid UTF-8".into()))?
        .trim()
        .to_string();

    if kiki_wire_bytes.is_empty() {
        return Err(Error::BadResponse("empty kiki body".into()));
    }
    if disp_id.is_empty() {
        return Err(Error::BadResponse("empty dispID".into()));
    }

    Ok(MintResponse {
        kiki_wire_bytes,
        disp_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fingerprints of the mint headers the official v6.7 app sends.
    /// `DEFAULT_UNIQUE_ID` is Android's privacy-MAC fallback, identical
    /// across installs.
    const CAPTURED_DAC: &str = "00000002199023255552INTERCOM16";
    const CAPTURED_PW: &str =
        "0123456789012345678901234567890145ae58b99a0fe056cf0d775868d1bd852510d056";
    const CAPTURED_USER_AGENT: &str = "eEZlDBXhMVTcQA==";

    #[test]
    fn build_mint_request_matches_captured_galaxy() {
        let req = build_mint_request(DEFAULT_UNIQUE_ID);
        assert_eq!(req.dac, CAPTURED_DAC);
        assert_eq!(req.pw, CAPTURED_PW);
        assert_eq!(req.user_agent, CAPTURED_USER_AGENT);
    }

    #[test]
    fn user_agent_is_a_universal_constant_for_v67() {
        // Two calls return identical bytes — the userAgent carries no
        // per-install identity, despite the field name.
        assert_eq!(derive_user_agent(), derive_user_agent());
    }

    #[test]
    fn parse_response_splits_on_last_comma_only() {
        let body = b"AAAA,BBBB,1234567890123456";
        let parsed = super::parse_response(body).expect("parse");
        assert_eq!(parsed.kiki_wire_bytes, b"AAAA,BBBB");
        assert_eq!(parsed.disp_id, "1234567890123456");
    }

    #[test]
    fn parse_response_trims_dispid_whitespace() {
        let body = b"kiki,1234567890123456\n";
        let parsed = super::parse_response(body).expect("parse");
        assert_eq!(parsed.disp_id, "1234567890123456");
    }

    #[test]
    fn parse_response_rejects_missing_comma() {
        let body = b"kiki body without disp id";
        assert!(matches!(
            super::parse_response(body),
            Err(crate::Error::BadResponse(_))
        ));
    }
}
