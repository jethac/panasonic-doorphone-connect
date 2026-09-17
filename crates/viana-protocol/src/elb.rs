//! VIANA ELB bootstrap (`mcn.s2.vianaaws.jp/mcn/api/getUrl`).
//!
//! Once we have a `signatureDeviceId` (from `kiki.dat` decryption — see
//! [`crate::identity`]), we POST to the ELB to obtain our partition's
//! per-account WSS URL. That URL is our persistent kick channel for the
//! life of the bridge process.
//!
//! Server cert is signed by Panasonic's private "Appliance Secure Certificate
//! Authority" CA (rodata in the legitimate app's `files/249d350c.0`); public
//! CA chains do NOT verify it. The caller passes in a [`reqwest::Client`]
//! that has been pre-configured with the right root store. See
//! `crates/viana-ha/src/main.rs` for an example.
//!
//! Request shape (verified against live capture 2026-05-08):
//!     POST https://mcn.s2.vianaaws.jp/mcn/api/getUrl
//!     Authorization: Basic <signatureDeviceId>
//!     Content-Type: text/xml
//!     User-Agent: <empty — POCO HTTPSClientSession default; reqwest's auto-UA also works>
//!     Body: `<request>\r\n</request>\r\n` (23 bytes, fixed)
//!
//! Response shape:
//!     HTTP/1.1 200 OK
//!     <response>
//!       <url>wss://NN-mcn.s2.vianaaws.jp:443/mcn/ws/kick</url>
//!       <irca><host>...</host><port>...</port></irca>
//!       <options><unlock>true</unlock></options>
//!     </response>

use quick_xml::events::Event;
use quick_xml::reader::Reader;
use reqwest::Client;

use crate::error::{Error, Result};

/// VIANA ELB endpoint. TLS, Panasonic-private CA chain.
pub const ELB_URL: &str = "https://mcn.s2.vianaaws.jp/mcn/api/getUrl";

/// Fixed XML request body emitted by the legitimate app's POCO client. Exactly
/// 23 bytes including the trailing `\r\n`. Verified pre-TLS via Frida hook of
/// `Poco::Net::HTTPRequest::write` on 2026-05-08.
pub const REQUEST_BODY: &str = "<request>\r\n</request>\r\n";

/// Parsed `getUrl` response. Field semantics from observation:
/// - `kick_url`: where to open the persistent WSS for kick events.
/// - `irca_host` / `irca_port`: STUN/relay hint for direct P2P media (currently unused
///   by us — bridge sources media LAN-direct from the base, not via relay).
/// - `unlock_supported`: server flag indicating whether the client may invoke
///   the door-unlock command via `kickTerminal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElbResponse {
    pub kick_url: String,
    pub irca_host: Option<String>,
    pub irca_port: Option<u16>,
    pub unlock_supported: bool,
}

/// Hit the ELB once and parse the response.
///
/// `client` must be configured to verify the Panasonic CA (see crate docs);
/// `signature_device_id` is the printable Base64 string produced by
/// [`crate::identity::decode_kiki`] / [`crate::identity::from_wire_form`].
pub async fn get_url(client: &Client, signature_device_id: &str) -> Result<ElbResponse> {
    let resp = client
        .post(ELB_URL)
        .header("Authorization", format!("Basic {signature_device_id}"))
        .header("Content-Type", "text/xml")
        .body(REQUEST_BODY)
        .send()
        .await?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        return Err(Error::ServerError {
            status: status.as_u16(),
            body,
        });
    }

    parse_response(&body)
}

/// Decompose the XML response. Lenient: any unknown sub-elements are skipped.
fn parse_response(body: &str) -> Result<ElbResponse> {
    let mut reader = Reader::from_str(body);
    reader.config_mut().trim_text(true);

    let mut kick_url: Option<String> = None;
    let mut irca_host: Option<String> = None;
    let mut irca_port: Option<u16> = None;
    let mut unlock_supported = false;

    let mut path: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                path.push(name);
            }
            Ok(Event::End(_)) => {
                path.pop();
            }
            Ok(Event::Text(t)) => {
                let text = t
                    .unescape()
                    .map_err(|e| Error::BadResponse(format!("xml unescape: {e}")))?
                    .into_owned();
                match path.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
                    ["response", "url"] => kick_url = Some(text),
                    ["response", "irca", "host"] => irca_host = Some(text),
                    ["response", "irca", "port"] => {
                        irca_port = text.parse().ok();
                    }
                    ["response", "options", "unlock"] => {
                        unlock_supported = matches!(text.as_str(), "true" | "1" | "yes");
                    }
                    _ => {}
                }
            }
            Ok(Event::CData(c)) => {
                let text = String::from_utf8_lossy(&c).into_owned();
                if let ["response", "url"] = path.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
                    kick_url = Some(text);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(Error::BadResponse(format!("xml parse: {e}"))),
        }
        buf.clear();
    }

    let kick_url = kick_url
        .ok_or_else(|| Error::BadResponse("missing <url> in getUrl response".into()))?;

    if !kick_url.starts_with("wss://") {
        return Err(Error::BadResponse(format!(
            "kick url is not wss://: {kick_url}"
        )));
    }

    Ok(ElbResponse {
        kick_url,
        irca_host,
        irca_port,
        unlock_supported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured live response from 2026-05-08 fresh-launch tcpdump. The kick
    /// URL partition (`12-mcn`) is per-account stable; the irca hint changes
    /// per region (this one is `ap-northeast-1`).
    const FIXTURE_RESPONSE: &str = "<response><url>wss://12-mcn.s2.vianaaws.jp:443/mcn/ws/kick</url><irca><host>52.68.48.129</host><port>30100</port></irca><options><unlock>true</unlock></options></response>";

    #[test]
    fn parses_captured_response() {
        let r = parse_response(FIXTURE_RESPONSE).expect("parse");
        assert_eq!(r.kick_url, "wss://12-mcn.s2.vianaaws.jp:443/mcn/ws/kick");
        assert_eq!(r.irca_host.as_deref(), Some("52.68.48.129"));
        assert_eq!(r.irca_port, Some(30100));
        assert!(r.unlock_supported);
    }

    #[test]
    fn rejects_non_wss_url() {
        let body = "<response><url>http://something/</url></response>";
        assert!(matches!(
            parse_response(body),
            Err(crate::Error::BadResponse(_))
        ));
    }

    #[test]
    fn rejects_missing_url() {
        let body = "<response><irca><host>x</host></irca></response>";
        assert!(matches!(
            parse_response(body),
            Err(crate::Error::BadResponse(_))
        ));
    }

    #[test]
    fn parses_response_with_unknown_extra_elements() {
        // Server may grow the response; tolerate unknown tags.
        let body = "<response><url>wss://12-mcn.s2.vianaaws.jp:443/mcn/ws/kick</url><newField>x</newField><options><unlock>true</unlock></options></response>";
        let r = parse_response(body).expect("parse");
        assert_eq!(r.kick_url, "wss://12-mcn.s2.vianaaws.jp:443/mcn/ws/kick");
        assert!(r.unlock_supported);
    }

    #[test]
    fn unlock_flag_recognises_alternate_truthy_values() {
        for v in ["true", "1", "yes"] {
            let body = format!(
                "<response><url>wss://x/</url><options><unlock>{v}</unlock></options></response>"
            );
            assert!(parse_response(&body).expect("parse").unlock_supported, "unlock={v}");
        }
        for v in ["false", "0", "no", ""] {
            let body = format!(
                "<response><url>wss://x/</url><options><unlock>{v}</unlock></options></response>"
            );
            assert!(!parse_response(&body).expect("parse").unlock_supported, "unlock={v}");
        }
    }
}
