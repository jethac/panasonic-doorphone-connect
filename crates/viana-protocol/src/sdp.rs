//! Minimal SDP build + parse for the VIANA call-setup flow.
//!
//! The legitimate phone exchanges SDP-like blobs inside `kickTerminal` envelopes
//! to negotiate RTP transport for monitor / answer / outbound-call sessions.
//! These aren't RFC 4566 SDP — Panasonic added a custom `a=key-mgmt:` namespace
//! that carries the per-call XOR key material (`pairingId`, `xorData`,
//! `xorAuthA`, `xorAuthB`).
//!
//! We only need a tiny subset of SDP: the `c=` connection address, the
//! `m=` media descriptions (port + payload type), and the `a=key-mgmt:` lines.
//! Everything else is round-tripped or generated from a fixed template.

use base64::{Engine, engine::general_purpose::STANDARD as B64};

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaKind {
    Audio,
    Video,
}

/// One `m=` media block plus its `a=key-mgmt:` lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaSection {
    pub kind: MediaKind,
    /// Source port of the RTP stream (the side that owns this `m=` block).
    pub port: u16,
    /// Payload type from the `m=` line (8 = PCMA, 97 = H.264 in this app).
    pub payload_type: u8,
    /// `a=key-mgmt:pairingId XXXX` — 32-bit hex, only present in base→phone SDPs.
    pub pairing_id: Option<u32>,
    /// 8-byte `xorData` decoded from Base64. Used for the per-packet XOR.
    pub xor_data: Option<[u8; 8]>,
    /// 8-byte `xorAuthA` decoded from Base64. Used in challenge response.
    pub xor_auth_a: Option<[u8; 8]>,
    /// 8-byte `xorAuthB` decoded from Base64. Used in challenge response.
    pub xor_auth_b: Option<[u8; 8]>,
}

/// Parsed SDP — connection IP + the media blocks we care about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sdp {
    /// `c=IN IP4 <addr>` — the IP the other end will source RTP from
    /// (or expects us to source RTP from).
    pub connection_ip: Option<String>,
    pub media: Vec<MediaSection>,
}

impl Sdp {
    pub fn audio(&self) -> Option<&MediaSection> {
        self.media.iter().find(|m| m.kind == MediaKind::Audio)
    }
    pub fn video(&self) -> Option<&MediaSection> {
        self.media.iter().find(|m| m.kind == MediaKind::Video)
    }
}

/// Parse an SDP blob into the subset of fields we care about. Tolerates the
/// `\r\n` and bare-`\n` line terminators we've seen in real captures, and
/// silently skips lines we don't recognise.
pub fn parse(text: &str) -> Result<Sdp> {
    let mut connection_ip: Option<String> = None;
    let mut media: Vec<MediaSection> = Vec::new();
    let mut cur: Option<MediaSection> = None;

    for raw_line in text.split(|c| c == '\n' || c == '\r') {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        match &line[..line.len().min(2)] {
            "c=" => {
                // c=IN IP4 <addr>
                let rest = &line[2..];
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 3 {
                    connection_ip = Some(parts[2].to_string());
                }
            }
            "m=" => {
                // Push any pending section, start a fresh one.
                if let Some(s) = cur.take() {
                    media.push(s);
                }
                let rest = &line[2..];
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                let kind = match parts[0] {
                    "audio" => MediaKind::Audio,
                    "video" => MediaKind::Video,
                    _ => continue, // ignore unknown media types
                };
                let port: u16 = parts[1]
                    .parse()
                    .map_err(|e| Error::BadResponse(format!("bad m= port: {e}")))?;
                // parts[2] = "RTP/AVP"; parts[3..] = payload type list
                let payload_type: u8 = parts
                    .get(3)
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(0);
                cur = Some(MediaSection {
                    kind,
                    port,
                    payload_type,
                    pairing_id: None,
                    xor_data: None,
                    xor_auth_a: None,
                    xor_auth_b: None,
                });
            }
            "a=" => {
                let Some(section) = cur.as_mut() else { continue };
                let rest = &line[2..];
                let Some(stripped) = rest.strip_prefix("key-mgmt:") else { continue };
                let parts: Vec<&str> = stripped.splitn(2, char::is_whitespace).collect();
                if parts.len() < 2 {
                    continue;
                }
                let key = parts[0];
                let val = parts[1].trim();
                match key {
                    "pairingId" => {
                        section.pairing_id = u32::from_str_radix(val, 16).ok();
                    }
                    "xorData" => section.xor_data = decode_8byte_b64(val),
                    "xorAuthA" => section.xor_auth_a = decode_8byte_b64(val),
                    "xorAuthB" => section.xor_auth_b = decode_8byte_b64(val),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    if let Some(s) = cur.take() {
        media.push(s);
    }

    Ok(Sdp {
        connection_ip,
        media,
    })
}

fn decode_8byte_b64(s: &str) -> Option<[u8; 8]> {
    let bytes = B64.decode(s).ok()?;
    let mut out = [0u8; 8];
    if bytes.len() < 8 {
        return None;
    }
    out.copy_from_slice(&bytes[..8]);
    Some(out)
}

/// Build the phone-side SDP we send to the base in monitor / answer requests.
/// Mirrors the official app's offer.
pub fn build_phone_offer(local_ip: &str, audio_port: u16, video_port: u16) -> String {
    // The app uses LF-only line endings inside CDATA. Real captures show this.
    format!(
        "v=0\r\n\
         o=mobile 0 0 IN IP4 {ip}\r\n\
         s=\r\n\
         c=IN IP4 {ip}\r\n\
         t=0 0\r\n\
         m=video {vport} RTP/AVP 97\r\n\
         a=rtpmap:97 H264/90000\r\n\
         a=imageattr:97 recv [x=800,y=480,fps=150],[x=640,y=480,fps=60],[x=640,y=360,fps=150],[x=320,y=240,fps=100],[x=320,y=184,fps=150]\r\n\
         a=recvonly\r\n\
         m=audio {aport} RTP/AVP 8\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=ptime:20\r\n\
         a=sendrecv\r\n",
        ip = local_ip,
        vport = video_port,
        aport = audio_port,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Example base SDP from a monitor connect (IPs replaced with TEST-NET).
    const BASE_SDP_FIXTURE: &str = "v=0\r\n\
        o=baseset 0 0 IN IP4 192.0.2.1\r\n\
        c=IN IP4 192.0.2.1\r\n\
        t=0 0\r\n\
        m=video 33217 RTP/AVP 97\r\n\
        a=key-mgmt:pairingId aa96f943\r\n\
        a=key-mgmt:xorData p5KM2WrWCP8=\r\n\
        a=key-mgmt:xorAuthA 2coyeqPOSJA=\r\n\
        a=key-mgmt:xorAuthB PxULHmY023M=\r\n\
        a=rtpmap:97 H264/90000\r\n\
        a=imageattr:97 send [x=640,y=480,Gfps=150,Lfps=150]\r\n\
        a=sendonly\r\n\
        m=audio 38878 RTP/AVP 8\r\n\
        a=key-mgmt:pairingId 997e9e56\r\n\
        a=key-mgmt:xorData mD/SXjehd38=\r\n\
        a=key-mgmt:xorAuthA FO236WMH1R0=\r\n\
        a=key-mgmt:xorAuthB Q4OYo8EoXDc=\r\n\
        a=rtpmap:8 PCMA/8000\r\n\
        a=ptime:20\r\n\
        a=sendonly\r\n";

    #[test]
    fn parses_base_response_sdp() {
        let sdp = parse(BASE_SDP_FIXTURE).expect("parse");
        assert_eq!(sdp.connection_ip.as_deref(), Some("192.0.2.1"));

        let video = sdp.video().expect("video");
        assert_eq!(video.port, 33217);
        assert_eq!(video.payload_type, 97);
        assert_eq!(video.pairing_id, Some(0xaa96f943));
        assert!(video.xor_data.is_some(), "video xorData should parse");

        let audio = sdp.audio().expect("audio");
        assert_eq!(audio.port, 38878);
        assert_eq!(audio.payload_type, 8);
        assert_eq!(audio.pairing_id, Some(0x997e9e56));
        assert!(audio.xor_data.is_some(), "audio xorData should parse");
        assert!(audio.xor_auth_a.is_some());
        assert!(audio.xor_auth_b.is_some());
    }

    #[test]
    fn build_phone_offer_includes_local_ip_and_ports() {
        let s = build_phone_offer("192.168.1.50", 55492, 56046);
        assert!(s.contains("c=IN IP4 192.168.1.50"));
        assert!(s.contains("m=video 56046 RTP/AVP 97"));
        assert!(s.contains("m=audio 55492 RTP/AVP 8"));
        assert!(s.contains("a=rtpmap:97 H264/90000"));
        assert!(s.contains("a=rtpmap:8 PCMA/8000"));
    }

    #[test]
    fn parse_round_trips_through_build() {
        let s = build_phone_offer("10.0.0.5", 5000, 5002);
        let sdp = parse(&s).expect("parse own offer");
        assert_eq!(sdp.connection_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(sdp.audio().unwrap().port, 5000);
        assert_eq!(sdp.video().unwrap().port, 5002);
    }
}
