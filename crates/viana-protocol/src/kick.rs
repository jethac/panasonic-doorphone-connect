//! VIANA "kick" XML envelope — request + notice messages exchanged on the
//! persistent WSS to `<NN>-mcn.s2.vianaaws.jp/mcn/ws/kick`.
//!
//! Native grammar recovered from `WebSocketLibXMLUtils::ToXML` /
//! `WebSocketLibSendParam::Convert` / `WebSocketLibBroadcastServerHelper::ParseResponse`.
//! The wire envelope is:
//!
//! ```xml
//! <request>                               <!-- or <notice> -->
//!   <command>kickTerminal</command>       <!-- or auth, kickServer, kick, reconnect, disconnect -->
//!   <kickId>00000000</kickId>             <!-- 8 ASCII hex digits = uint32 -->
//!   <kind>1</kind>                        <!-- enum, varies by command -->
//!   <device><id>...</id></device>         <!-- up to 4 device ids (16-byte C strings) -->
//!   <param>
//!     <key>JSON</key>
//!     <value><![CDATA[{...}]]></value>
//!   </param>
//!   <param>
//!     <key>SDP</key>
//!     <value><![CDATA[v=0...]]></value>
//!   </param>
//!   <!-- up to 10 params; JSON / BINARY / SDP / status. BINARY is base64'd. -->
//! </request>
//! ```
//!
//! Server-originated `<notice>` envelopes look the same but carry server →
//! client events (incoming-call kicks, presence updates, etc.).
//!
//! See `docs/PROTOCOL.md` for the envelope.

use std::borrow::Cow;

use quick_xml::events::{BytesCData, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;

use crate::error::{Error, Result};

/// Top-level XML root tag. Outbound messages from the bridge are always
/// `Request`; messages from the server are typically `Notice` (events) or
/// `Request` (server-initiated calls etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Root {
    Request,
    Notice,
}

impl Root {
    fn tag(self) -> &'static str {
        match self {
            Root::Request => "request",
            Root::Notice => "notice",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "request" => Some(Root::Request),
            "notice" => Some(Root::Notice),
            _ => None,
        }
    }
}

/// Kick command enum from the native string table in `libwebsocketdp.so`.
/// Numeric values are the table indices; we serialize/deserialize the string
/// forms because that's what's on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Auth,
    KickTerminal,
    KickServer,
    Kick,
    Reconnect,
    Disconnect,
    Unknown,
}

impl Command {
    fn tag(self) -> &'static str {
        match self {
            Command::Auth => "auth",
            Command::KickTerminal => "kickTerminal",
            Command::KickServer => "kickServer",
            Command::Kick => "kick",
            Command::Reconnect => "reconnect",
            Command::Disconnect => "disconnect",
            Command::Unknown => "unknown",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "auth" => Command::Auth,
            "kickTerminal" => Command::KickTerminal,
            "kickServer" => Command::KickServer,
            "kick" => Command::Kick,
            "reconnect" => Command::Reconnect,
            "disconnect" => Command::Disconnect,
            _ => Command::Unknown,
        }
    }
}

/// A typed param. The native ABI defines four types; only `Json`, `Sdp`, and
/// `Status` carry text; `Binary` is auto-Base64'd by the legitimate client and
/// surfaced here as raw bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Param {
    Json(String),
    Sdp(String),
    Status(String),
    Binary(Vec<u8>),
    /// Anything we didn't recognise — kept verbatim so we can round-trip
    /// uncommon server payloads without losing them.
    Other { key: String, value: String },
}

impl Param {
    fn key(&self) -> &str {
        match self {
            Param::Json(_) => "JSON",
            Param::Sdp(_) => "SDP",
            Param::Status(_) => "status",
            Param::Binary(_) => "BINARY",
            Param::Other { key, .. } => key,
        }
    }
}

/// A fully decoded kick envelope. Outbound and inbound use the same shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KickEnvelope {
    pub root: Root,
    pub command: Command,
    /// 32-bit kick ID. Wire form is 8 ASCII hex chars.
    pub kick_id: u32,
    /// Command-specific subtype enum. `1` is the most common.
    pub kind: i32,
    /// Up to 4 device id strings (16-char C strings on the native side).
    pub devices: Vec<String>,
    /// Up to 10 typed params.
    pub params: Vec<Param>,
}

impl KickEnvelope {
    /// Convenience: extract the first JSON param as a string slice.
    pub fn json(&self) -> Option<&str> {
        self.params.iter().find_map(|p| match p {
            Param::Json(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Convenience: extract the first SDP param as a string slice.
    pub fn sdp(&self) -> Option<&str> {
        self.params.iter().find_map(|p| match p {
            Param::Sdp(s) => Some(s.as_str()),
            _ => None,
        })
    }
}

/// Serialize a kick envelope to the wire XML format. CDATA is used for value
/// fields, matching the legitimate client.
pub fn to_xml(env: &KickEnvelope) -> Result<String> {
    let mut writer = Writer::new(Vec::new());
    let root = env.root.tag();
    writer
        .write_event(Event::Start(BytesStart::new(root)))
        .map_err(xml_err)?;

    write_simple(&mut writer, "command", env.command.tag())?;
    // Server-side regex requires uppercase hex (`^[0-9A-F]*$`); lowercase
    // gives resultCode=102 and an immediate disconnect.
    write_simple(&mut writer, "kickId", &format!("{:08X}", env.kick_id))?;
    write_simple(&mut writer, "kind", &env.kind.to_string())?;

    for dev in &env.devices {
        writer
            .write_event(Event::Start(BytesStart::new("device")))
            .map_err(xml_err)?;
        write_simple(&mut writer, "id", dev)?;
        writer
            .write_event(Event::End(BytesEnd::new("device")))
            .map_err(xml_err)?;
    }

    for p in &env.params {
        writer
            .write_event(Event::Start(BytesStart::new("param")))
            .map_err(xml_err)?;
        write_simple(&mut writer, "key", p.key())?;
        let value: Cow<'_, str> = match p {
            Param::Json(s) | Param::Sdp(s) | Param::Status(s) => Cow::Borrowed(s.as_str()),
            Param::Binary(b) => Cow::Owned(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b,
            )),
            Param::Other { value, .. } => Cow::Borrowed(value.as_str()),
        };
        writer
            .write_event(Event::Start(BytesStart::new("value")))
            .map_err(xml_err)?;
        writer
            .write_event(Event::CData(BytesCData::new(value.as_ref())))
            .map_err(xml_err)?;
        writer
            .write_event(Event::End(BytesEnd::new("value")))
            .map_err(xml_err)?;
        writer
            .write_event(Event::End(BytesEnd::new("param")))
            .map_err(xml_err)?;
    }

    writer
        .write_event(Event::End(BytesEnd::new(root)))
        .map_err(xml_err)?;

    let bytes = writer.into_inner();
    String::from_utf8(bytes).map_err(|e| Error::BadResponse(format!("kick xml utf-8: {e}")))
}

fn write_simple(writer: &mut Writer<Vec<u8>>, tag: &str, text: &str) -> Result<()> {
    writer
        .write_event(Event::Start(BytesStart::new(tag)))
        .map_err(xml_err)?;
    writer
        .write_event(Event::Text(BytesText::new(text)))
        .map_err(xml_err)?;
    writer
        .write_event(Event::End(BytesEnd::new(tag)))
        .map_err(xml_err)?;
    Ok(())
}

fn xml_err(e: quick_xml::Error) -> Error {
    Error::BadResponse(format!("kick xml: {e}"))
}

/// Parse a kick envelope from XML. Tolerant of unknown elements — they're
/// preserved as `Param::Other` if they appear inside `<param>`, otherwise
/// silently skipped.
pub fn from_xml(input: &str) -> Result<KickEnvelope> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(true);

    let mut root: Option<Root> = None;
    let mut command: Option<Command> = None;
    let mut kick_id: u32 = 0;
    let mut kind: i32 = 0;
    let mut devices: Vec<String> = Vec::new();
    let mut params: Vec<Param> = Vec::new();

    let mut path: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    // Per-param scratch state. A `<param>` block can contain `<key>` and
    // `<value>` in either order.
    let mut cur_key: Option<String> = None;
    let mut cur_value: Option<String> = None;

    fn flush_text(target: &mut Option<String>, t: Cow<'_, str>) {
        // Append in case the value spans multiple text/CDATA events.
        match target {
            Some(s) => s.push_str(&t),
            None => *target = Some(t.into_owned()),
        }
    }

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if path.is_empty() {
                    root = Root::parse(&name);
                    if root.is_none() {
                        return Err(Error::BadResponse(format!("unknown root tag: {name}")));
                    }
                }
                if name == "param" {
                    cur_key = None;
                    cur_value = None;
                }
                path.push(name);
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                path.pop();
                if name == "param" {
                    let key = cur_key.take().unwrap_or_default();
                    let val = cur_value.take().unwrap_or_default();
                    params.push(match key.as_str() {
                        "JSON" => Param::Json(val),
                        "SDP" => Param::Sdp(val),
                        "status" => Param::Status(val),
                        "BINARY" => {
                            let bytes = base64::Engine::decode(
                                &base64::engine::general_purpose::STANDARD,
                                val.as_bytes(),
                            )
                            .map_err(|e| Error::BadResponse(format!("kick BINARY base64: {e}")))?;
                            Param::Binary(bytes)
                        }
                        _ => Param::Other { key, value: val },
                    });
                }
            }
            Ok(Event::Text(t)) => {
                let text = t
                    .unescape()
                    .map_err(|e| Error::BadResponse(format!("kick xml unescape: {e}")))?;
                let segs: Vec<&str> = path.iter().map(String::as_str).collect();
                match segs.as_slice() {
                    [_root, "command"] => command = Some(Command::parse(&text)),
                    [_root, "kickId"] => {
                        kick_id = u32::from_str_radix(&text, 16).map_err(|e| {
                            Error::BadResponse(format!("kickId parse: {e}"))
                        })?;
                    }
                    [_root, "kind"] => {
                        kind = text
                            .parse()
                            .map_err(|e| Error::BadResponse(format!("kind parse: {e}")))?;
                    }
                    [_root, "device", "id"] => devices.push(text.into_owned()),
                    [_root, "param", "key"] => flush_text(&mut cur_key, text),
                    [_root, "param", "value"] => flush_text(&mut cur_value, text),
                    _ => {}
                }
            }
            Ok(Event::CData(c)) => {
                let text = String::from_utf8_lossy(&c);
                let segs: Vec<&str> = path.iter().map(String::as_str).collect();
                if let [_root, "param", "value"] = segs.as_slice() {
                    flush_text(&mut cur_value, text);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(Error::BadResponse(format!("kick xml: {e}"))),
        }
        buf.clear();
    }

    Ok(KickEnvelope {
        root: root.ok_or_else(|| Error::BadResponse("missing root tag".into()))?,
        command: command.unwrap_or(Command::Unknown),
        kick_id,
        kind,
        devices,
        params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_kick_terminal_request() {
        let env = KickEnvelope {
            root: Root::Request,
            command: Command::KickTerminal,
            kick_id: 0x1234ABCD,
            kind: 1,
            devices: vec!["doorphone-target".into()],
            params: vec![
                Param::Json(r#"{"request":"connect","seqNo":284}"#.into()),
                Param::Sdp("v=0\r\no=mobile 0 0 IN IP4 192.0.2.10\r\n".into()),
            ],
        };
        let xml = to_xml(&env).expect("serialize");
        assert!(xml.contains("<command>kickTerminal</command>"));
        // kickId MUST be uppercase hex — VIANA enforces a `^[0-9A-F]*$` regex
        // and disconnects on lowercase input.
        assert!(xml.contains("<kickId>1234ABCD</kickId>"));
        assert!(xml.contains("<kind>1</kind>"));
        assert!(xml.contains("<![CDATA[{"));
        let parsed = from_xml(&xml).expect("parse");
        assert_eq!(parsed, env);
    }

    /// Authentication notice the Broadcast server sends on success.
    #[test]
    fn parses_live_auth_notice() {
        let xml = "<notice><command>auth</command><resultCode>000</resultCode><message>機器認証成功。</message></notice>";
        let env = from_xml(xml).expect("parse");
        assert_eq!(env.root, Root::Notice);
        assert_eq!(env.command, Command::Auth);
        // resultCode + message are unknown sub-elements of <notice>; they're
        // not <param>s so the parser silently skips them. That's fine — the
        // bridge keys off command + kind.
    }

    #[test]
    fn parses_envelope_with_binary_param() {
        let xml = "<request><command>kick</command><kickId>00000001</kickId><kind>0</kind><param><key>BINARY</key><value><![CDATA[SGVsbG8=]]></value></param></request>";
        let env = from_xml(xml).expect("parse");
        assert_eq!(env.params.len(), 1);
        match &env.params[0] {
            Param::Binary(bytes) => assert_eq!(bytes, b"Hello"),
            other => panic!("expected Binary, got {:?}", other),
        }
    }

    #[test]
    fn parses_unknown_root_as_error() {
        let xml = "<garbage><command>auth</command></garbage>";
        assert!(matches!(from_xml(xml), Err(crate::Error::BadResponse(_))));
    }

    #[test]
    fn preserves_unknown_param_types_via_other() {
        let xml = "<request><command>auth</command><kickId>00000000</kickId><kind>0</kind><param><key>FUTURE</key><value><![CDATA[abc]]></value></param></request>";
        let env = from_xml(xml).expect("parse");
        assert_eq!(env.params.len(), 1);
        match &env.params[0] {
            Param::Other { key, value } => {
                assert_eq!(key, "FUTURE");
                assert_eq!(value, "abc");
            }
            other => panic!("expected Other, got {:?}", other),
        }
    }
}
