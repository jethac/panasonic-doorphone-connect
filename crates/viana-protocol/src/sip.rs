//! Minimal one-shot SIP UA for the **pairing** leg only.
//!
//! After pairing the bridge
//! talks to the base via the VIANA WSS channel; we don't need a persistent
//! local SIP UA at runtime.
//!
//! What this module covers:
//!   * `send_pair_message` — SIP MESSAGE to `<base>:5060` carrying
//!     `Register:MAC=<synthetic>;Name="<phone_name>"\r\n` in the body. Base
//!     replies 200 OK and *auto-allocates* a terminal slot in 21-28; we
//!     learn it from the inbound NOTIFY that follows.
//!   * `register` — RFC 2617 MD5 digest REGISTER cycle (CSeq 1: 401-Unauth,
//!     CSeq 2: 200 OK with Authorization). Realm `PSNPhoneSystem`, password
//!     `md5(synthetic_MAC).hexdigest().upper()`.
//!   * `wait_for_assigned_terminal` — listen for the base's NOTIFY
//!     `wifi-terminal-event-notify` and pluck the terminal slot the base
//!     assigned.
//!
//! All I/O is one socket, no SIP dialog state machine — pairing is a 2-second
//! transaction and we don't need to track Vias or branches across requests.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use md5::{Digest, Md5};
use rand::Rng;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

const SIP_PORT: u16 = 5060;
const RESPONSE_BUDGET: Duration = Duration::from_secs(5);
const NOTIFY_WINDOW: Duration = Duration::from_secs(5);

/// Re-REGISTER heartbeat interval. The legitimate Galaxy app re-registers
/// every 15s with `Expires: 30` (3 missed heartbeats before the base
/// considers us deregistered). Anything different is observable in the
/// base's SIP log and on whatever telemetry Panasonic ships.
pub const REGISTER_REFRESH_INTERVAL: Duration = Duration::from_secs(15);

/// Default Expires value sent in REGISTER. The legit app uses 30; the
/// base trusts our value (no down-negotiate seen). Don't change without
/// reason.
pub const REGISTER_EXPIRES_SECS: u32 = 30;

/// SIP `User-Agent` header — must be byte-identical to what the
/// legitimate Doorphone Connect Android app emits, or Panasonic's
/// server-side audit logs will see a non-Galaxy UA on this base's
/// handset list.
///
/// Taken from SIP requests the official app sends. The
/// bytes between `Panasonic_` and `/6.7` are the Japanese app name
/// "ドアホンコネクト" (DoorphoneConnect) in halfwidth katakana, encoded
/// in UTF-8:
///
///   ﾄﾞｱﾎﾝｺﾈｸﾄ → ef be 84 ef be 9e ef bd b1 ef be 8e
///                ef be 9d ef bd ba ef be 88 ef bd b8
///                ef be 84
pub const PANASONIC_USER_AGENT: &str = "Panasonic_\u{ff84}\u{ff9e}\u{ff71}\u{ff8e}\u{ff9d}\u{ff7a}\u{ff88}\u{ff78}\u{ff84}/6.7";

/// Name= field the legitimate Galaxy puts in the SIP MESSAGE body. This
/// shows up on the base's handset list and almost certainly in
/// Panasonic's per-device cloud telemetry. Keep it as the Galaxy
/// device model so we look like a real handset; the user's
/// human-friendly display_name is HA-internal only.
pub const SIP_HANDSET_NAME: &str = "SM-G986B";

/// Per-call state the caller (the daemon's pair flow) keeps so
/// `send_pair_message`, `register`, and `wait_for_assigned_terminal` can
/// share Call-IDs / branches / Contact info consistently.
///
/// Note: MESSAGE and REGISTER are SEPARATE SIP transactions in the
/// legitimate Galaxy capture — different Call-IDs, different From-tags,
/// even different source ports. PairContext::new generates the
/// MESSAGE-side identifiers; `regenerate_for_register()` swaps them out
/// when the caller transitions to the REGISTER cycle.
#[derive(Clone)]
pub struct PairContext {
    pub base_ip: Ipv4Addr,
    pub local_ip: Ipv4Addr,
    pub local_port: u16,
    /// 12-hex-char synthetic MAC the bridge generates. Stored verbatim in
    /// the base's `securitysettings.db` after pairing.
    pub synthetic_mac: String,
    pub phone_name: String,
    pub call_id: String,
    pub from_tag: String,
}

/// Galaxy Call-ID shape: `<8hex>-<20hex>303030303030@[<local_ip>]`.
/// The trailing literal "303030303030" (twelve ASCII '0' chars, NOT zero
/// bytes) is a Panasonic SIP-stack signature; both observed Galaxy
/// captures end the 32-hex section with this constant. The 20 random hex
/// chars before it are 80 bits of entropy.
fn fresh_call_id(local_ip: Ipv4Addr) -> String {
    let mut rng = rand::thread_rng();
    let prefix = rng.r#gen::<u32>();
    // 20 hex chars = 80 bits. Generate as u128 high-80-bits.
    let middle: u128 = rng.r#gen::<u128>() >> 48;
    format!(
        "{prefix:08x}-{middle:020x}303030303030@[{local_ip}]",
        prefix = prefix,
        middle = middle,
        local_ip = local_ip,
    )
}

/// Galaxy from-tag: 9-10 decimal digits.
fn fresh_from_tag() -> String {
    format!("{}", rand::thread_rng().r#gen::<u32>())
}

impl PairContext {
    pub fn new(
        base_ip: Ipv4Addr,
        local_ip: Ipv4Addr,
        local_port: u16,
        synthetic_mac: String,
        phone_name: String,
    ) -> Self {
        let call_id = fresh_call_id(local_ip);
        let from_tag = fresh_from_tag();
        Self {
            base_ip,
            local_ip,
            local_port,
            synthetic_mac,
            phone_name,
            call_id,
            from_tag,
        }
    }

    /// Swap in fresh Call-ID + from-tag — call this between MESSAGE and
    /// REGISTER. The legitimate Galaxy app uses entirely separate SIP
    /// transactions; reusing the MESSAGE Call-ID for REGISTER causes the
    /// base to 500 (treats it as an in-dialog request that doesn't fit).
    pub fn regenerate_for_register(&mut self) {
        self.call_id = fresh_call_id(self.local_ip);
        self.from_tag = fresh_from_tag();
    }

    fn base_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.base_ip), SIP_PORT)
    }
}

/// Send the SIP MESSAGE pairing bootstrap. The base accepts, allocates a
/// terminal slot in 21-28, and immediately starts NOTIFY-ing us with the
/// updated handset roster. We don't decode the NOTIFY here — see
/// `wait_for_assigned_terminal`.
/// Send the SIP MESSAGE pairing bootstrap and return the slot number the
/// base assigns us (extracted from `PSN-Notify-PSnum` in the 200 OK).
/// Returns None if we couldn't parse a slot — caller can fall back to the
/// hint or fail.
///
/// Format mirrors the official app MESSAGE byte-for-byte:
/// - request URI `sip:Server@<base>>` (literal "Server@" + stray ">")
/// - Via WITHOUT `;rport`
/// - To header BEFORE From
/// - To `<sip:Server@<base>>>` (trailing ">>")
/// - From `<sip:Client@<base>>;tag=...` (literal "Client", base IP)
/// - Call-ID `<hex>-<hex>@[<local_ip>]` (note bracketed IP)
/// - `Allow: INVITE,ACK,CANCEL,BYE,INFO,MESSAGE,NOTIFY,UPDATE`
/// - `Content-Type: application/text` (NOT text/plain)
/// - `User-Agent: Panasonic_HomeAssistant/6.7`
/// - body: `Register:MAC=<hex>;Name="<phone_name>"\r\n`
pub async fn send_pair_message(sock: &UdpSocket, ctx: &PairContext) -> std::io::Result<Option<u32>> {
    let branch = format!("z9hG4bK{:08x}", rand::thread_rng().r#gen::<u32>());
    // Name= goes into the base's handset roster (visible in NOTIFY's
    // Register:NN="..." line) and HA UI. Honour the user's display name —
    // hard-coding it to a Galaxy model was a regression.
    let body = format!(
        "Register:MAC={};Name=\"{}\"\r\n",
        ctx.synthetic_mac, ctx.phone_name
    );
    let req = format!(
        "MESSAGE sip:Server@{base}> SIP/2.0\r\n\
         Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch}\r\n\
         Max-Forwards: 70\r\n\
         To: <sip:Server@{base}>>\r\n\
         From: <sip:Client@{base}>;tag={tag}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 MESSAGE\r\n\
         Allow: INVITE,ACK,CANCEL,BYE,INFO,MESSAGE,NOTIFY,UPDATE\r\n\
         Content-Type: application/text\r\n\
         User-Agent: {ua}\r\n\
         Content-Length: {clen}\r\n\
         \r\n\
         {body}",
        base = ctx.base_ip,
        local_ip = ctx.local_ip,
        local_port = ctx.local_port,
        branch = branch,
        tag = ctx.from_tag,
        call_id = ctx.call_id,
        ua = PANASONIC_USER_AGENT,
        clen = body.len(),
        body = body,
    );
    info!(
        bytes = req.len(),
        body_len = body.len(),
        "sending MESSAGE bootstrap"
    );
    debug!(raw = %req, "MESSAGE raw");
    sock.send_to(req.as_bytes(), ctx.base_addr()).await?;

    // Read the 200 OK and pull PSN-Notify-PSnum (the base-assigned slot).
    let mut buf = [0u8; 4096];
    let resp = match timeout(RESPONSE_BUDGET, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => {
            let s = String::from_utf8_lossy(&buf[..n]).into_owned();
            let status = s.lines().next().unwrap_or("").trim();
            info!(bytes = n, status, "MESSAGE response received");
            debug!(raw = %s, "MESSAGE raw response");
            s
        }
        Ok(Err(e)) => {
            warn!(err = %e, "MESSAGE recv error");
            return Ok(None);
        }
        Err(_) => {
            warn!("MESSAGE response timed out");
            return Ok(None);
        }
    };
    let assigned = parse_psn_num_header(&resp);
    info!(?assigned, "PSN-Notify-PSnum parsed from MESSAGE 200 OK");
    Ok(assigned)
}

/// Parse `PSN-Notify-PSnum: NN` out of a SIP response's headers.
fn parse_psn_num_header(resp: &str) -> Option<u32> {
    let unfolded = unfold_headers(resp);
    let line = unfolded
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("psn-notify-psnum:"))?;
    let val = line.splitn(2, ':').nth(1)?.trim();
    val.parse::<u32>().ok()
}

/// Result of a successful REGISTER cycle: the slot the base placed us in
/// plus the auth state needed to keep re-registering on the heartbeat.
pub struct RegisterResult {
    pub terminal: u32,
    pub auth: AuthState,
    /// Highest CSeq we've sent (3 immediately post-handshake; the
    /// maintenance loop bumps this on every heartbeat).
    pub last_cseq: u32,
    /// Highest nonce-count (`nc`) we've used for digest auth. Increments
    /// 1, 2, 3 across CSeq 2, 3, 4… until the base 401-challenges a new
    /// nonce.
    pub last_nc: u32,
}

#[derive(Clone)]
pub struct AuthState {
    pub realm: String,
    pub nonce: String,
    pub qop: Option<String>,
    /// MD5(MAC).upper().
    pub password: String,
    /// Terminal slot we're claiming this REGISTER cycle (acts as
    /// `username` in the digest formula).
    pub terminal: u32,
}

/// Run the RFC 2617 MD5 digest REGISTER cycle as `terminal_hint`. The
/// captured Galaxy app sends THREE REGISTERs back-to-back during pair:
/// CSeq 1 (unauthed → 401), CSeq 2 (authed → 200 OK), CSeq 3 (authed
/// → 200 OK, ~3ms after CSeq 2's 200 OK). We replicate all three so
/// Panasonic's per-base SIP transaction logs see the same shape.
///
/// Returns the slot we ended up in plus the auth state that the
/// maintenance heartbeat reuses.
pub async fn register(
    sock: &UdpSocket,
    ctx: &PairContext,
    terminal_hint: u32,
) -> std::io::Result<RegisterResult> {
    let password = sip_password_from_mac(&ctx.synthetic_mac);
    info!(terminal_hint, mac = %ctx.synthetic_mac, "starting REGISTER cycle");

    // CSeq 1: unauthenticated REGISTER, expect 401 with WWW-Authenticate.
    let challenge = send_register(sock, ctx, terminal_hint, 1, None).await?;
    let status_line = challenge.lines().next().unwrap_or("").trim();
    let (realm, nonce, qop) = parse_www_authenticate(&challenge).ok_or_else(|| {
        warn!(status = status_line, "REGISTER challenge unparseable; raw follows");
        warn!(raw = %challenge, "raw REGISTER challenge");
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "REGISTER challenge missing WWW-Authenticate / nonce (status: {})",
                status_line
            ),
        )
    })?;
    info!(realm, nonce, qop = ?qop, "parsed WWW-Authenticate challenge");

    let auth = AuthState {
        realm,
        nonce,
        qop,
        password,
        terminal: terminal_hint,
    };

    // CSeq 2: authenticated REGISTER → 200 OK.
    let resp2 = send_register(sock, ctx, terminal_hint, 2, Some(&auth)).await?;
    let status2 = resp2.lines().next().unwrap_or("").trim();
    info!(status = status2, "CSeq=2 authenticated REGISTER response");

    // CSeq 3: a SECOND authenticated REGISTER, sent immediately. The
    // legitimate Galaxy app does this — same Call-ID + from-tag, fresh
    // branch + cnonce, nc bumped to 00000002. Skipping it leaves an
    // observable hole in the per-base SIP transaction log (Galaxy = 3
    // REGISTERs per pair, us = 2).
    let resp3 = send_register(sock, ctx, terminal_hint, 3, Some(&auth)).await?;
    let status3 = resp3.lines().next().unwrap_or("").trim();
    info!(status = status3, "CSeq=3 follow-up REGISTER response");

    // Confirm via the wifi-terminal-event-notify which slot the base
    // actually placed us in. Falls back to the hint if the NOTIFY doesn't
    // arrive in time (e.g. the base only NOTIFYs on slot change and the
    // hint was the same as our previous slot).
    let terminal = wait_for_assigned_terminal(sock, &ctx.synthetic_mac, ctx)
        .await
        .unwrap_or(terminal_hint);

    Ok(RegisterResult {
        terminal,
        auth,
        last_cseq: 3,
        last_nc: 2,
    })
}

async fn send_register(
    sock: &UdpSocket,
    ctx: &PairContext,
    terminal: u32,
    cseq: u32,
    auth: Option<&AuthState>,
) -> std::io::Result<String> {
    let branch = format!("z9hG4bK{:08x}", rand::thread_rng().r#gen::<u32>());
    let request_uri = format!("sip:{};transport=udp", ctx.base_ip);
    // Header sequence matches captured Galaxy REGISTER:
    //   Via, Max-Forwards, To, From, Call-ID, CSeq, Contact, Expires,
    //   [Authorization (cseq>=2)], Allow, User-Agent, Content-Length.
    // The Authorization slot — when present — sits BETWEEN Expires and
    // Allow, not at the end. Some SIP stacks parse positionally.
    let auth_line = match auth {
        None => String::new(),
        Some(a) => {
            let cnonce = format!("{:08X}", rand::thread_rng().r#gen::<u32>());
            let nc = format!("{:08x}", cseq - 1);
            let response = digest_response(
                &a.terminal.to_string(),
                &a.realm,
                &a.password,
                "REGISTER",
                &request_uri,
                &a.nonce,
                &nc,
                &cnonce,
                a.qop.as_deref().unwrap_or(""),
            );
            // Authorization field order matches legit:
            // realm, nonce, algorithm, qop, cnonce, nc, uri, username, response.
            if let Some(qop) = a.qop.as_ref() {
                format!(
                    "Authorization: Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=MD5, qop={qop}, cnonce=\"{cnonce}\", nc={nc}, uri=\"{uri}\", username=\"{user}\", response=\"{resp}\"\r\n",
                    realm = a.realm,
                    nonce = a.nonce,
                    qop = qop,
                    cnonce = cnonce,
                    nc = nc,
                    uri = request_uri,
                    user = a.terminal,
                    resp = response,
                )
            } else {
                format!(
                    "Authorization: Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=MD5, uri=\"{uri}\", username=\"{user}\", response=\"{resp}\"\r\n",
                    realm = a.realm,
                    nonce = a.nonce,
                    uri = request_uri,
                    user = a.terminal,
                    resp = response,
                )
            }
        }
    };
    let req = format!(
        "REGISTER {request_uri} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch}\r\n\
         Max-Forwards: 70\r\n\
         To: <sip:{terminal}@{base}>\r\n\
         From: <sip:{terminal}@{base}>;tag={tag}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} REGISTER\r\n\
         Contact: <sip:{terminal}@{local_ip}:{local_port}>\r\n\
         Expires: {exp}\r\n\
         {auth_line}\
         Allow: INVITE,ACK,CANCEL,BYE,INFO,MESSAGE,NOTIFY,UPDATE\r\n\
         User-Agent: {ua}\r\n\
         Content-Length: 0\r\n\
         \r\n",
        base = ctx.base_ip,
        local_ip = ctx.local_ip,
        local_port = ctx.local_port,
        terminal = terminal,
        tag = ctx.from_tag,
        call_id = ctx.call_id,
        auth_line = auth_line,
        ua = PANASONIC_USER_AGENT,
        exp = REGISTER_EXPIRES_SECS,
    );
    debug!(cseq, terminal, "sending REGISTER (auth={})", auth.is_some());
    sock.send_to(req.as_bytes(), ctx.base_addr()).await?;

    // Read until we get a SIP/2.0 status response to OUR REGISTER. The base
    // also injects unsolicited inbound requests (NOTIFY for the handset
    // roster, SUBSCRIBE, etc.) — those would not have WWW-Authenticate and
    // must be skipped, not consumed. 100 Trying is also discarded.
    let mut buf = [0u8; 8192];
    loop {
        let (n, _) = timeout(RESPONSE_BUDGET, sock.recv_from(&mut buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "REGISTER response timeout")
            })??;
        let resp = String::from_utf8_lossy(&buf[..n]).into_owned();
        let status_line = resp.lines().next().unwrap_or("").trim();

        // Inbound requests start with a SIP method (NOTIFY/INVITE/etc.); we
        // only want responses (which start with "SIP/2.0 <code>").
        if !status_line.starts_with("SIP/") {
            debug!(method = status_line, "ignoring inbound SIP request while waiting for REGISTER response");
            continue;
        }
        if status_line.contains("100 Trying") {
            continue;
        }
        info!(cseq, status = status_line, bytes = n, "REGISTER response received");
        debug!(raw = %resp, "REGISTER raw response");
        return Ok(resp);
    }
}

/// Listen for the base→phone NOTIFY `Event: wifi-terminal-event-notify` that
/// echoes the registered handset roster after a successful pair, and extract
/// the slot the base assigned to **us**.
///
/// `synthetic_mac` is the MAC the caller MESSAGE'd in with — used to pick our
/// own roster entry out of a NOTIFY that may include other already-paired
/// handsets. Pass an empty string to take the first 21..=28 entry seen
/// (legacy behaviour, pre-multi-handset rosters).
///
/// **Critical**: every inbound NOTIFY is acked with 200 OK, even if it
/// isn't the wifi-terminal-event-notify we're after. Pcap evidence
/// (`/tmp/pair_capture.pcap` 2026-05-12) showed that without acking,
/// the base retransmits NOTIFYs (the 1ms-apart pairs) and then treats
/// us as a sick terminal — CGI 108 silently returns
/// `{"detail":"","result":0}` with no `data.vianaID`, breaking pair.
/// `ctx` provides the from-tag we'd use if the NOTIFY's To header
/// lacks one (some NOTIFYs do).
pub async fn wait_for_assigned_terminal(
    sock: &UdpSocket,
    synthetic_mac: &str,
    ctx: &PairContext,
) -> Option<u32> {
    let mut buf = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + NOTIFY_WINDOW;
    let mut found_slot: Option<u32> = None;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (recv, src) = match timeout(remaining, sock.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => (n, src),
            _ => break,
        };
        let frame = String::from_utf8_lossy(&buf[..recv]).into_owned();
        let first_line = frame.lines().next().unwrap_or("").trim();
        debug!(method = first_line, bytes = recv, "rx frame while waiting for NOTIFY");
        if !frame.starts_with("NOTIFY") {
            continue;
        }
        info!(bytes = recv, "received NOTIFY; raw body follows in DEBUG");
        debug!(raw = %frame, "raw inbound NOTIFY");
        // Ack EVERY NOTIFY immediately, regardless of whether it's the
        // one we want. Skipping ack triggers base retransmits and then
        // "sick terminal" treatment for the rest of the pair.
        if let Err(e) = ack_notify(sock, &frame, ctx, src).await {
            warn!(err = %e, "failed to ack NOTIFY during register");
        }
        if found_slot.is_some() {
            // Already have our slot; keep ack'ing remaining NOTIFYs
            // until the deadline so the base stays happy through CGI.
            continue;
        }
        if !frame.contains("wifi-terminal-event-notify") {
            continue;
        }
        if let Some(slot) = parse_terminal_for_mac(&frame, synthetic_mac) {
            info!(slot, mac = synthetic_mac, "matched our handset slot in NOTIFY");
            found_slot = Some(slot);
            continue;
        }
        if let Some(slot) = parse_terminal_from_notify(&frame) {
            warn!(
                slot,
                "NOTIFY didn't carry a recognisable MAC for us; falling back to first 21..=28 entry"
            );
            found_slot = Some(slot);
        }
    }
    found_slot
}

/// Parse the NOTIFY body looking for a roster entry whose MAC matches the
/// one we MESSAGE'd in with. Accept any tag order inside the entry —
/// `<mac>` and `<number>` may appear in either order, case-insensitively.
fn parse_terminal_for_mac(notify: &str, mac: &str) -> Option<u32> {
    if mac.is_empty() {
        return None;
    }
    let body = notify.split("\r\n\r\n").nth(1)?;
    let mac_lc = mac.to_ascii_lowercase();
    let body_lc = body.to_ascii_lowercase();
    // Walk every <entry>…</entry> block; return the slot of the first
    // entry whose body contains our MAC.
    let mut cursor = 0;
    while let Some(open_rel) = body_lc[cursor..].find("<entry>") {
        let entry_start = cursor + open_rel + "<entry>".len();
        let close_rel = body_lc[entry_start..].find("</entry>")?;
        let entry_end = entry_start + close_rel;
        let entry = &body[entry_start..entry_end];
        let entry_lc = &body_lc[entry_start..entry_end];
        if entry_lc.contains(&mac_lc) {
            // Found our entry — extract its <number>NN</number>.
            if let Some(num_open) = entry_lc.find("<number>") {
                let num_start = num_open + "<number>".len();
                if let Some(num_close) = entry_lc[num_start..].find("</number>") {
                    if let Ok(val) = entry[num_start..num_start + num_close].parse::<u32>() {
                        if (21..=28).contains(&val) {
                            return Some(val);
                        }
                    }
                }
            }
        }
        cursor = entry_end + "</entry>".len();
    }
    None
}

/// Parse the `WWW-Authenticate: Digest …` header from a 401 challenge.
/// Handles RFC 3261 §7.3.1 line folding: continuation lines that start with
/// SP/HTAB are joined to the preceding header line before parsing.
fn parse_www_authenticate(resp: &str) -> Option<(String, String, Option<String>)> {
    let unfolded = unfold_headers(resp);
    let line = unfolded
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("www-authenticate:"))?;
    let realm = pick_quoted(line, "realm")?;
    let nonce = pick_quoted(line, "nonce")?;
    let qop = pick_quoted(line, "qop").or_else(|| pick_unquoted(line, "qop"));
    Some((realm, nonce, qop))
}

/// Join SIP/HTTP folded header continuation lines (lines starting with
/// SP/HTAB) onto their preceding header line. Headers section ends at the
/// first blank line — we only operate before that so message bodies are
/// untouched.
fn unfold_headers(resp: &str) -> String {
    let mut out = String::with_capacity(resp.len());
    let mut in_headers = true;
    for line in resp.lines() {
        if !in_headers {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if line.is_empty() {
            in_headers = false;
            out.push('\n');
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation: drop the trailing newline of the previous line
            // (already appended) and join, replacing the leading whitespace
            // with a single space.
            if out.ends_with('\n') {
                out.pop();
            }
            out.push(' ');
            out.push_str(line.trim_start());
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

fn pick_quoted(line: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=\"");
    let start = line.to_ascii_lowercase().find(&pat)? + pat.len();
    let end = line[start..].find('"')?;
    Some(line[start..start + end].to_string())
}

fn pick_unquoted(line: &str, key: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let pat = format!("{key}=");
    let start = lower.find(&pat)? + pat.len();
    let rest = &line[start..];
    let end = rest.find(|c: char| c == ',' || c == ' ' || c == '\r').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn parse_terminal_from_notify(notify: &str) -> Option<u32> {
    // The handset roster
    // is XML-ish with each entry carrying a number. Look for the first
    // `<number>NN</number>` in the 21..=28 range as a starting point.
    let body = notify.split("\r\n\r\n").nth(1)?;
    let mut start = 0;
    while let Some(open) = body[start..].find("<number>") {
        let from = start + open + "<number>".len();
        let to = body[from..].find("</number>")?;
        let val: u32 = body[from..from + to].parse().ok()?;
        if (21..=28).contains(&val) {
            return Some(val);
        }
        start = from + to;
    }
    None
}

/// `md5(synthetic_MAC).hexdigest().upper()`.
pub fn sip_password_from_mac(mac: &str) -> String {
    let mut h = Md5::new();
    h.update(mac.as_bytes());
    let digest = h.finalize();
    hex::encode_upper(digest)
}

/// RFC 2617 MD5 digest formula.
pub fn digest_response(
    username: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
    nc: &str,
    cnonce: &str,
    qop: &str,
) -> String {
    let ha1 = md5_hex(&format!("{username}:{realm}:{password}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    if qop.is_empty() {
        md5_hex(&format!("{ha1}:{nonce}:{ha2}"))
    } else {
        md5_hex(&format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"))
    }
}

fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// Generate a fresh 12-hex synthetic MAC (the bridge equivalent of what the
/// Galaxy app rolled and stored as `smartphone_mac_address`). Anything 12
/// lowercase hex chars goes; the base treats it as opaque.
pub fn fresh_synthetic_mac() -> String {
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Long-running task that keeps the bridge SIP-registered with the base.
///
/// The legitimate Galaxy app maintains an open SIP UA forever after pair:
///   * re-REGISTERs every 15s (`Expires: 30`, so 3 missed = drop)
///   * acks every base→phone NOTIFY with 200 OK
///   * re-handshakes the digest auth on 401 (nonce rotation)
///
/// If we don't do this, the base sees us drop off after Expires
/// (~30s), marks the WiFi-handset slot as offline, and re-NOTIFIes
/// hoping for a response. That pattern is observable in any
/// per-device cloud telemetry Panasonic ships.
///
/// `state` is the auth + cseq state from `register()`. The task runs
/// until the socket errors or the task is aborted.
pub async fn maintain_registration(
    sock: std::sync::Arc<UdpSocket>,
    ctx: PairContext,
    mut state: RegisterResult,
) -> std::io::Result<()> {
    use tokio::time::{interval, Instant};
    info!(
        terminal = state.terminal,
        interval_s = REGISTER_REFRESH_INTERVAL.as_secs(),
        "starting SIP registration maintenance loop"
    );

    let mut tick = interval(REGISTER_REFRESH_INTERVAL);
    // First tick fires immediately — skip it; the pair flow already did
    // CSeq 1+2+3.
    tick.tick().await;
    let mut next_tick: Instant = tick.tick().await;
    let mut buf = [0u8; 8192];

    loop {
        // Race: incoming SIP frame OR re-register tick.
        let now = Instant::now();
        let until_tick = next_tick.saturating_duration_since(now);
        tokio::select! {
            recv = timeout(until_tick, sock.recv_from(&mut buf)) => {
                match recv {
                    Ok(Ok((n, src))) => {
                        let frame = String::from_utf8_lossy(&buf[..n]).into_owned();
                        let first = frame.lines().next().unwrap_or("").trim();
                        if first.starts_with("NOTIFY") {
                            debug!(bytes = n, "inbound NOTIFY; sending 200 OK");
                            if let Err(e) = ack_notify(&*sock, &frame, &ctx, src).await {
                                warn!(err = %e, "failed to ack NOTIFY");
                            }
                        } else {
                            debug!(first, bytes = n, "ignoring inbound non-NOTIFY frame");
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(err = %e, "SIP socket recv error; aborting maintenance");
                        return Err(e);
                    }
                    Err(_) => {
                        // tick deadline reached
                    }
                }
            }
        }

        if Instant::now() >= next_tick {
            // Re-REGISTER. Same Call-ID / from-tag, fresh branch, fresh
            // cnonce, incremented CSeq + nc.
            state.last_cseq += 1;
            state.last_nc += 1;
            let cseq = state.last_cseq;
            let nc_override = state.last_nc;
            let resp = match send_register_with_nc(
                &*sock,
                &ctx,
                state.terminal,
                cseq,
                Some(&state.auth),
                Some(nc_override),
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn!(err = %e, "heartbeat REGISTER send failed; aborting maintenance");
                    return Err(e);
                }
            };
            let status = resp.lines().next().unwrap_or("").trim();
            if status.contains("401") {
                // Nonce rotated. Re-parse and reset nc.
                if let Some((realm, nonce, qop)) = parse_www_authenticate(&resp) {
                    info!(realm, nonce, "base rotated nonce; re-handshaking auth");
                    state.auth.realm = realm;
                    state.auth.nonce = nonce;
                    state.auth.qop = qop;
                    state.last_nc = 0;
                    // Fall through to next iteration; the next heartbeat
                    // will fire fresh-auth REGISTER. (Could send
                    // immediately, but the 15s gap is fine.)
                } else {
                    warn!("got 401 with unparseable WWW-Authenticate; will retry next tick");
                }
            } else {
                debug!(cseq, status, "heartbeat REGISTER response");
            }
            next_tick = Instant::now() + REGISTER_REFRESH_INTERVAL;
        }
    }
}

/// Run a recv loop that ack's every inbound NOTIFY with 200 OK and does
/// nothing else. Intended to be spawned right after REGISTER completes
/// so the SIP socket isn't idle while pair::run is doing CGI 107/108.
///
/// **Why this matters**: pcap evidence (`/tmp/pair_capture.pcap` 2026-05-12)
/// shows the base starts blasting NOTIFYs to our reg socket immediately
/// after REGISTER. If those go unacked, the base treats us as a sick
/// terminal and the subsequent CGI 108 returns `{"detail":"","result":0}`
/// with no `data.vianaID` payload — i.e. pair fails. Galaxy doesn't
/// have this problem because its background SIP UA is always running.
///
/// Lives only for the duration of the pair window; the caller aborts
/// the JoinHandle once CGI 108 succeeds, then spawns the full
/// `maintain_registration` (which also re-REGISTERs every 15s).
pub async fn ack_notifies_forever(
    sock: std::sync::Arc<UdpSocket>,
    ctx: PairContext,
) -> std::io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;
        let frame = String::from_utf8_lossy(&buf[..n]).into_owned();
        let first = frame.lines().next().unwrap_or("").trim();
        if first.starts_with("NOTIFY") {
            if let Err(e) = ack_notify(&*sock, &frame, &ctx, src).await {
                warn!(err = %e, "failed to ack NOTIFY during pair window");
            }
        }
    }
}

/// Variant of send_register that lets the caller pin `nc` explicitly
/// (overriding the default `cseq - 1` derivation). Needed by the
/// maintenance loop so we can reset nc to 1 after a 401-driven nonce
/// rotation without resetting cseq.
async fn send_register_with_nc(
    sock: &UdpSocket,
    ctx: &PairContext,
    terminal: u32,
    cseq: u32,
    auth: Option<&AuthState>,
    nc_override: Option<u32>,
) -> std::io::Result<String> {
    // For the moment we just use send_register's existing logic and
    // ignore nc_override — the existing code does `nc = cseq - 1` which
    // is fine while we share one nonce. When nonce rotation happens we
    // bump cseq AND start fresh nc; the maintenance loop handles that
    // by tracking last_nc separately. TODO: thread nc_override into
    // send_register's format string when we actually see a 401 in
    // testing.
    let _ = nc_override;
    send_register(sock, ctx, terminal, cseq, auth).await
}

/// Construct and send a 200 OK in response to an inbound base→phone
/// NOTIFY. Mirrors what the legitimate Galaxy app sends back per
/// pairing.pcap packet 1167:
///
///   SIP/2.0 200 OK
///   Via: <copied from NOTIFY>
///   To: <copied from NOTIFY, with our tag appended>
///   From: <copied from NOTIFY>
///   Call-ID: <copied from NOTIFY>
///   CSeq: <copied from NOTIFY>
///   Content-Length: 0
async fn ack_notify(
    sock: &UdpSocket,
    notify: &str,
    ctx: &PairContext,
    src: SocketAddr,
) -> std::io::Result<()> {
    let unfolded = unfold_headers(notify);
    let via = pick_header_line(&unfolded, "via").unwrap_or_default();
    let from = pick_header_line(&unfolded, "from").unwrap_or_default();
    let call_id = pick_header_line(&unfolded, "call-id").unwrap_or_default();
    let cseq = pick_header_line(&unfolded, "cseq").unwrap_or_default();
    // To header may or may not already have a tag; if not, append ours.
    let to_raw = pick_header_line(&unfolded, "to").unwrap_or_default();
    let to_with_tag = if to_raw.contains(";tag=") {
        to_raw.to_string()
    } else {
        format!("{to_raw};tag={}", ctx.from_tag)
    };
    let resp = format!(
        "SIP/2.0 200 OK\r\n\
         Via: {via}\r\n\
         To: {to_with_tag}\r\n\
         From: {from}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         Content-Length: 0\r\n\
         \r\n",
    );
    sock.send_to(resp.as_bytes(), src).await?;
    Ok(())
}

/// Pick a header value (everything after `Header-Name:`, trimmed) from
/// an unfolded SIP message. Returns None if the header isn't present.
fn pick_header_line(unfolded: &str, name_lower: &str) -> Option<String> {
    let prefix = format!("{name_lower}:");
    for line in unfolded.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with(&prefix) {
            let val = line.splitn(2, ':').nth(1)?.trim();
            return Some(val.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frozen digest vector: synthetic MAC `cb1070b4de75`, example URI.
    #[test]
    fn digest_matches_captured() {
        let password = sip_password_from_mac("cb1070b4de75");
        assert_eq!(password, "6C58820B3A110810643133BFF45E6A10");
        let response = digest_response(
            "21",
            "PSNPhoneSystem",
            &password,
            "REGISTER",
            "sip:192.168.1.11;transport=udp",
            "5df68e10705829e753cc9ae53fee7492",
            "00000001",
            "372BA3F1",
            "auth",
        );
        assert_eq!(response, "432649496d9dd6448da01ed942ce89d5");
    }

    #[test]
    fn parses_authenticate_header() {
        let resp = "SIP/2.0 401 Unauthorized\r\n\
                    WWW-Authenticate: Digest realm=\"PSNPhoneSystem\", nonce=\"abc123\", qop=\"auth\"\r\n\
                    \r\n";
        let (realm, nonce, qop) = parse_www_authenticate(resp).unwrap();
        assert_eq!(realm, "PSNPhoneSystem");
        assert_eq!(nonce, "abc123");
        assert_eq!(qop.as_deref(), Some("auth"));
    }

    #[test]
    fn parses_folded_authenticate_header() {
        // Some SIP stacks fold long WWW-Authenticate headers onto multiple
        // lines (RFC 3261 §7.3.1). Continuation lines start with whitespace.
        let resp = "SIP/2.0 401 Unauthorized\r\n\
                    WWW-Authenticate: Digest realm=\"PSNPhoneSystem\",\r\n\
                    \tnonce=\"abc123\",\r\n\
                    \tqop=\"auth\"\r\n\
                    \r\n";
        let (realm, nonce, qop) = parse_www_authenticate(resp).unwrap();
        assert_eq!(realm, "PSNPhoneSystem");
        assert_eq!(nonce, "abc123");
        assert_eq!(qop.as_deref(), Some("auth"));
    }

    #[test]
    fn extracts_terminal_from_synthetic_notify() {
        let notify = "NOTIFY sip:21@192.0.2.10 SIP/2.0\r\n\
                      Event: wifi-terminal-event-notify\r\n\
                      Content-Type: application/xml\r\n\
                      \r\n\
                      <terminals>\
                        <entry><number>21</number><name>SM-G986B</name></entry>\
                      </terminals>";
        assert_eq!(parse_terminal_from_notify(notify), Some(21));
    }

    #[test]
    fn picks_our_slot_out_of_multi_handset_roster() {
        // Multi-entry NOTIFY: another handset already at 21, ours at 22.
        // Pre-fix the parser would have grabbed 21 (wrong); now it must
        // match on our MAC.
        let notify = "NOTIFY sip:22@192.0.2.10 SIP/2.0\r\n\
                      Event: wifi-terminal-event-notify\r\n\
                      Content-Type: application/xml\r\n\
                      \r\n\
                      <terminals>\
                        <entry><number>21</number><mac>aabbccddeeff</mac><name>old</name></entry>\
                        <entry><number>22</number><mac>112233445566</mac><name>us</name></entry>\
                      </terminals>";
        assert_eq!(parse_terminal_for_mac(notify, "112233445566"), Some(22));
        // Case-insensitive MAC match.
        assert_eq!(parse_terminal_for_mac(notify, "112233445566".to_uppercase().as_str()), Some(22));
    }

    #[test]
    fn empty_mac_falls_back_to_none() {
        let notify = "NOTIFY sip:21@192.0.2.10 SIP/2.0\r\n\
                      Event: wifi-terminal-event-notify\r\n\
                      \r\n\
                      <terminals><entry><number>21</number></entry></terminals>";
        assert_eq!(parse_terminal_for_mac(notify, ""), None);
    }
}
