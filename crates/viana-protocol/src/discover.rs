//! `tgdect` — Panasonic's proprietary LAN-discovery protocol.
//!
//! LAN discovery via `tgdect` UDP broadcast and a TCP callback.
//! See `docs/PROTOCOL.md`. Reference Python port: none — this
//! crate is the canonical implementation.
//!
//! Wire shape:
//!   1. Phone binds a random high TCP listener (`tcp_port`) in the app's
//!      hardcoded search range, 60000..=65000.
//!   2. Phone sends UDP broadcast → `255.255.255.255:50006` with ASCII payload
//!      `"tgdect,{tcp_port},{mac_filter}"`. `mac_filter` is `00:00:00:00:00:00`
//!      during initial pairing (wildcard), or the known base MAC for normal-
//!      mode searches. The legitimate app also binds the UDP sender to a
//!      random source port in the same 60000..=65000 range.
//!   3. Base TCP-callbacks to `phone_ip:tcp_port` and writes ASCII CSV
//!      `"<base_ip>,<base_mac>,<model>,<status>"`. `status=0` → base found,
//!      pair button NOT pressed; `status=1` → base in pair-accept mode.
//!
//! `discover_base` polls every ~5 s with a fresh listen port each time, until
//! it sees `status=1` or hits the deadline.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use rand::Rng;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::{Instant, sleep, timeout};

const TGDECT_PORT: u16 = 50006;
const SEARCH_PORT_MIN: u16 = 60000;
const SEARCH_PORT_MAX: u16 = 65000;
const BIND_ATTEMPTS: usize = 10;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const TCP_ACCEPT_BUDGET: Duration = Duration::from_millis(1500);
const TCP_READ_BUDGET: Duration = Duration::from_millis(500);

/// What the base reports about itself in the discovery response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredBase {
    pub lan_ip: Ipv4Addr,
    /// Lowercase, colon-separated, e.g. `"00:11:22:33:44:55"`.
    pub mac: String,
    /// Model string the base reports. Observed: `"KX-HNB600"`.
    pub model: String,
}

/// What state the base is in. `status` field of the CSV response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairStatus {
    /// `status=0` — base is on the LAN but the pair button has not been
    /// pressed (or the pair-accept window expired).
    NotAccepting,
    /// `status=1` — base is in pair-accept mode; the SIP MESSAGE bootstrap
    /// will be honoured.
    Accepting,
}

/// Outcome of `wait_for_accepting`: either the base entered pair mode, the
/// deadline expired (with `last_seen` carrying the most recent `NotAccepting`
/// observation if any), or no Panasonic answered at all.
#[derive(Debug, Clone)]
pub enum DiscoverOutcome {
    Accepted(DiscoveredBase),
    TimedOutWaiting { last_seen: DiscoveredBase },
    NoBaseOnLan,
}

/// One-shot probe: send a single broadcast and wait briefly for a callback.
/// Returns the base + status if anything answered. Used for the HA Config
/// Flow's "is there a Panasonic on this LAN at all?" check before asking the
/// user to press the pair button.
pub async fn probe_once() -> std::io::Result<Option<(DiscoveredBase, PairStatus)>> {
    let (listener, tcp_port) = bind_tcp_search_listener().await?;

    let udp = bind_udp_search_socket().await?;
    udp.set_broadcast(true)?;
    let probe = format!("tgdect,{tcp_port},00:00:00:00:00:00");
    udp.send_to(
        probe.as_bytes(),
        SocketAddrV4::new(Ipv4Addr::BROADCAST, TGDECT_PORT),
    )
    .await?;

    match timeout(TCP_ACCEPT_BUDGET, listener.accept()).await {
        Ok(Ok((mut stream, _peer))) => {
            let mut buf = [0u8; 256];
            let n = match timeout(TCP_READ_BUDGET, stream.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                _ => return Ok(None),
            };
            Ok(parse_response_bytes(&buf[..n]))
        }
        _ => Ok(None),
    }
}

async fn bind_tcp_search_listener() -> std::io::Result<(TcpListener, u16)> {
    let mut last_err = None;
    for _ in 0..BIND_ATTEMPTS {
        let port = random_search_port();
        match TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await {
            Ok(listener) => return Ok((listener, port)),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no search TCP port attempted",
        )
    }))
}

async fn bind_udp_search_socket() -> std::io::Result<UdpSocket> {
    let mut last_err = None;
    for _ in 0..BIND_ATTEMPTS {
        let port = random_search_port();
        match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await {
            Ok(socket) => return Ok(socket),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no search UDP port attempted",
        )
    }))
}

fn random_search_port() -> u16 {
    rand::thread_rng().gen_range(SEARCH_PORT_MIN..=SEARCH_PORT_MAX)
}

/// Poll the LAN until a Panasonic base reports `status=1` (pair-accept) or
/// `deadline` elapses. Sends a fresh probe every ~5 s with a new TCP listen
/// port (matches the legitimate Galaxy app's behaviour).
pub async fn wait_for_accepting(deadline: Duration) -> std::io::Result<DiscoverOutcome> {
    let until = Instant::now() + deadline;
    let mut last_found: Option<DiscoveredBase> = None;

    while Instant::now() < until {
        if let Some((base, status)) = probe_once().await? {
            match status {
                PairStatus::Accepting => return Ok(DiscoverOutcome::Accepted(base)),
                PairStatus::NotAccepting => last_found = Some(base),
            }
        }
        if Instant::now() + POLL_INTERVAL > until {
            break;
        }
        sleep(POLL_INTERVAL).await;
    }

    Ok(match last_found {
        Some(b) => DiscoverOutcome::TimedOutWaiting { last_seen: b },
        None => DiscoverOutcome::NoBaseOnLan,
    })
}

/// Parse a tgdect callback CSV. The pcap shows a trailing NUL after the status
/// digit; logcat may render trailing non-printables strangely.
pub fn parse_response(raw: &str) -> Option<(DiscoveredBase, PairStatus)> {
    parse_response_bytes(raw.as_bytes())
}

pub fn parse_response_bytes(raw: &[u8]) -> Option<(DiscoveredBase, PairStatus)> {
    let end = raw
        .iter()
        .position(|b| matches!(b, b'\0' | b'\r' | b'\n'))
        .unwrap_or(raw.len());
    let trimmed = std::str::from_utf8(&raw[..end]).ok()?.trim();
    let parts: Vec<&str> = trimmed.split(',').collect();
    if parts.len() < 4 {
        return None;
    }
    let lan_ip: Ipv4Addr = parts[0].parse().ok()?;
    let mac = parts[1].to_ascii_lowercase();
    let model = parts[2].to_string();
    let status = match parts[3].chars().next()? {
        '1' => PairStatus::Accepting,
        '0' => PairStatus::NotAccepting,
        _ => return None,
    };
    Some((DiscoveredBase { lan_ip, mac, model }, status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_callback() {
        let (base, status) = parse_response_bytes(
            b"192.0.2.1,00:11:22:33:44:55,KX-HNB600,1\0",
        )
        .unwrap();
        assert_eq!(base.lan_ip, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(base.mac, "00:11:22:33:44:55");
        assert_eq!(base.model, "KX-HNB600");
        assert_eq!(status, PairStatus::Accepting);
    }

    #[test]
    fn parses_status_zero() {
        let (_, status) = parse_response_bytes(
            b"192.0.2.1,00:11:22:33:44:55,KX-HNB600,0\0",
        )
        .unwrap();
        assert_eq!(status, PairStatus::NotAccepting);
    }

    #[test]
    fn tolerates_trailing_line_ending() {
        let raw = b"192.0.2.1,00:11:22:33:44:55,KX-HNB600,0\r\n";
        let (base, status) = parse_response_bytes(raw).unwrap();
        assert_eq!(base.lan_ip, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(status, PairStatus::NotAccepting);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_response("not,enough").is_none());
        assert!(parse_response("not.an.ip,mac,model,1").is_none());
        assert!(parse_response("192.0.2.1,mac,model,9").is_none());
    }
}
