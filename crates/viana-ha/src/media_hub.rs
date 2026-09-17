//! Daemon-wide shared state that bridges `run_monitor` (which owns the
//! base-side RTP sockets) with the HTTP API endpoints (which serve media
//! to HA + accept mic input from HA).
//!
//! Created once at daemon startup; cloned (via Arc) into both run_monitor
//! and the HTTP server's ApiState. Per INTERCOM-DESIGN.md §C and §D.
//!
//! What lives here:
//!   * Broadcast channels for inbound media (PCM audio samples from base,
//!     raw H264 NALU bytes from base) — multi-consumer; HTTP stream
//!     handlers attach as receivers
//!   * Talker state — per-talker mic input ring buffers, fed by
//!     POST /stream/audio/in, drained by the 20ms mixer tick that runs
//!     inside run_monitor
//!   * Outbound RTP context — set when monitor session active, holds the
//!     UDP socket + base audio addr that the mixer ships PCMA frames to
//!   * Monitor phase atomic — 0=idle, 1=preview (rx only), 2=talking
//!     (rx + at least one talker active). HTTP /state reads this.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::{broadcast, Mutex};
use uuid::Uuid;

/// 8 kHz sample rate, 20 ms RTP frame = 160 samples.
pub const SAMPLES_PER_FRAME: usize = 160;

/// Per-talker buffer holds up to 80 ms of PCM (4× frame interval) so the
/// mixer can pull a full frame even with bursty HA input.
pub const TALKER_BUFFER_SAMPLES: usize = SAMPLES_PER_FRAME * 4;

/// Drop a talker after this many milliseconds of mic silence with no
/// explicit /control/hangup. Prevents a crashed HA tab from holding a
/// slot indefinitely. See INTERCOM-DESIGN.md §D.
pub const TALKER_IDLE_TIMEOUT_MS: u64 = 10_000;

/// Monitor lifecycle phase. Reported on /state and via SSE
/// `monitor.started` / `monitor.ended`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MonitorPhase {
    Idle = 0,
    Preview = 1,
    Talking = 2,
}

impl MonitorPhase {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Preview,
            2 => Self::Talking,
            _ => Self::Idle,
        }
    }
}

/// Per-talker mic-input ring buffer + bookkeeping.
pub struct TalkerSlot {
    pub source: String,
    pub buffer: VecDeque<i16>,
    pub last_chunk_at: Instant,
}

/// Outbound audio context — populated by run_monitor when a session
/// starts, cleared when it ends. The mixer task pulls this Arc to know
/// where to send.
pub struct OutboundAudio {
    pub sock: Arc<UdpSocket>,
    pub base_audio_addr: SocketAddr,
    /// PCMA payload type; almost always 8 (G.711 a-law).
    pub payload_type: u8,
    /// SSRC to use on outbound packets. Match the inbound-flow SSRC if
    /// the base correlates per-flow; for now matches the keepalive const.
    pub ssrc: u32,
    /// Per-call XOR key (8 bytes) — same one used to decrypt inbound,
    /// applied symmetrically on outbound from offset 12.
    pub xor_data: [u8; 8],
}

/// Mutable shared state. Most accesses are infrequent (talker
/// add/remove, monitor start/stop) so a single Mutex is fine. Audio
/// samples flow through the broadcast channels which don't need this
/// lock at all.
pub struct HubState {
    pub talkers: std::collections::HashMap<Uuid, TalkerSlot>,
    pub outbound: Option<Arc<OutboundAudio>>,
    /// Set true while monitor session is in `Preview` or `Talking`. Used
    /// by run_monitor to suppress its idle-teardown timer when a HA
    /// stream consumer is attached.
    pub stream_consumers: usize,
}

impl HubState {
    fn new() -> Self {
        Self {
            talkers: std::collections::HashMap::new(),
            outbound: None,
            stream_consumers: 0,
        }
    }
}

pub struct MediaHub {
    /// Decoded PCM samples from base (post-XOR, post-PCMA-decode). 8 kHz
    /// mono i16. Each broadcast item is one 20 ms frame (160 samples).
    pub audio_in_tx: broadcast::Sender<Arc<Vec<i16>>>,
    /// Raw H264 NALU bytes from base (post-XOR, with the 12-byte RTP
    /// header stripped). Each broadcast item is one RTP-packet payload;
    /// the consumer is responsible for NALU framing / SPS/PPS handling.
    pub video_in_tx: broadcast::Sender<Arc<Vec<u8>>>,
    /// Mutable shared state. See `HubState`.
    pub state: Mutex<HubState>,
    /// 0=idle, 1=preview, 2=talking. Read with relaxed ordering.
    phase: AtomicU8,
}

impl MediaHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            audio_in_tx: broadcast::channel(64).0,
            video_in_tx: broadcast::channel(256).0,
            state: Mutex::new(HubState::new()),
            phase: AtomicU8::new(MonitorPhase::Idle as u8),
        })
    }

    pub fn phase(&self) -> MonitorPhase {
        MonitorPhase::from_u8(self.phase.load(Ordering::Relaxed))
    }

    pub fn set_phase(&self, phase: MonitorPhase) {
        self.phase.store(phase as u8, Ordering::Relaxed);
    }
}
