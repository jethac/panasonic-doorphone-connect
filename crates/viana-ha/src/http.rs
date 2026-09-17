//! Local HTTP API surface for the daemon.
//!
//! The HA Custom Integration is the primary client. It hits us at
//! `127.0.0.1:7878` (or wherever `[server].listen` says) for state, pairing,
//! monitor control, and live media. The desktop debug client uses the same
//! API from the LAN/Tailscale side.
//!
//! Authn: bearer token from the on-disk config. Every endpoint except
//! `/state` (which only leaks paired/unpaired and listen addr) requires
//! `Authorization: Bearer <token>`. The integration grabs the token by
//! reading the same config file as the daemon (it's installed on the same
//! box; the token never has to traverse the network).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Response, sse::{Event, KeepAlive, Sse}},
    routing::{get, post},
};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast};
use tracing::{info, warn};

use crate::config::{BaseConfig, Config};

/// Shared state every handler can borrow. A clone is cheap (Arcs all the way
/// down).
#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<Mutex<Config>>,
    pub config_path: std::path::PathBuf,
    /// Send daemon commands. Same channel that stdin writes to. Cloning is
    /// safe; mpsc senders are clone-able.
    pub cmd_tx: tokio::sync::mpsc::Sender<crate::DaemonCommand>,
    /// Broadcast bus of structured events the daemon emits. The `/events`
    /// SSE endpoint subscribes here. JSON-serialised before being sent
    /// over the wire.
    pub events: broadcast::Sender<serde_json::Value>,
    /// Daemon-wide media hub — broadcast channels for inbound media
    /// (consumed by `/stream/video`, which muxes both H.264 video and
    /// PCM audio into a single MPEG-TS) and talker state for outbound
    /// mic input (`/control/answer`, `/stream/audio/in`,
    /// `/control/hangup`). See `crate::media_hub`.
    pub media_hub: Arc<crate::media_hub::MediaHub>,
}

pub async fn serve(state: ApiState) -> anyhow::Result<()> {
    let addr: SocketAddr = state
        .config
        .lock()
        .await
        .server
        .listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid server.listen: {e}"))?;

    let app = Router::new()
        .route("/state", get(get_state))
        .route("/discover", post(post_discover))
        .route("/pair", post(post_pair))
        .route("/monitor", post(post_monitor).delete(delete_monitor))
        .route("/events", get(get_events))
        // Phase 2/3: live inbound stream from the base — H264 video
        // muxed with PCMA audio into MPEG-TS. There's no standalone
        // audio endpoint; intercom audio is the camera's audio track.
        .route("/stream/video", get(get_stream_video))
        // Phase 4: outbound mic input + answer/hangup control. See
        // INTERCOM-DESIGN.md §D.
        .route("/control/answer", post(post_control_answer))
        .route("/control/hangup", post(post_control_hangup))
        .route("/stream/audio/in", post(post_stream_audio_in))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?;
    info!(%addr, "HTTP API listening");
    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("axum serve: {e}"))?;
    Ok(())
}

/// Authn middleware. /state is intentionally exempt so the HA integration
/// can probe the daemon to confirm it's alive before prompting the user
/// for a token.
async fn require_bearer(
    State(state): State<ApiState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if req.uri().path() == "/state" {
        return Ok(next.run(req).await);
    }
    let expected = state.config.lock().await.server.auth_token.clone();
    // /stream/video is consumed by HA's stream worker → ffmpeg, which
    // can't carry a Bearer header through the URL hand-off. Accept the
    // token as a `?token=` query param for /stream/* endpoints. Same
    // secret value as the Bearer header.
    let from_query = if req.uri().path().starts_with("/stream/") {
        req.uri()
            .query()
            .and_then(|q| {
                q.split('&')
                    .filter_map(|kv| kv.split_once('='))
                    .find_map(|(k, v)| (k == "token").then(|| v.to_string()))
            })
    } else {
        None
    };
    let from_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::to_owned);
    let presented = from_query.or(from_header).unwrap_or_default();
    if presented.is_empty() || presented != expected {
        warn!(path = %req.uri().path(), "rejected unauthenticated request");
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(req).await)
}

#[derive(Serialize)]
struct StateView {
    paired: bool,
    base: Option<BaseConfig>,
    listen: String,
    daemon_version: &'static str,
}

async fn get_state(State(state): State<ApiState>) -> Json<StateView> {
    let cfg = state.config.lock().await;
    Json(StateView {
        paired: cfg.is_paired(),
        base: cfg.base.clone(),
        listen: cfg.server.listen.clone(),
        daemon_version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Serialize)]
struct DiscoverResponse {
    /// Whether a Panasonic base answered the tgdect probe.
    found: bool,
    /// Present iff `found`. Lowercase-MAC + IP + model the base reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    base: Option<DiscoveredView>,
    /// Whether the base is currently in pair-accept mode (status=1). When
    /// `found` is true and this is false, the user hasn't pressed the pair
    /// button yet — HA can prompt them and call /pair.
    accepting: bool,
}

#[derive(Serialize)]
struct DiscoveredView {
    lan_ip: std::net::Ipv4Addr,
    mac: String,
    model: String,
}

/// One-shot tgdect probe. The HA Config Flow uses this BEFORE asking the
/// user to press the pair button, so it can fail-fast if the daemon is on
/// a network with no Panasonic base.
async fn post_discover(
    State(_state): State<ApiState>,
) -> Result<Json<DiscoverResponse>, (StatusCode, String)> {
    match viana_protocol::discover::probe_once().await {
        Ok(Some((base, status))) => Ok(Json(DiscoverResponse {
            found: true,
            base: Some(DiscoveredView {
                lan_ip: base.lan_ip,
                mac: base.mac,
                model: base.model,
            }),
            accepting: matches!(status, viana_protocol::discover::PairStatus::Accepting),
        })),
        Ok(None) => Ok(Json(DiscoverResponse {
            found: false,
            base: None,
            accepting: false,
        })),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("discover: {e}"))),
    }
}

#[derive(Deserialize)]
struct PairRequest {
    /// User-supplied login password they previously set on the base unit's
    /// own menu. CGI 107 will validate it.
    base_login_password: String,
    /// Friendly name the user wants to give the door phone. Surfaces on the
    /// base's handset list and in HA.
    #[serde(default)]
    display_name: Option<String>,
    /// How long to wait for the user to press the pair button on the base.
    /// Defaults to 60s if omitted.
    #[serde(default)]
    pair_window_secs: Option<u64>,
}

#[derive(Serialize)]
struct PairResponse {
    /// Pair flow status: "paired" on success.
    status: &'static str,
    /// The freshly-persisted base info. Same shape /state will return on
    /// the next call.
    base: BaseConfig,
}

/// Drive a full pair flow:
///   1. Make sure we have a minted identity (kiki.dat + disp_id sidecar).
///   2. Wait for the base to enter pair-accept mode.
///   3. SIP MESSAGE → SIP REGISTER → CGI 107 (login) → CGI 108 (register).
///   4. Persist the result to config.toml.
async fn post_pair(
    State(state): State<ApiState>,
    Json(req): Json<PairRequest>,
) -> Result<Json<PairResponse>, (StatusCode, String)> {
    use viana_protocol::pair::{PairError, PairInputs};

    // Snapshot what we need from config under the lock, then drop it — the
    // pair flow takes 30+s and we don't want to block /state probes.
    let (kiki_path, unique_id, listen_for_local_ip, base_viana_id_hint) = {
        let cfg = state.config.lock().await;
        (
            cfg.identity.kiki_path.clone(),
            cfg.identity
                .unique_id
                .clone()
                .unwrap_or_else(|| viana_protocol::mint::DEFAULT_UNIQUE_ID.to_string()),
            cfg.server.listen.clone(),
            cfg.base
                .as_ref()
                .map(|b| b.viana_id.clone())
                .filter(|s| !s.is_empty()),
        )
    };

    // Step 1: identity.
    let identity = crate::identity::load_or_mint_with_disp_id(&kiki_path, &unique_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("identity: {e:#}")))?;

    let local_ip = pick_local_ipv4(&listen_for_local_ip)
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "could not pick local ipv4".into()))?;

    let phone_name = req.display_name.clone().unwrap_or_else(|| "viana-ha".to_string());
    let pair_window = Duration::from_secs(req.pair_window_secs.unwrap_or(60));

    let inputs = PairInputs {
        local_ip,
        local_sip_port: 0,
        base_login_password: &req.base_login_password,
        phone_name: &phone_name,
        our_viana_id: &identity.disp_id,
        our_cert: &identity.signature_device_id,
        synthetic_mac: &identity.synthetic_mac,
        base_viana_id_hint: base_viana_id_hint.as_deref(),
        pair_window,
    };

    let (result, maintenance) = match viana_protocol::pair::run(inputs).await {
        Ok(r) => r,
        Err(PairError::NoBaseOnLan) => {
            return Err((
                StatusCode::NOT_FOUND,
                "no Panasonic base found on this LAN".into(),
            ));
        }
        Err(PairError::PairButtonTimeout) => {
            return Err((
                StatusCode::REQUEST_TIMEOUT,
                "pair button was not pressed in time".into(),
            ));
        }
        Err(PairError::LoginRejected(code)) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!("base rejected login password (CGI 107 result={code})"),
            ));
        }
        Err(e) => {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("pair: {e}")));
        }
    };

    // Persist into config.
    let base_cfg = BaseConfig {
        viana_id: result.base_viana_id.clone(),
        lan_ip: Some(result.base_lan_ip.to_string()),
        mac: Some(result.base_mac.clone()),
        model: Some(result.base_model.clone()),
        display_name: req.display_name.clone(),
        paired_at: Some(now_iso8601()),
        synthetic_mac: Some(result.synthetic_mac.clone()),
        assigned_terminal: Some(result.assigned_terminal),
        cert: result.base_cert.clone(),
    };
    {
        let mut cfg = state.config.lock().await;
        cfg.base = Some(base_cfg.clone());
        if let Err(e) = cfg.save(&state.config_path) {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("save config: {e:#}"),
            ));
        }
    }

    // Notify SSE subscribers so the HA Config Flow can pick up the new base
    // without polling /state.
    let _ = state.events.send(serde_json::json!({
        "event": "paired",
        "base": &base_cfg,
    }));

    // Spawn the long-running SIP maintenance task. The legitimate Galaxy
    // app keeps the SIP UA alive forever after pair (re-REGISTER every
    // 15s + NOTIFY ack); not doing so would leave us looking like a
    // handset that paired then immediately disappeared from SIP. Task
    // owns the REGISTER socket; it runs until daemon exit or
    // socket-error. No graceful shutdown plumbing yet — daemon process
    // exit kills it.
    tokio::spawn(async move {
        if let Err(e) = viana_protocol::sip::maintain_registration(
            maintenance.sock,
            maintenance.ctx,
            maintenance.register_state,
        )
        .await
        {
            tracing::warn!(err = %e, "SIP maintenance task exited");
        }
    });

    Ok(Json(PairResponse {
        status: "paired",
        base: base_cfg,
    }))
}

/// Pick the local IPv4 we should advertise during pair. Honours the bind
/// address in `[server].listen` if it's a concrete IP; otherwise falls back
/// to whichever interface routes to 8.8.8.8.
fn pick_local_ipv4(listen: &str) -> Option<std::net::Ipv4Addr> {
    if let Ok(addr) = listen.parse::<SocketAddr>() {
        if let std::net::IpAddr::V4(v4) = addr.ip() {
            if !v4.is_unspecified() {
                return Some(v4);
            }
        }
    }
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// ISO-8601 (UTC) "now". Reuses the cheap formatter from main.rs's tracing
/// timestamps — but expressed inline here to avoid a circular dep.
fn now_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let days = (secs / 86400) as i64;
    let s_of_day = (secs % 86400) as u32;
    let h = s_of_day / 3600;
    let m = (s_of_day % 3600) / 60;
    let s = s_of_day % 60;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let mon = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = (y + if mon <= 2 { 1 } else { 0 }) as i32;
    format!("{y:04}-{mon:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[derive(Deserialize, Default)]
struct MonitorRequest {
    /// Override the door number (default = first registered door).
    #[serde(default)]
    door_no: Option<u32>,
    /// Where the daemon writes audio.bin / video.bin during the session.
    /// HA picks something under its own data dir.
    media_dir: String,
}

#[derive(Serialize)]
struct MonitorResponse {
    status: &'static str,
}

async fn post_monitor(
    State(state): State<ApiState>,
    Json(req): Json<MonitorRequest>,
) -> Result<Json<MonitorResponse>, (StatusCode, String)> {
    if !state.config.lock().await.is_paired() {
        return Err((StatusCode::FAILED_DEPENDENCY, "daemon is unpaired".into()));
    }
    state
        .cmd_tx
        .send(crate::DaemonCommand::StartMonitor {
            media_dir: req.media_dir,
            door_no: req.door_no,
            duration_secs: Some(0),
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("queue: {e}")))?;
    Ok(Json(MonitorResponse { status: "started" }))
}

async fn delete_monitor(
    State(state): State<ApiState>,
) -> Result<Json<MonitorResponse>, (StatusCode, String)> {
    state
        .cmd_tx
        .send(crate::DaemonCommand::StopMonitor)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("queue: {e}")))?;
    Ok(Json(MonitorResponse { status: "stopping" }))
}

/// SSE feed of every structured event the daemon emits — ring detections,
/// monitor lifecycle, base getState replies. The HA integration's
/// coordinator subscribes here and fans the events out to entity updates.
async fn get_events(
    State(state): State<ApiState>,
) -> Sse<impl Stream<Item = Result<Event, axum::Error>>> {
    let mut rx = state.events.subscribe();
    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(value) => {
                    let payload = value.to_string();
                    yield Ok(Event::default().data(payload));
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    yield Ok(Event::default().event("lag").data(n.to_string()));
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

// ===========================================================================
// Phase 2/3 — inbound media streams (camera + listen audio)
// ===========================================================================

/// Drop guard returned by `increment_consumer_and_maybe_start`. Lives
/// for the duration of the HTTP stream (held by the async_stream
/// closure). On drop: decrements the consumer count, then 30s later
/// checks if everything is idle and ends the monitor session if so.
struct ConsumerGuard {
    hub: std::sync::Arc<crate::media_hub::MediaHub>,
    cmd_tx: tokio::sync::mpsc::Sender<crate::DaemonCommand>,
}

impl Drop for ConsumerGuard {
    fn drop(&mut self) {
        let hub = self.hub.clone();
        let cmd_tx = self.cmd_tx.clone();
        tokio::spawn(async move {
            {
                let mut s = hub.state.lock().await;
                if s.stream_consumers > 0 {
                    s.stream_consumers -= 1;
                }
            }
            // 30s grace before tearing down — HA stream integration
            // tends to disconnect/reconnect briefly during snapshot
            // grabs and we don't want to flap the base-side session.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let s = hub.state.lock().await;
            if s.stream_consumers == 0 && s.talkers.is_empty() && s.outbound.is_some() {
                drop(s);
                if let Err(e) = cmd_tx.send(crate::DaemonCommand::StopMonitor).await {
                    tracing::warn!("idle teardown StopMonitor send failed: {e}");
                } else {
                    tracing::info!("idle teardown — last stream consumer gone, ending monitor");
                }
            }
        });
    }
}

/// Increment the daemon-wide stream consumer count. If we just
/// transitioned from zero (no monitor active yet), fire StartMonitor
/// so the camera/audio actually has bytes to serve. Per
/// INTERCOM-DESIGN.md §C "manual camera open also fires monitor".
async fn increment_consumer_and_maybe_start(state: &ApiState) -> ConsumerGuard {
    let should_start = {
        let mut s = state.media_hub.state.lock().await;
        let was_idle = s.stream_consumers == 0 && s.outbound.is_none();
        s.stream_consumers += 1;
        was_idle
    };
    if should_start {
        let cmd = crate::DaemonCommand::StartMonitor {
            media_dir: "/tmp/viana-stream".to_string(),
            door_no: Some(1),
            duration_secs: Some(0),
        };
        if let Err(e) = state.cmd_tx.try_send(cmd) {
            warn!("stream-open StartMonitor send failed: {e}");
        } else {
            info!("stream consumer attached → fired monitor session");
        }
    }
    ConsumerGuard {
        hub: state.media_hub.clone(),
        cmd_tx: state.cmd_tx.clone(),
    }
}

/// RAII guard for a temp FIFO file used to feed audio to ffmpeg. Removes
/// the file on drop. We intentionally don't share the FIFO across
/// consumers — each HA stream worker gets its own ffmpeg + its own FIFO
/// so a disconnect cleanly tears down both.
struct FifoCleanup(std::path::PathBuf);
impl Drop for FifoCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `GET /stream/video` — MPEG-TS muxed H.264 video + AAC audio for HA's
/// stream integration to consume. The intercom audio is the camera's
/// audio track — there's no standalone listen endpoint.
///
/// Pipeline:
///   broadcast<Annex-B NALU> → ffmpeg stdin (pipe:0)
///   broadcast<i16 PCM 8 kHz> → s16le bytes → audio FIFO (named pipe)
///   ffmpeg muxes to MPEG-TS → stdout → HTTP response body
///
/// Audio comes in over a Unix FIFO because ffmpeg's CLI only takes one
/// stdin; pipe:0 is video, the FIFO path is the second input. The FIFO
/// is created per session in /tmp and removed on disconnect.
///
/// We spawn ffmpeg per consumer because each HA stream worker session
/// needs its own muxer state (PMT/PAT counters, continuity counters).
/// `-fflags +genpts` synthesizes monotonic PTS/DTS from the input rate —
/// without this, raw H.264 with no in-band timing throws "No dts in 7
/// consecutive packets" on the HA side.
///
/// On consumer attach, also fires StartMonitor if no session is
/// active (INTERCOM-DESIGN.md §C). On consumer drop, ffmpeg is killed
/// (kill_on_drop), feeder tasks abort, the FIFO is removed, and the
/// ConsumerGuard triggers the 30s idle-teardown check.
async fn get_stream_video(
    State(state): State<ApiState>,
) -> impl axum::response::IntoResponse {
    use axum::body::Body;
    use axum::http::header;
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::process::Command;

    let guard = increment_consumer_and_maybe_start(&state).await;
    let mut video_rx = state.media_hub.video_in_tx.subscribe();
    let audio_tx = state.media_hub.audio_in_tx.clone();

    // Per-session audio FIFO. Lives in /tmp so it's auto-cleaned on
    // reboot if Drop misses; FifoCleanup removes it on normal teardown.
    let session_id = uuid::Uuid::new_v4();
    let audio_fifo_path = std::env::temp_dir().join(format!("viana-audio-{session_id}.fifo"));
    let mkfifo_status = Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(&audio_fifo_path)
        .status()
        .await;
    match mkfifo_status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            warn!("mkfifo exit status {s}");
            return axum::response::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("mkfifo failed"))
                .unwrap();
        }
        Err(e) => {
            warn!("mkfifo spawn failed: {e}");
            return axum::response::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("mkfifo spawn failed: {e}")))
                .unwrap();
        }
    }
    let fifo_cleanup = FifoCleanup(audio_fifo_path.clone());

    let mut child = match Command::new("ffmpeg")
        .args([
            "-hide_banner",
            "-loglevel", "warning",
            // +genpts so the muxer can synthesize timestamps; +nobuffer
            // so MPEG-TS output isn't held back by demux probing.
            "-fflags", "+genpts+nobuffer",
            // Video input — H.264 Annex-B over stdin. analyzeduration 0
            // + probesize 32 means ffmpeg doesn't wait 5 s of input
            // before opening the output muxer (that was the bulk of the
            // 7-second camera startup). -r 15 hints the framerate so
            // the demuxer can synthesize smooth 15 fps PTS via +genpts —
            // wallclock timestamps would inherit network jitter and
            // make playback stutter.
            "-analyzeduration", "0",
            "-probesize", "32",
            "-thread_queue_size", "1024",
            "-f", "h264",
            "-r", "15",
            "-i", "pipe:0",
            // Audio input — raw PCM s16le 8 kHz mono via FIFO. ffmpeg
            // opens this for read at startup; our writer task opens it
            // for write concurrently, which unblocks both sides. Our
            // writer paces at exactly 50 Hz (one 20 ms frame per tick),
            // so the natural byte rate matches 8 kHz and ffmpeg's
            // sample-count PTS comes out perfectly smooth.
            "-analyzeduration", "0",
            "-probesize", "32",
            "-thread_queue_size", "1024",
            "-f", "s16le",
            "-ar", "8000",
            "-ac", "1",
            "-i",
        ])
        .arg(&audio_fifo_path)
        .args([
            // Mux: video copy (no re-encode), audio AAC at 32 kbps.
            // 32k stays under the per-AAC-frame bit budget at 8 kHz
            // (max ≈ 48 kbps); 64k clamped, producing noisy frames the
            // browser eventually gave up on.
            "-c:v", "copy",
            "-c:a", "aac",
            "-b:a", "32k",
            "-ar", "8000",
            "-ac", "1",
            "-f", "mpegts",
            "-muxdelay", "0",
            "-muxpreload", "0",
            "-flush_packets", "1",
            "pipe:1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("ffmpeg spawn failed: {e}");
            drop(fifo_cleanup);
            return axum::response::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("ffmpeg spawn failed: {e}")))
                .unwrap();
        }
    };

    let mut stdin = child.stdin.take().expect("stdin pipe");
    let mut stdout = child.stdout.take().expect("stdout pipe");
    let stderr = child.stderr.take().expect("stderr pipe");

    // Drain stderr into log so ffmpeg warnings/errors are visible.
    tokio::spawn(async move {
        let mut reader = stderr;
        let mut buf = vec![0u8; 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let s = String::from_utf8_lossy(&buf[..n]);
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        warn!("ffmpeg: {trimmed}");
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Video feeder: broadcast<Annex-B NALU> → ffmpeg stdin.
    let video_feeder = tokio::spawn(async move {
        loop {
            match video_rx.recv().await {
                Ok(payload) => {
                    if stdin.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!("video broadcast lagged {n} frames; brief stutter possible");
                    continue;
                }
                Err(_) => break,
            }
        }
        let _ = stdin.shutdown().await;
    });

    // Audio feeder: opens the FIFO for write (blocks async until ffmpeg
    // opens it for read), then pumps PCM samples in at a fixed 50 Hz
    // (one 20 ms / 160-sample frame per tick). When the base sends real
    // audio we forward it; otherwise we emit a silence frame.
    //
    // Strictly one frame per tick — no burst-draining. If real frames
    // queue faster than we drain (network jitter), the broadcast
    // channel's 64-slot buffer absorbs ~1.3 s of slack; we catch up
    // naturally over subsequent ticks. Draining in bursts would write
    // 5–10 frames in one syscall, ffmpeg would assign close-together
    // PTS to that whole chunk, and the muxed output would stutter when
    // the player tried to pace itself by PTS.
    //
    // The constant cadence also matters because ffmpeg's MPEG-TS muxer
    // with two inputs won't emit output until both inputs have
    // produced data; silence keeps the muxer happy when the door is
    // quiet.
    let audio_fifo_for_writer = audio_fifo_path.clone();
    let audio_feeder = tokio::spawn(async move {
        let writer = match tokio::fs::OpenOptions::new()
            .write(true)
            .open(&audio_fifo_for_writer)
            .await
        {
            Ok(w) => w,
            Err(e) => {
                warn!("audio FIFO open failed: {e}");
                return;
            }
        };
        let mut writer = writer;
        let mut audio_rx = audio_tx.subscribe();
        // 20 ms ticks — matches one PCM frame at 8 kHz mono.
        let mut ticker = tokio::time::interval(std::time::Duration::from_millis(20));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let silence_frame_bytes: Vec<u8> = vec![0u8; 160 * 2]; // 160 samples × 2 bytes
        loop {
            ticker.tick().await;
            // Take at most ONE frame per tick. Empty → silence.
            let frame = match audio_rx.try_recv() {
                Ok(samples) => Some(samples),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => None,
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => None,
                Err(tokio::sync::broadcast::error::TryRecvError::Closed) => return,
            };
            let write_result = match frame {
                Some(samples) => {
                    let mut b = Vec::with_capacity(samples.len() * 2);
                    for s in samples.iter() {
                        b.extend_from_slice(&s.to_le_bytes());
                    }
                    writer.write_all(&b).await
                }
                None => writer.write_all(&silence_frame_bytes).await,
            };
            if write_result.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });

    // Body stream: pump ffmpeg stdout → HTTP. Captures everything that
    // needs cleanup so HA disconnects tear it all down.
    let stream = async_stream::stream! {
        let _consumer_guard = guard;
        let _ffmpeg_child = child;
        let _fifo_cleanup = fifo_cleanup;
        let video_handle = video_feeder;
        let audio_handle = audio_feeder;

        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match stdout.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    yield Ok::<_, std::io::Error>(bytes::Bytes::copy_from_slice(&buf[..n]));
                }
                Err(_) => break,
            }
        }
        video_handle.abort();
        audio_handle.abort();
    };

    let body = Body::from_stream(stream);
    axum::response::Response::builder()
        .header(header::CONTENT_TYPE, "video/mp2t")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(body)
        .unwrap()
}

// ===========================================================================
// Phase 4 — outbound mic + answer/hangup control
// ===========================================================================

#[derive(Deserialize)]
struct AnswerRequest {
    /// UUID minted by the HA surface — opaque correlation id used in
    /// /stream/audio/in's X-Talker-Token header and /control/hangup.
    talker_id: uuid::Uuid,
    /// Human-readable HA-side identifier (entity_id / device name) for
    /// telemetry only. Surfaces in `talker.joined` SSE events.
    #[serde(default)]
    source: Option<String>,
}

#[derive(Serialize)]
struct AnswerResponse {
    status: &'static str,
    talker_id: uuid::Uuid,
    talker_count: usize,
}

/// `POST /control/answer {talker_id, source?}` — register a new mic
/// talker. Per INTERCOM-DESIGN.md §D, multiple talkers can join
/// simultaneously; daemon mixes their PCM streams. Always returns 200
/// (no busy state).
async fn post_control_answer(
    State(state): State<ApiState>,
    Json(req): Json<AnswerRequest>,
) -> Result<Json<AnswerResponse>, (StatusCode, String)> {
    use std::time::Instant;
    let source = req.source.unwrap_or_else(|| "unknown".to_string());
    let talker = crate::media_hub::TalkerSlot {
        source: source.clone(),
        buffer: std::collections::VecDeque::with_capacity(crate::media_hub::TALKER_BUFFER_SAMPLES),
        last_chunk_at: Instant::now(),
    };
    let count = {
        let mut s = state.media_hub.state.lock().await;
        s.talkers.insert(req.talker_id, talker);
        s.talkers.len()
    };
    let _ = state.events.send(serde_json::json!({
        "event": "talker.joined",
        "source": source,
        "talker_id": req.talker_id,
        "talker_count": count,
    }));
    info!(source, talker_id = %req.talker_id, count, "talker joined");
    Ok(Json(AnswerResponse {
        status: "ok",
        talker_id: req.talker_id,
        talker_count: count,
    }))
}

#[derive(Deserialize)]
struct HangupRequest {
    talker_id: uuid::Uuid,
}

#[derive(Serialize)]
struct HangupResponse {
    status: &'static str,
    talker_count: usize,
    monitor_will_end: bool,
}

/// `POST /control/hangup {talker_id}` — remove a single talker. If they
/// were the LAST talker, also stops the monitor session (camera + audio
/// go idle). Per INTERCOM-DESIGN.md §C/§D.
async fn post_control_hangup(
    State(state): State<ApiState>,
    Json(req): Json<HangupRequest>,
) -> Result<Json<HangupResponse>, (StatusCode, String)> {
    let (count, source) = {
        let mut s = state.media_hub.state.lock().await;
        let removed = s.talkers.remove(&req.talker_id);
        let src = removed.map(|t| t.source).unwrap_or_else(|| "unknown".into());
        (s.talkers.len(), src)
    };
    let _ = state.events.send(serde_json::json!({
        "event": "talker.left",
        "source": source.clone(),
        "talker_id": req.talker_id,
        "reason": "hangup",
        "talker_count": count,
    }));
    info!(source, talker_id = %req.talker_id, count, "talker hung up");
    let monitor_will_end = count == 0;
    if monitor_will_end {
        // Last talker out — end the monitor session. Per §C, hang up
        // tears down the monitor regardless of stream consumers.
        if let Err(e) = state
            .cmd_tx
            .send(crate::DaemonCommand::StopMonitor)
            .await
        {
            warn!("hangup StopMonitor send failed: {e}");
        }
    }
    Ok(Json(HangupResponse {
        status: "ok",
        talker_count: count,
        monitor_will_end,
    }))
}

/// `POST /stream/audio/in` — accepts PCM 16-bit 8 kHz mono chunks from
/// HA. Header `X-Talker-Token: <uuid>` identifies which talker.
/// Chunks land in that talker's ring buffer; the mixer drains it at
/// 20 ms ticks. Returns 403 if the talker isn't currently registered.
async fn post_stream_audio_in(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    use std::time::Instant;
    let token_str = headers
        .get("x-talker-token")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "missing X-Talker-Token".into()))?;
    let token: uuid::Uuid = token_str
        .parse()
        .map_err(|e: uuid::Error| (StatusCode::BAD_REQUEST, format!("bad token: {e}")))?;

    if body.len() % 2 != 0 {
        return Err((StatusCode::BAD_REQUEST, "body must be 16-bit PCM (even byte count)".into()));
    }
    let samples: Vec<i16> = body
        .chunks_exact(2)
        .map(|c| i16::from_le_bytes([c[0], c[1]]))
        .collect();

    let mut s = state.media_hub.state.lock().await;
    let Some(talker) = s.talkers.get_mut(&token) else {
        return Err((StatusCode::FORBIDDEN, "talker not registered (Answer first)".into()));
    };
    talker.last_chunk_at = Instant::now();
    // Cap buffer to prevent runaway memory if HA bursts faster than the
    // mixer drains. Drop oldest samples on overflow.
    for s_val in samples {
        if talker.buffer.len() >= crate::media_hub::TALKER_BUFFER_SAMPLES {
            talker.buffer.pop_front();
        }
        talker.buffer.push_back(s_val);
    }
    Ok(StatusCode::NO_CONTENT)
}
