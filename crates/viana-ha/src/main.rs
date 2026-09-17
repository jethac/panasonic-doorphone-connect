//! `viana-ha` — VIANA-cloud-direct doorphone bridge daemon.
//!
//! On startup:
//!   1. Load `kiki.dat` from disk (mint a fresh one on first boot if missing).
//!   2. Decrypt → derive `signatureDeviceId`.
//!   3. POST to `mcn.s2.vianaaws.jp/mcn/api/getUrl` with that auth header to
//!      obtain our partition's persistent kick WSS URL.
//!   4. Open the WSS, hold it open, log every incoming kick frame as JSON to
//!      stdout (and parse it for diagnostic purposes).
//!
//! TLS: Panasonic's `*.s2.vianaaws.jp` leaf cert and the CA that issued it are
//! both X.509 **v1** (issued 2015-2021, expire 2026-2065). Modern rustls/webpki
//! refuses to even parse v1 certs. We therefore use OS-native TLS (Schannel on
//! Windows, OpenSSL on Linux, SecureTransport on macOS) which is more lenient,
//! and explicitly add the Panasonic CA as an extra trust anchor.
//!
//! Headless daemon: mint/load identity, hold the VIANA WSS, expose a local
//! HTTP API for the Home Assistant custom component.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncBufReadExt;
use tokio::sync::broadcast;
use tokio_tungstenite::Connector;
use tracing::{debug, error, info, warn};
use viana_protocol::{
    elb,
    kick,
    mint::DEFAULT_UNIQUE_ID,
};

mod config;
mod http;
mod identity;
mod media_hub;

/// Process-wide broadcast bus for structured daemon events. Set once at
/// startup; every `emit_event` and ring-detection println pushes here so
/// the HTTP `/events` SSE endpoint can fan them out to subscribers (the
/// HA integration's coordinator, the debug client, etc.).
static EVENT_BUS: OnceLock<broadcast::Sender<serde_json::Value>> = OnceLock::new();

fn event_bus() -> Option<&'static broadcast::Sender<serde_json::Value>> {
    EVENT_BUS.get()
}

/// Commands accepted on stdin (one JSON object per line). The daemon stays
/// alive between calls — the parent (Tauri UI) sends `start_monitor` /
/// `stop_monitor` to drive the media plane up and down without restarting
/// authentication, heartbeats, or the WSS connection. EOF on stdin is
/// treated as `quit`.
#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum DaemonCommand {
    StartMonitor {
        media_dir: String,
        #[serde(default)]
        door_no: Option<u32>,
        #[serde(default)]
        duration_secs: Option<u64>,
    },
    StopMonitor,
    Quit,
}

/// Structured events the daemon emits to stdout (newline-delimited JSON).
/// These are in addition to the existing `doorphone.ring` and ad-hoc tracing
/// output. The Tauri shell consumes these to drive UI state transitions
/// without scraping log strings.
#[derive(Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum DaemonEvent<'a> {
    /// First emitted once the WSS auth handshake completes.
    Ready,
    /// Emitted right before the daemon sends the connect kick to the base.
    MonitorStarting { media_dir: &'a str },
    /// Emitted after the monitor session ends (clean disconnect or error).
    MonitorEnded {
        media_dir: &'a str,
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

fn emit_event(event: DaemonEvent<'_>) {
    let value = serde_json::to_value(&event).unwrap_or(serde_json::Value::Null);
    println!("{value}");
    if let Some(bus) = event_bus() {
        let _ = bus.send(value);
    }
}

/// Same shape as `emit_event` but for raw JSON values (used for the
/// in-flight `doorphone.ring` and inbound-kick payloads we already build
/// as `serde_json::Value`).
fn emit_value(value: serde_json::Value) {
    println!("{value}");
    if let Some(bus) = event_bus() {
        let _ = bus.send(value);
    }
}

#[derive(Parser, Debug)]
#[command(name = "viana-ha", about = "VIANA-direct doorphone bridge daemon")]
struct Args {
    /// Path to the persistent runtime config file. Defaults to
    /// `/opt/viana-ha/config.toml`. Created with sensible defaults if missing
    /// — daemon then boots in unpaired mode (HTTP only, /pair available).
    #[arg(long, env = "VIANA_CONFIG", default_value = "/opt/viana-ha/config.toml")]
    config_path: PathBuf,

    // ----- back-compat overrides -----
    // The fields below let the existing systemd unit + ad-hoc CLI invocations
    // keep working while we transition to the config-file path. Any field
    // that's specified on the command line wins over what's in config.toml.
    /// Override `[identity].kiki_path` from config.
    #[arg(long, env = "VIANA_KIKI_PATH")]
    kiki_path: Option<PathBuf>,
    /// Override `[identity].ca_cert_path` from config.
    #[arg(long, env = "VIANA_CA_CERT")]
    ca_cert: Option<PathBuf>,
    /// Override the unique_id used for fresh identity minting.
    #[arg(long)]
    unique_id: Option<String>,
    /// Override `[base].viana_id` from config. Presence of this *or* a
    /// `[base]` table in config.toml puts the daemon in paired mode.
    #[arg(long, env = "VIANA_BASE_ID")]
    base_viana_id: Option<String>,
    /// Override `[heartbeat].interval_secs` from config.
    #[arg(long, env = "VIANA_HEARTBEAT_SECS")]
    heartbeat_secs: Option<u64>,

    // ----- one-shot CLI knobs (not in config) -----
    /// Send a monitor-connect kick immediately after auth. Convenient for
    /// capture jobs; the HA integration uses the HTTP API instead.
    #[arg(long)]
    monitor_on_connect: bool,
    /// Upper bound on duration for `--monitor-on-connect`. 0 = until stop.
    #[arg(long, default_value = "10")]
    monitor_secs: u64,
    /// Local IPv4 to put in the phone-side SDP. Auto-detected if omitted.
    #[arg(long, env = "VIANA_LOCAL_IP")]
    local_ip: Option<String>,
    /// Where `--monitor-on-connect` stores audio.bin / video.bin.
    #[arg(long, env = "VIANA_MEDIA_DIR")]
    media_dir: Option<PathBuf>,
    /// Which door's camera to monitor (CLI one-shot only).
    #[arg(long, default_value = "1")]
    door_no: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,viana_ha=debug,viana_protocol=debug".parse().unwrap()),
        )
        .compact()
        .init();

    let args = Args::parse();
    info!(config = %args.config_path.display(), "starting viana-ha daemon");

    // Load (or initialise) the on-disk config. CLI overrides applied below
    // are kept in-memory only — they don't write back to config.toml so
    // back-compat ExecStart= lines won't accidentally lock in a new shape.
    let mut cfg = config::Config::load(&args.config_path)
        .with_context(|| format!("loading {}", args.config_path.display()))?;
    let was_default = !args.config_path.exists();
    if was_default {
        // Persist the freshly-generated auth_token + defaults so the HA
        // integration on the same box can read it.
        cfg.save(&args.config_path)
            .with_context(|| format!("writing initial config to {}", args.config_path.display()))?;
        info!(path = %args.config_path.display(), "wrote initial config");
    }
    if let Some(p) = &args.kiki_path {
        cfg.identity.kiki_path = p.clone();
    }
    if let Some(p) = &args.ca_cert {
        cfg.identity.ca_cert_path = p.clone();
    }
    if let Some(u) = &args.unique_id {
        cfg.identity.unique_id = Some(u.clone());
    }
    if let Some(id) = &args.base_viana_id {
        // CLI override implies "treat as paired with this base id". Anything
        // else (LAN IP, model) stays as whatever's in the config file.
        cfg.base = Some(cfg.base.clone().unwrap_or_default()).map(|mut b| {
            b.viana_id = id.clone();
            b
        });
    }
    if let Some(hb) = args.heartbeat_secs {
        cfg.heartbeat.interval_secs = hb;
    }

    // Process-wide event bus. Capacity is intentionally large enough to
    // ride out a slow SSE subscriber for a few seconds without dropping.
    let (bus_tx, _bus_rx) = broadcast::channel::<serde_json::Value>(256);
    EVENT_BUS
        .set(bus_tx.clone())
        .map_err(|_| anyhow::anyhow!("event bus already initialised"))?;

    // Stdin reader: parse one JSON command per line. EOF doesn't quit (so
    // systemd's `StandardInput=null` is fine); the daemon also accepts
    // commands via the HTTP API now.
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel::<DaemonCommand>(16);
    let cmd_tx_for_stdin = cmd_tx.clone();
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<DaemonCommand>(trimmed) {
                        Ok(cmd) => {
                            if cmd_tx_for_stdin.send(cmd).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => warn!(line = trimmed, error = %e, "ignoring bad daemon command"),
                    }
                }
                Ok(None) | Err(_) => {
                    // EOF or read error: just stop reading. We deliberately
                    // do NOT send Quit here so the daemon survives being
                    // launched by systemd with `StandardInput=null` (default
                    // for service units). For interactive/desktop usage,
                    // send `{"cmd":"quit"}` explicitly or signal the process.
                    break;
                }
            }
        }
    });

    // Back-compat: --monitor-on-connect injects an immediate StartMonitor so
    // existing CLI invocations (one-shot scripts, capture jobs) keep working.
    if args.monitor_on_connect {
        let media_dir = args
            .media_dir
            .clone()
            .unwrap_or_else(|| {
                PathBuf::from(format!(
                    "monitor_{}",
                    chrono_compat_timestamp().replace(':', "-").replace('.', "-")
                ))
            })
            .to_string_lossy()
            .into_owned();
        let _ = cmd_tx
            .send(DaemonCommand::StartMonitor {
                media_dir,
                door_no: Some(args.door_no),
                duration_secs: Some(args.monitor_secs),
            })
            .await;
        if args.monitor_secs > 0 {
            // Schedule an automatic StopMonitor at the deadline. With the new
            // architecture the monitor session no longer hard-bounds itself
            // on a duration — that's what stop commands are for. Keep this
            // safety net for legacy CLI usage.
            let cmd_tx_deadline = cmd_tx.clone();
            let secs = args.monitor_secs;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(secs)).await;
                let _ = cmd_tx_deadline.send(DaemonCommand::StopMonitor).await;
            });
        }
    }

    // Wrap the live config in an Arc<Mutex<>> so the HTTP API and the
    // kick loop can both read/write it. The pair endpoint mutates `base`
    // and persists; the kick loop only reads at startup.
    let cfg_shared = Arc::new(tokio::sync::Mutex::new(cfg.clone()));

    // Daemon-wide media hub — broadcast channels for inbound base media,
    // talker state for outbound mic input. Shared between run_monitor
    // and the HTTP API. See media_hub.rs and INTERCOM-DESIGN.md §C/§D.
    let media_hub = media_hub::MediaHub::new();

    // Always bring up the HTTP API — even in unpaired mode the integration
    // needs `/state` and `/pair` to be reachable.
    let http_state = http::ApiState {
        config: cfg_shared.clone(),
        config_path: args.config_path.clone(),
        cmd_tx: cmd_tx.clone(),
        events: bus_tx.clone(),
        media_hub: media_hub.clone(),
    };
    let http_handle = tokio::spawn(async move {
        if let Err(e) = http::serve(http_state).await {
            error!("HTTP API server stopped: {e:#}");
        }
    });

    // Unpaired = no `[base]` in config and no --base-viana-id CLI override.
    // We don't try to talk to VIANA in this state; the operator drives a
    // pair through the HTTP API and restarts the daemon (the pair handler
    // writes config.toml, systemd handles the rest).
    if !cfg.is_paired() {
        warn!("daemon is unpaired — only the HTTP API is running. POST /pair to start pairing.");
        emit_event(DaemonEvent::Ready); // surface to subscribers; helps the integration know we're alive
        // Park the main thread on the HTTP server. The stdin reader keeps
        // draining commands but they'll mostly be no-ops without a session.
        let _ = http_handle.await;
        return Ok(());
    }

    let local_ip = match &args.local_ip {
        Some(ip) => ip.clone(),
        None => detect_local_ipv4().context("auto-detecting local IPv4")?,
    };

    let panasonic_ca_pem = std::fs::read(&cfg.identity.ca_cert_path)
        .with_context(|| format!("reading Panasonic CA from {}", cfg.identity.ca_cert_path.display()))?;
    let panasonic_ca = native_tls::Certificate::from_pem(&panasonic_ca_pem)
        .context("parsing Panasonic CA PEM")?;

    let unique_id = cfg.identity.unique_id.clone().unwrap_or_else(|| DEFAULT_UNIQUE_ID.to_string());
    let identity_loaded =
        identity::load_or_mint_with_disp_id(&cfg.identity.kiki_path, &unique_id)
            .await
            .context("identity bootstrap")?;
    let signature_device_id = identity_loaded.signature_device_id.clone();
    info!(
        sig_dev_id_prefix = &signature_device_id[..32],
        mac = %identity_loaded.synthetic_mac,
        "identity loaded"
    );

    let elb_client = build_panasonic_https_client(&panasonic_ca)?;
    let elb_resp = elb::get_url(&elb_client, &signature_device_id)
        .await
        .context("ELB getUrl")?;
    info!(
        kick_url = %elb_resp.kick_url,
        irca_host = ?elb_resp.irca_host,
        irca_port = ?elb_resp.irca_port,
        unlock_supported = elb_resp.unlock_supported,
        "ELB getUrl ok"
    );

    let base_cfg = cfg
        .base
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("paired mode but config.base is missing"))?;
    let base_viana_id = base_cfg.viana_id.clone();

    // Spawn the long-running SIP maintenance task. Mirrors what /pair
    // already does post-CGI; this is the same logic for the case where
    // the daemon was already paired and just restarted (systemd, deploy,
    // host reboot). Without it, the base sees us go SIP-quiet across
    // restarts — observable in any per-base telemetry.
    //
    // Best-effort: if the REGISTER cycle fails (e.g. our slot got
    // reassigned during a long outage), log loudly and continue with
    // WSS-only. The user's only recovery is then to re-pair via HA UI.
    if let Err(e) =
        spawn_startup_sip_maintenance(&identity_loaded, &cfg, base_cfg, &local_ip).await
    {
        warn!(
            err = %e,
            "SIP maintenance setup failed on startup — continuing in WSS-only mode. \
             Base will see us as SIP-dead until next /pair."
        );
        emit_value(serde_json::json!({
            "event": "sip.unhealthy",
            "reason": format!("{e:#}"),
        }));
    }

    let session = SessionConfig {
        kick_url: elb_resp.kick_url,
        signature_device_id,
        base_viana_id,
        heartbeat: Duration::from_secs(cfg.heartbeat.interval_secs),
        local_ip,
        default_door_no: args.door_no,
    };

    let kick_result = run_kick_loop(&session, &panasonic_ca, cmd_rx, media_hub, cmd_tx.clone()).await;
    http_handle.abort();
    let _ = http_handle.await;
    kick_result
}

/// Bring up the SIP REGISTER cycle on daemon startup (paired mode) and
/// spawn the long-running maintenance task. Skips MESSAGE bootstrap
/// entirely — the base remembers us via the persisted CGI 108 state +
/// our stable synthetic MAC, so REGISTER alone is enough to claim our
/// slot back.
async fn spawn_startup_sip_maintenance(
    identity_loaded: &identity::DaemonIdentity,
    cfg: &config::Config,
    base_cfg: &config::BaseConfig,
    local_ip: &str,
) -> anyhow::Result<()> {
    use std::net::Ipv4Addr;
    use viana_protocol::sip::{self, PairContext};

    let _ = cfg; // reserved for future use (e.g. heartbeat-interval override)

    let base_lan_ip: Ipv4Addr = base_cfg
        .lan_ip
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("base.lan_ip missing in config.toml"))?
        .parse()
        .context("base.lan_ip is not a valid IPv4")?;
    let local_v4: Ipv4Addr = local_ip
        .parse()
        .context("local_ip from auto-detect is not a valid IPv4")?;
    let terminal_hint = base_cfg.assigned_terminal.unwrap_or(21);

    let sock = std::sync::Arc::new(
        tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .context("bind SIP REGISTER socket")?,
    );
    let local_port = sock.local_addr()?.port();
    info!(
        local_port,
        base_lan_ip = %base_lan_ip,
        terminal_hint,
        mac = %identity_loaded.synthetic_mac,
        "startup SIP REGISTER bound; running cycle"
    );

    // PairContext::new generates a fresh Call-ID + from-tag — exactly
    // what we want; the maintenance loop uses these for the lifetime
    // of this socket's registration.
    let ctx = PairContext::new(
        base_lan_ip,
        local_v4,
        local_port,
        identity_loaded.synthetic_mac.clone(),
        // phone_name only appears in MESSAGE which we're skipping; pass
        // a sentinel so log lines show something reasonable.
        "viana-ha-startup".to_string(),
    );

    let reg_result = sip::register(&*sock, &ctx, terminal_hint)
        .await
        .context("startup REGISTER cycle")?;
    info!(
        terminal = reg_result.terminal,
        "startup REGISTER complete; spawning maintenance task"
    );

    tokio::spawn(async move {
        if let Err(e) = sip::maintain_registration(sock, ctx, reg_result).await {
            warn!(err = %e, "startup-spawned SIP maintenance task exited");
        }
    });
    Ok(())
}

#[derive(Clone)]
struct SessionConfig {
    kick_url: String,
    signature_device_id: String,
    base_viana_id: String,
    heartbeat: Duration,
    local_ip: String,
    default_door_no: u32,
}

#[derive(Clone)]
struct MonitorConfig {
    local_ip: String,
    media_dir: PathBuf,
    door_no: u32,
    duration: Duration,
    /// Set to `true` by `stop_monitor` to wind the RTP loops down promptly.
    stop: tokio::sync::watch::Receiver<bool>,
}

/// Auto-detect the local IPv4 by opening a UDP socket to 8.8.8.8:0 and asking
/// the OS what source address it picked. Doesn't actually send any packets;
/// just exercises the routing table.
fn detect_local_ipv4() -> Result<String> {
    use std::net::{SocketAddr, UdpSocket};
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect("8.8.8.8:80")?;
    let local: SocketAddr = sock.local_addr()?;
    Ok(local.ip().to_string())
}

/// reqwest client backed by OS-native TLS, with the Panasonic v1 CA added as
/// an extra trust anchor so it'll accept `mcn.s2.vianaaws.jp`.
fn build_panasonic_https_client(ca: &native_tls::Certificate) -> Result<reqwest::Client> {
    let connector = native_tls::TlsConnector::builder()
        .add_root_certificate(ca.clone())
        .build()
        .context("building native-tls connector")?;
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .use_preconfigured_tls(connector)
        .build()?)
}

/// JSON event we emit to stdout for every parsed kick frame. Will become the
/// payload of the daemon's Unix-socket protocol when the HA shim arrives.
#[derive(Debug, Serialize)]
struct KickEvent<'a> {
    ts: String,
    direction: &'a str,
    raw_xml: &'a str,
    parsed: ParsedKick<'a>,
}

#[derive(Debug, Serialize)]
struct ParsedKick<'a> {
    root: &'a str,
    command: &'a str,
    kick_id_hex: String,
    kind: i32,
    devices: Vec<&'a str>,
    json: Option<&'a str>,
    sdp: Option<&'a str>,
    other_param_keys: Vec<String>,
}

/// Connect, hold, and log. Reconnects with exponential backoff (capped) on
/// disconnect. Run forever; only Ctrl-C, Quit command, or stdin EOF exits.
async fn run_kick_loop(
    session: &SessionConfig,
    panasonic_ca: &native_tls::Certificate,
    cmd_rx: tokio::sync::mpsc::Receiver<DaemonCommand>,
    media_hub: Arc<media_hub::MediaHub>,
    cmd_tx_self: tokio::sync::mpsc::Sender<DaemonCommand>,
) -> Result<()> {
    let connector = native_tls::TlsConnector::builder()
        .add_root_certificate(panasonic_ca.clone())
        .build()
        .context("WSS native-tls connector")?;

    // The command receiver lives across reconnects. connect_and_pump borrows
    // it; if we lose the WSS we keep any commands queued on the channel.
    let cmd_rx = std::sync::Arc::new(tokio::sync::Mutex::new(cmd_rx));
    let mut backoff = Duration::from_secs(2);
    let max_backoff = Duration::from_secs(60);
    loop {
        info!(kick_url = %session.kick_url, "connecting kick WSS");
        match connect_and_pump(
            session,
            connector.clone(),
            cmd_rx.clone(),
            media_hub.clone(),
            cmd_tx_self.clone(),
        )
        .await
        {
            Ok(LoopExit::Quit) => {
                info!("quit command received; exiting");
                return Ok(());
            }
            Ok(LoopExit::Reconnect) => {
                warn!("kick WSS closed; reconnecting");
                backoff = Duration::from_secs(2);
            }
            Err(e) => {
                error!("kick WSS error: {e:#}; reconnecting in {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }

        if tokio::signal::ctrl_c().now_or_never_ok() {
            info!("ctrl-c; exiting");
            return Ok(());
        }
    }
}

enum LoopExit {
    /// WSS dropped — outer loop should reconnect.
    Reconnect,
    /// Daemon was asked to quit (stdin EOF or explicit Quit command).
    Quit,
}

async fn connect_and_pump(
    session: &SessionConfig,
    connector: native_tls::TlsConnector,
    cmd_rx: std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<DaemonCommand>>>,
    media_hub: Arc<media_hub::MediaHub>,
    cmd_tx_self: tokio::sync::mpsc::Sender<DaemonCommand>,
) -> Result<LoopExit> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message;

    let mut req = session.kick_url.as_str().into_client_request()?;
    req.headers_mut().insert(
        "Authorization",
        format!("Basic {}", session.signature_device_id).parse()?,
    );

    let (ws, response) = tokio_tungstenite::connect_async_tls_with_config(
        req,
        None,
        false,
        Some(Connector::NativeTls(connector)),
    )
    .await?;
    info!(
        status = %response.status(),
        "WSS handshake complete"
    );

    let (mut sink, mut stream) = ws.split();

    let kick_id_counter = Arc::new(AtomicU32::new(rand_u32_from_clock()));
    let seq_no_counter = Arc::new(AtomicU32::new(0));
    let (sender_tx, mut sender_rx) = tokio::sync::mpsc::channel::<String>(64);

    let send_loop = tokio::spawn(async move {
        while let Some(xml) = sender_rx.recv().await {
            debug!(bytes = xml.len(), "WSS send");
            if let Err(e) = sink.send(Message::Text(xml.into())).await {
                error!("WSS send: {e}");
                break;
            }
        }
    });

    // Step 1: inner-auth XML. Without this the server drops us
    // after ~25 s with resultCode=103.
    {
        let xml = format!(
            "<request>\n<command>auth</command>\n<authentication>Basic {}</authentication>\n</request>",
            session.signature_device_id
        );
        sender_tx
            .send(xml)
            .await
            .map_err(|e| anyhow::anyhow!("send auth: {e}"))?;
        info!("sent inner-auth request");
    }

    // Step 2: kickTerminal getState — wakes the base up so subsequent kicks
    // route correctly.
    {
        let xml = build_get_state_kick(
            kick_id_counter.fetch_add(1, Ordering::Relaxed),
            &session.base_viana_id,
            seq_no_counter.fetch_add(1, Ordering::Relaxed),
        );
        sender_tx
            .send(xml)
            .await
            .map_err(|e| anyhow::anyhow!("send initial kick: {e}"))?;
        info!("sent initial getState");
    }

    emit_event(DaemonEvent::Ready);

    // Heartbeat task.
    let hb_tx = sender_tx.clone();
    let hb_base = session.base_viana_id.clone();
    let hb_kick = Arc::clone(&kick_id_counter);
    let hb_seq = Arc::clone(&seq_no_counter);
    let hb_interval = session.heartbeat;
    let hb_loop = tokio::spawn(async move {
        let mut tick = tokio::time::interval(hb_interval);
        tick.tick().await;
        loop {
            tick.tick().await;
            let xml = build_get_state_kick(
                hb_kick.fetch_add(1, Ordering::Relaxed),
                &hb_base,
                hb_seq.fetch_add(1, Ordering::Relaxed),
            );
            if hb_tx.send(xml).await.is_err() {
                debug!("heartbeat channel closed");
                return;
            }
        }
    });

    // Active monitor session — at most one at a time. The stop_tx half is
    // held here so StopMonitor can flip its watch; the join handle is kept
    // so we can await graceful disconnect before reporting MonitorEnded.
    let mut active: Option<ActiveMonitor> = None;

    // Pump WSS messages and stdin commands in lockstep. We hold the cmd_rx
    // mutex for the duration of this connection so messages aren't lost; on
    // exit the lock drops and the next connect_and_pump grabs it again.
    let mut cmd_rx_guard = cmd_rx.lock().await;
    let exit = loop {
        tokio::select! {
            ws_msg = stream.next() => {
                let Some(msg) = ws_msg else {
                    break LoopExit::Reconnect;
                };
                match msg {
                    Ok(Message::Text(text)) => {
                        handle_kick_text(&text, "in", &sender_tx, &cmd_tx_self, active.is_some()).await;
                    }
                    Ok(Message::Binary(bin)) => match std::str::from_utf8(&bin) {
                        Ok(text) => handle_kick_text(text, "in", &sender_tx, &cmd_tx_self, active.is_some()).await,
                        Err(_) => warn!(
                            bytes = bin.len(),
                            "non-UTF8 binary frame; raw hex={}",
                            hex::encode(&bin[..bin.len().min(64)])
                        ),
                    },
                    Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => {}
                    Ok(Message::Close(frame)) => {
                        info!(?frame, "server closed");
                        break LoopExit::Reconnect;
                    }
                    Err(e) => {
                        warn!("WSS recv error: {e}");
                        break LoopExit::Reconnect;
                    }
                }
            }
            cmd = cmd_rx_guard.recv() => {
                let Some(cmd) = cmd else {
                    // cmd channel closed — the stdin watcher exited. Treat
                    // as Quit.
                    break LoopExit::Quit;
                };
                match cmd {
                    DaemonCommand::StartMonitor { media_dir, door_no, duration_secs } => {
                        if active.is_some() {
                            warn!("ignoring StartMonitor — a session is already active");
                            continue;
                        }
                        let media_dir = PathBuf::from(media_dir);
                        if let Err(e) = tokio::fs::create_dir_all(&media_dir).await {
                            warn!(?e, ?media_dir, "create_dir_all failed");
                            continue;
                        }
                        let door = door_no.unwrap_or(session.default_door_no);
                        let secs = duration_secs.unwrap_or(0);
                        // Cap at 12h to prevent a wedged client from pinning
                        // the call open forever.
                        let duration = if secs == 0 {
                            Duration::from_secs(12 * 60 * 60)
                        } else {
                            Duration::from_secs(secs)
                        };
                        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
                        let cfg = MonitorConfig {
                            local_ip: session.local_ip.clone(),
                            media_dir: media_dir.clone(),
                            door_no: door,
                            duration,
                            stop: stop_rx,
                        };
                        let tx = sender_tx.clone();
                        let kick_ctr = Arc::clone(&kick_id_counter);
                        let seq_ctr = Arc::clone(&seq_no_counter);
                        let base = session.base_viana_id.clone();
                        let media_dir_str = media_dir.to_string_lossy().into_owned();
                        emit_event(DaemonEvent::MonitorStarting { media_dir: &media_dir_str });
                        emit_value(serde_json::json!({
                            "event": "monitor.started",
                            "ts": chrono_compat_timestamp(),
                            "phase": "preview",
                        }));
                        media_hub.set_phase(media_hub::MonitorPhase::Preview);
                        let media_dir_for_task = media_dir_str.clone();
                        let hub_for_task = media_hub.clone();
                        let handle = tokio::spawn(async move {
                            let result = run_monitor(tx, kick_ctr, seq_ctr, base, cfg, hub_for_task.clone()).await;
                            let (ok, err) = match &result {
                                Ok(()) => (true, None),
                                Err(e) => (false, Some(format!("{e:#}"))),
                            };
                            emit_event(DaemonEvent::MonitorEnded {
                                media_dir: &media_dir_for_task,
                                ok,
                                error: err.clone(),
                            });
                            emit_value(serde_json::json!({
                                "event": "monitor.ended",
                                "ts": chrono_compat_timestamp(),
                                "ok": ok,
                                "error": err,
                            }));
                            hub_for_task.set_phase(media_hub::MonitorPhase::Idle);
                            // Drop any lingering talkers + outbound ctx — the
                            // session ended, all bets are off.
                            {
                                let mut st = hub_for_task.state.lock().await;
                                st.talkers.clear();
                                st.outbound = None;
                            }
                            result
                        });
                        active = Some(ActiveMonitor {
                            stop_tx,
                            handle,
                            media_dir: media_dir_str,
                        });
                    }
                    DaemonCommand::StopMonitor => {
                        if let Some(am) = active.take() {
                            let _ = am.stop_tx.send(true);
                            // Don't await — let the monitor flush its
                            // disconnect kick and exit on its own. The
                            // MonitorEnded event will fire when it does.
                            tokio::spawn(async move {
                                let _ = am.handle.await;
                            });
                        } else {
                            debug!("StopMonitor with no active session — noop");
                        }
                    }
                    DaemonCommand::Quit => {
                        if let Some(am) = active.take() {
                            let _ = am.stop_tx.send(true);
                            let _ = am.handle.await;
                        }
                        break LoopExit::Quit;
                    }
                }
            }
        }
    };

    drop(sender_tx);
    let _ = send_loop.await;
    hb_loop.abort();
    let _ = hb_loop.await;
    Ok(exit)
}

struct ActiveMonitor {
    stop_tx: tokio::sync::watch::Sender<bool>,
    handle: tokio::task::JoinHandle<Result<()>>,
    #[allow(dead_code)]
    media_dir: String,
}

// `pump_recv` was inlined into `connect_and_pump`'s select! loop so we can
// multiplex inbound WSS messages with stdin commands.

fn build_get_state_kick(kick_id: u32, base_viana_id: &str, seq_no: u32) -> String {
    let json = serde_json::json!({
        "request": "getState",
        "seqNo": seq_no,
        "inHouse": true,
        "version": " 4.00",
        "capability": 255,
    })
    .to_string();
    let env = kick::KickEnvelope {
        root: kick::Root::Request,
        command: kick::Command::KickTerminal,
        kick_id,
        kind: 1,
        devices: vec![base_viana_id.to_string()],
        params: vec![kick::Param::Json(json)],
    };
    kick::to_xml(&env).unwrap_or_default()
}

fn build_kick_status_ack(kick_id: u32, base_viana_id: &str) -> String {
    let env = kick::KickEnvelope {
        root: kick::Root::Request,
        command: kick::Command::Kick,
        kick_id,
        kind: 1,
        devices: vec![base_viana_id.to_string()],
        params: vec![kick::Param::Status("0".into())],
    };
    kick::to_xml(&env).unwrap_or_default()
}

fn rand_u32_from_clock() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    nanos ^ 0xDEADBEEF
}

/// Pending monitor sessions keyed by seqNo so the receive task can wake them up
/// when the base responds with the SDP we need. Also routes inbound `kick`
/// notices for the same seqNo so we can detect monitor-end / disconnect.
static MONITOR_PENDING: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<i64, tokio::sync::mpsc::Sender<KickEnvelopeForward>>>,
> = std::sync::OnceLock::new();

#[derive(Debug)]
struct KickEnvelopeForward {
    json: String,
    sdp: Option<String>,
}

fn pending_monitors()
    -> &'static std::sync::Mutex<std::collections::HashMap<i64, tokio::sync::mpsc::Sender<KickEnvelopeForward>>>
{
    MONITOR_PENDING.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn build_monitor_connect_kick(
    kick_id: u32,
    base_viana_id: &str,
    seq_no: u32,
    door_no: u32,
    sdp: &str,
) -> String {
    let json = serde_json::json!({
        "request": "connect",
        "attr": {
            "deviceInfo": { "deviceNo": door_no, "deviceName": "door" },
            "connectKind": 2,
            "isSlowSpeedVideoReception": false,
        },
        "seqNo": seq_no,
        "inHouse": true,
    })
    .to_string();
    let env = kick::KickEnvelope {
        root: kick::Root::Request,
        command: kick::Command::KickTerminal,
        kick_id,
        kind: 1,
        devices: vec![base_viana_id.to_string()],
        params: vec![kick::Param::Json(json), kick::Param::Sdp(sdp.to_string())],
    };
    kick::to_xml(&env).unwrap_or_default()
}

fn build_disconnect_kick(kick_id: u32, base_viana_id: &str, seq_no: u32) -> String {
    let json = serde_json::json!({
        "request": "disconnect",
        "attr": {"disconnectKind": 0, "reason": 0},
        "seqNo": seq_no,
        "inHouse": true,
    })
    .to_string();
    let env = kick::KickEnvelope {
        root: kick::Root::Request,
        command: kick::Command::KickTerminal,
        kick_id,
        kind: 1,
        devices: vec![base_viana_id.to_string()],
        params: vec![kick::Param::Json(json)],
    };
    kick::to_xml(&env).unwrap_or_default()
}

/// Drive one monitor session end-to-end: bind UDP sockets, send the kick,
/// wait for the base's SDP response, receive media, save artifacts, send
/// disconnect.
async fn run_monitor(
    sender_tx: tokio::sync::mpsc::Sender<String>,
    kick_id_counter: Arc<AtomicU32>,
    seq_no_counter: Arc<AtomicU32>,
    base_viana_id: String,
    cfg: MonitorConfig,
    media_hub: Arc<media_hub::MediaHub>,
) -> Result<()> {
    info!(
        local_ip = %cfg.local_ip,
        media_dir = %cfg.media_dir.display(),
        door = cfg.door_no,
        duration_s = cfg.duration.as_secs(),
        "monitor session starting"
    );

    // Bind UDP sockets (kernel auto-assigns ports). Bind to 0.0.0.0 so the
    // base can send to whatever IP we advertised in SDP regardless of
    // multi-NIC routing oddities.
    let audio_sock = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await.context("audio bind")?);
    let video_sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.context("video bind")?;
    let audio_port = audio_sock.local_addr()?.port();
    let video_port = video_sock.local_addr()?.port();
    info!(audio_port, video_port, "RTP sockets bound");

    let phone_sdp = viana_protocol::sdp::build_phone_offer(&cfg.local_ip, audio_port, video_port);

    let seq_no = seq_no_counter.fetch_add(1, Ordering::Relaxed) as i64;
    let kick_id = kick_id_counter.fetch_add(1, Ordering::Relaxed);

    let (resp_tx, mut resp_rx) = tokio::sync::mpsc::channel::<KickEnvelopeForward>(16);
    pending_monitors()
        .lock()
        .unwrap()
        .insert(seq_no, resp_tx);

    let xml = build_monitor_connect_kick(kick_id, &base_viana_id, seq_no as u32, cfg.door_no, &phone_sdp);
    sender_tx.send(xml).await.map_err(|e| anyhow::anyhow!("send connect: {e}"))?;
    info!(seq_no, kick_id_hex = format!("{:08X}", kick_id), "sent connect (monitor) kick");

    // Wait for the base's response — typically arrives within ~100ms.
    let base_response = tokio::time::timeout(Duration::from_secs(5), resp_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("monitor response timeout"))?
        .ok_or_else(|| anyhow::anyhow!("monitor response channel closed"))?;

    let resp_json: serde_json::Value = serde_json::from_str(&base_response.json)
        .context("parse base connect response JSON")?;
    let result = resp_json
        .get("result")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let reason = resp_json.get("reason").and_then(|v| v.as_i64()).unwrap_or(-1);
    info!(result, reason, "base connect response");

    if !result {
        error!("base rejected monitor connect — JSON: {}", base_response.json);
        // best-effort cleanup: remove our pending entry.
        pending_monitors().lock().unwrap().remove(&seq_no);
        return Err(anyhow::anyhow!("base rejected connect, reason={reason}"));
    }

    let base_sdp_text = base_response
        .sdp
        .ok_or_else(|| anyhow::anyhow!("base did not include SDP in connect response"))?;
    let base_sdp = viana_protocol::sdp::parse(&base_sdp_text)
        .context("parse base SDP")?;
    let base_ip = base_sdp
        .connection_ip
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("base SDP missing c=IP"))?;
    let base_audio = base_sdp.audio().ok_or_else(|| anyhow::anyhow!("no audio media"))?;
    let base_video = base_sdp.video().ok_or_else(|| anyhow::anyhow!("no video media"))?;
    let audio_xor = base_audio
        .xor_data
        .ok_or_else(|| anyhow::anyhow!("no audio xorData"))?;
    let video_xor = base_video
        .xor_data
        .ok_or_else(|| anyhow::anyhow!("no video xorData"))?;
    let audio_auth_a = base_audio
        .xor_auth_a
        .ok_or_else(|| anyhow::anyhow!("no audio xorAuthA"))?;
    let audio_auth_b = base_audio
        .xor_auth_b
        .ok_or_else(|| anyhow::anyhow!("no audio xorAuthB"))?;
    let video_auth_a = base_video
        .xor_auth_a
        .ok_or_else(|| anyhow::anyhow!("no video xorAuthA"))?;
    let video_auth_b = base_video
        .xor_auth_b
        .ok_or_else(|| anyhow::anyhow!("no video xorAuthB"))?;

    info!(
        base_ip = %base_ip,
        base_audio_port = base_audio.port,
        base_video_port = base_video.port,
        audio_xor = %hex::encode(audio_xor),
        video_xor = %hex::encode(video_xor),
        "got SDP keys — starting media receive"
    );

    let audio_path = cfg.media_dir.join("audio.bin");
    let video_path = cfg.media_dir.join("video.bin");
    let audio_file = tokio::fs::File::create(&audio_path).await?;
    let video_file = tokio::fs::File::create(&video_path).await?;

    let base_ip_addr: std::net::IpAddr = base_ip.parse().context("parse base ip")?;
    let base_audio_addr = std::net::SocketAddr::new(base_ip_addr, base_audio.port);

    // Register outbound audio context BEFORE spawning the mixer so
    // POST /control/answer requests that race in immediately can find
    // the socket. The mixer task pulls this Arc each tick.
    {
        let mut st = media_hub.state.lock().await;
        st.outbound = Some(Arc::new(media_hub::OutboundAudio {
            sock: audio_sock.clone(),
            base_audio_addr,
            payload_type: 8,
            // Match the inbound-keepalive SSRC; base appears to ignore
            // SSRC mismatches but keeping it stable is friendly.
            ssrc: 0x8691a780,
            xor_data: audio_xor,
        }));
    }

    let mixer_hub = media_hub.clone();
    let mixer_stop = cfg.stop.clone();
    let mixer_handle = tokio::spawn(async move {
        run_outbound_mixer(mixer_hub, mixer_stop).await;
    });

    let recv_audio = tokio::spawn(receive_rtp_loop(
        "audio",
        audio_sock.clone(),
        audio_xor,
        audio_auth_a,
        audio_auth_b,
        audio_file,
        cfg.duration,
        base_ip_addr,
        base_audio.port,
        8, // PCMA
        cfg.stop.clone(),
        Some(media_hub.audio_in_tx.clone()),
        None,
    ));
    let recv_video = tokio::spawn(receive_rtp_loop(
        "video",
        Arc::new(video_sock),
        video_xor,
        video_auth_a,
        video_auth_b,
        video_file,
        cfg.duration,
        base_ip_addr,
        base_video.port,
        97, // dynamic H.264
        cfg.stop.clone(),
        None,
        Some(media_hub.video_in_tx.clone()),
    ));

    let (a, v) = tokio::join!(recv_audio, recv_video);
    // Mixer task observes cfg.stop too; just wait for it to wind down.
    let _ = mixer_handle.await;
    let audio_count = a.unwrap_or(Ok(0)).unwrap_or(0);
    let video_count = v.unwrap_or(Ok(0)).unwrap_or(0);
    info!(
        audio_packets = audio_count,
        video_packets = video_count,
        audio_path = %audio_path.display(),
        video_path = %video_path.display(),
        "monitor session media saved"
    );

    // Send disconnect.
    let dc_seq = seq_no_counter.fetch_add(1, Ordering::Relaxed);
    let dc_kid = kick_id_counter.fetch_add(1, Ordering::Relaxed);
    let dc_xml = build_disconnect_kick(dc_kid, &base_viana_id, dc_seq);
    let _ = sender_tx.send(dc_xml).await;
    info!("sent disconnect");

    pending_monitors().lock().unwrap().remove(&seq_no);
    Ok(())
}

/// Bind a UDP socket and read RTP packets for `duration`. Each packet has the
/// XOR transform applied to bytes [12..] using `xor_data`. Output is the
/// concatenation of (4-byte BE length) || (full decrypted UDP payload) so
/// downstream tools can re-frame.
///
/// Critically: the base will NOT start streaming until we send it a "hole
/// punch" RTP keepalive on the same socket, even though SDP advertises
/// `a=sendonly`. The legitimate Galaxy app does this every ~500ms and the
/// base responds with the actual media:
/// every monitor flow opens with one 12-byte phone→base RTP-header-only
/// packet, then thousands of base→phone media packets follow.
async fn receive_rtp_loop(
    label: &'static str,
    sock: Arc<tokio::net::UdpSocket>,
    xor_data: [u8; 8],
    auth_a: [u8; 8],
    auth_b: [u8; 8],
    mut out: tokio::fs::File,
    duration: Duration,
    base_ip: std::net::IpAddr,
    base_port: u16,
    payload_type: u8,
    mut stop: tokio::sync::watch::Receiver<bool>,
    audio_pcm_tx: Option<broadcast::Sender<Arc<Vec<i16>>>>,
    video_h264_tx: Option<broadcast::Sender<Arc<Vec<u8>>>>,
) -> Result<u64> {
    // Per-loop H264 RTP depacketizer. Stays in scope across packets so
    // FU-A fragments accumulate correctly. Audio path doesn't need it.
    let mut h264_depack = viana_media::h264::H264Depacketizer::new();
    use tokio::io::AsyncWriteExt;
    let base_addr = std::net::SocketAddr::new(base_ip, base_port);

    let keepalive = build_rtp_keepalive(payload_type);

    if let Err(e) = sock.send_to(&keepalive, base_addr).await {
        warn!(label, ?e, "initial keepalive send failed");
    }

    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + duration;
    let mut media_count: u64 = 0;
    let mut challenge_count: u64 = 0;
    let mut keepalive_tick = tokio::time::interval(Duration::from_millis(500));
    keepalive_tick.tick().await;

    if *stop.borrow() {
        return Ok(0);
    }

    loop {
        let remaining = match deadline.checked_duration_since(tokio::time::Instant::now()) {
            Some(d) => d,
            None => break,
        };
        tokio::select! {
            _ = keepalive_tick.tick() => {
                let _ = sock.send_to(&keepalive, base_addr).await;
            }
            _ = stop.changed() => {
                if *stop.borrow() {
                    info!(label, "stop signal received");
                    break;
                }
            }
            recv = tokio::time::timeout(remaining, sock.recv_from(&mut buf)) => {
                let (n, src) = match recv {
                    Ok(Ok((n, src))) => (n, src),
                    Ok(Err(e)) => { warn!(?e, label, "recv_from error"); break; }
                    Err(_) => break,
                };
                let wire = &buf[..n];

                // Challenge packets identified BEFORE XOR-decrypt because the
                // X bit lives in byte 0 (offset < 12, untouched by the XOR).
                if viana_media::challenge::is_challenge(wire) {
                    let response = viana_media::challenge::build_response(wire, auth_a, auth_b);
                    if let Err(e) = sock.send_to(&response, base_addr).await {
                        warn!(label, ?e, "challenge response send failed");
                    }
                    challenge_count += 1;
                    if challenge_count == 1 {
                        info!(label, %src, "responded to first challenge");
                    }
                    continue;
                }

                // Otherwise it's a media packet — XOR-decrypt, fan out
                // to broadcast subscribers, and save to disk.
                let mut pkt = wire.to_vec();
                viana_media::xor::unwrap_in_place(&mut pkt, xor_data, 12);
                let len = (pkt.len() as u32).to_be_bytes();
                out.write_all(&len).await?;
                out.write_all(&pkt).await?;

                // Strip RTP header (12 bytes minimum) before fanning out.
                if let Some(payload_off) = viana_media::rtp::payload_offset(&pkt) {
                    let payload = &pkt[payload_off..];
                    if let Some(tx) = &audio_pcm_tx {
                        // PCMA decode → PCM samples. One a-law byte per
                        // sample; payload should be ~160 bytes per 20ms.
                        let pcm = viana_media::pcma::decode(payload);
                        let _ = tx.send(Arc::new(pcm));
                    }
                    if let Some(tx) = &video_h264_tx {
                        // RFC 6184 depacketize: payload may be a
                        // complete NALU, a STAP-A aggregation, or one
                        // FU-A fragment. Output is zero or more
                        // Annex-B-prefixed NAL units that ffmpeg can
                        // decode directly.
                        for nalu in h264_depack.push(payload) {
                            let _ = tx.send(Arc::new(nalu));
                        }
                    }
                }

                media_count += 1;
                if media_count == 1 {
                    info!(label, %src, n, "first MEDIA packet");
                }
            }
        }
    }
    out.flush().await?;
    info!(label, challenge_count, media_count, "rtp loop done");
    Ok(media_count)
}

/// 20 ms outbound RTP mixer. Runs while monitor session is alive.
/// Each tick: pull SAMPLES_PER_FRAME samples from each active talker's
/// buffer (silence-pad if starved), sum with 1/sqrt(N) attenuation,
/// soft-clip, encode to PCMA, frame as RTP, XOR-encrypt, send to base.
///
/// Per INTERCOM-DESIGN.md §D. Idle talker reaping is also done here so
/// we don't need a separate task. Stops when `stop` flips true OR when
/// outbound context is gone (monitor ended).
async fn run_outbound_mixer(
    media_hub: Arc<media_hub::MediaHub>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    use std::time::Instant;
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sender = viana_media::rtp::RtpSender::new(8, 0x8691a780);
    let idle_timeout = Duration::from_millis(media_hub::TALKER_IDLE_TIMEOUT_MS);

    info!("outbound mixer started");
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => {
                if *stop.borrow() {
                    break;
                }
            }
        }

        let outbound: Option<Arc<media_hub::OutboundAudio>>;
        let mixed: Option<Vec<i16>>;

        {
            let mut st = media_hub.state.lock().await;
            outbound = st.outbound.clone();
            if outbound.is_none() {
                // No outbound socket yet (or session ended) — keep
                // ticking but emit nothing.
                continue;
            }

            // Reap idle talkers first so we don't mix from corpses.
            let now = Instant::now();
            let stale: Vec<uuid::Uuid> = st
                .talkers
                .iter()
                .filter_map(|(id, t)| {
                    if now.duration_since(t.last_chunk_at) > idle_timeout {
                        Some(*id)
                    } else {
                        None
                    }
                })
                .collect();
            for id in stale {
                if let Some(t) = st.talkers.remove(&id) {
                    info!(source = %t.source, "talker idle-released");
                    let _ = event_bus().map(|b| {
                        b.send(serde_json::json!({
                            "event": "talker.left",
                            "source": t.source,
                            "reason": "idle",
                            "talker_count": st.talkers.len(),
                        }))
                    });
                }
            }

            if st.talkers.is_empty() {
                // Nothing to mix this tick. Update phase to Preview if
                // we just transitioned out of Talking.
                if media_hub.phase() == media_hub::MonitorPhase::Talking {
                    media_hub.set_phase(media_hub::MonitorPhase::Preview);
                }
                mixed = None;
            } else {
                if media_hub.phase() == media_hub::MonitorPhase::Preview {
                    media_hub.set_phase(media_hub::MonitorPhase::Talking);
                }
                let n = st.talkers.len() as f32;
                // 1/sqrt(N) keeps perceived loudness roughly constant
                // as talkers join/leave.
                let atten = 1.0 / n.sqrt();
                let mut sum = vec![0i32; media_hub::SAMPLES_PER_FRAME];
                for talker in st.talkers.values_mut() {
                    for slot in sum.iter_mut() {
                        let s = talker.buffer.pop_front().unwrap_or(0);
                        *slot += s as i32;
                    }
                }
                let frame: Vec<i16> = sum
                    .into_iter()
                    .map(|v| {
                        let scaled = (v as f32 * atten).round() as i32;
                        scaled.clamp(-32768, 32767) as i16
                    })
                    .collect();
                mixed = Some(frame);
            }
        }

        let Some(out_ctx) = outbound else { continue };
        let Some(samples) = mixed else { continue };

        let pcma = viana_media::pcma::encode(&samples);
        let mut packet = sender.build(&pcma, media_hub::SAMPLES_PER_FRAME as u32);
        viana_media::xor::unwrap_in_place(&mut packet, out_ctx.xor_data, 12);
        if let Err(e) = out_ctx.sock.send_to(&packet, out_ctx.base_audio_addr).await {
            warn!("outbound mixer send failed: {e}");
        }
    }
    info!("outbound mixer stopped");
}

/// 12-byte RTP-header-only keepalive that the legitimate Galaxy sends to
/// "punch" the path on the base's media port. Matches bytes from
/// Observed keepalives look like: `41 PT 00 00 00 00
/// 00 00 86 91 a7 80`. The fixed SSRC `8691a780` is what the legit app uses;
/// the base appears to ignore SSRC mismatches.
fn build_rtp_keepalive(payload_type: u8) -> [u8; 12] {
    [
        0x41, payload_type,
        0x00, 0x00,             // seq = 0
        0x00, 0x00, 0x00, 0x00, // timestamp = 0
        0x86, 0x91, 0xa7, 0x80, // SSRC
    ]
}

#[derive(Debug)]
struct RingState {
    active: bool,
    device_name: Option<String>,
    device_no: Option<i64>,
    ring_counter: Option<i64>,
    smartp_no: Option<i64>,
}

/// Pull doorbell-ring info out of a `notifyState` JSON payload. Returns None
/// if the payload isn't a notifyState. When it IS a notifyState but no active
/// ring exists, returns `Some(RingState { active: false, .. })` so the caller
/// can emit a "ring stopped" event.
fn detect_ring(json: &str) -> Option<RingState> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    if v.get("request")?.as_str()? != "notifyState" {
        return None;
    }
    let arr = v.get("attr")?.get("callStateArray")?.as_array()?;
    let active_call = arr.iter().find_map(|cs| {
        let main = cs.get("mainCall")?;
        let is_ringing = main.get("isRingSetting")?.as_bool().unwrap_or(false);
        if !is_ringing {
            return None;
        }
        Some((cs, main))
    });
    if let Some((cs, main)) = active_call {
        Some(RingState {
            active: true,
            device_name: main
                .get("deviceName")
                .and_then(|x| x.as_str())
                .map(str::to_owned),
            device_no: main.get("deviceNo").and_then(|x| x.as_i64()),
            ring_counter: main.get("ringCounter").and_then(|x| x.as_i64()),
            smartp_no: cs.get("smartPNo").and_then(|x| x.as_i64()),
        })
    } else {
        Some(RingState {
            active: false,
            device_name: None,
            device_no: None,
            ring_counter: None,
            smartp_no: None,
        })
    }
}

async fn handle_kick_text(
    text: &str,
    direction: &str,
    sender_tx: &tokio::sync::mpsc::Sender<String>,
    cmd_tx_self: &tokio::sync::mpsc::Sender<DaemonCommand>,
    monitor_already_active: bool,
) {
    let ts = chrono_compat_timestamp();
    let parsed = match kick::from_xml(text) {
        Ok(env) => env,
        Err(e) => {
            warn!("kick XML parse error: {e}; raw: {text}");
            return;
        }
    };

    // Auto-ack inbound base→bridge kick notices. Empirically the legitimate
    // app does this: every `<notice><command>kick><kickId=N>...</notice>` it
    // receives, it replies with `<request><command>kick><kickId=N> status:0`.
    // The server-supplied kickId on the notice is what we echo verbatim.
    if matches!(parsed.root, kick::Root::Notice)
        && matches!(parsed.command, kick::Command::Kick)
        && !parsed.devices.is_empty()
    {
        let ack = build_kick_status_ack(parsed.kick_id, &parsed.devices[0]);
        if let Err(e) = sender_tx.send(ack).await {
            warn!("kick ack send: {e}");
        }
    }

    // Try to detect a doorbell ring in the inbound JSON. Real doorbell rings
    // arrive as `<notice><command>kick>` with JSON `{"request":"notifyState",
    // "attr":{"callStateArray":[{"mainCall":{"deviceName":"door","isRingSetting":
    // true,"ringCounter":N}, …}]}}`.
    if let Some(json) = parsed.json() {
        if let Some(ring) = detect_ring(json) {
            emit_value(serde_json::json!({
                "ts": ts.clone(),
                "event": "doorphone.ring",
                "active": ring.active,
                "device_name": ring.device_name,
                "device_no": ring.device_no,
                "ring_counter": ring.ring_counter,
                "smartp_no": ring.smartp_no,
            }));

            // Auto-fire monitor session on ring start (preview mode).
            // INTERCOM-DESIGN.md §C: ring → preview without user
            // action. If monitor already active, no-op (the ring
            // overlaps with someone manually viewing — fine).
            if ring.active && !monitor_already_active {
                let cmd = DaemonCommand::StartMonitor {
                    media_dir: "/tmp/viana-ring".to_string(),
                    door_no: ring.device_no.map(|n| n as u32),
                    duration_secs: Some(0), // 0 = until stop / idle teardown
                };
                if let Err(e) = cmd_tx_self.try_send(cmd) {
                    warn!("auto-monitor StartMonitor send failed: {e}");
                } else {
                    info!("ring detected → auto-fired monitor session");
                }
            }
        }

        // If this looks like a `connect` response, hand it off to the monitor
        // task that's waiting on the matching seqNo.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
            let response_kind = v.get("response").and_then(|x| x.as_str());
            let seq_no = v.get("seqNo").and_then(|x| x.as_i64());
            if matches!(response_kind, Some("connect")) {
                if let Some(seq_no) = seq_no {
                    let sender = pending_monitors().lock().unwrap().remove(&seq_no);
                    if let Some(tx) = sender {
                        let sdp = parsed.sdp().map(str::to_owned);
                        let _ = tx
                            .send(KickEnvelopeForward {
                                json: json.to_string(),
                                sdp,
                            })
                            .await;
                    }
                }
            }
        }
    }

    let event = KickEvent {
        ts,
        direction,
        raw_xml: text,
        parsed: ParsedKick {
            root: match parsed.root {
                kick::Root::Request => "request",
                kick::Root::Notice => "notice",
            },
            command: match parsed.command {
                kick::Command::Auth => "auth",
                kick::Command::KickTerminal => "kickTerminal",
                kick::Command::KickServer => "kickServer",
                kick::Command::Kick => "kick",
                kick::Command::Reconnect => "reconnect",
                kick::Command::Disconnect => "disconnect",
                kick::Command::Unknown => "unknown",
            },
            kick_id_hex: format!("{:08x}", parsed.kick_id),
            kind: parsed.kind,
            devices: parsed.devices.iter().map(String::as_str).collect(),
            json: parsed.json(),
            sdp: parsed.sdp(),
            other_param_keys: parsed
                .params
                .iter()
                .filter_map(|p| match p {
                    kick::Param::Other { key, .. } => Some(key.clone()),
                    _ => None,
                })
                .collect(),
        },
    };

    match serde_json::to_value(&event) {
        Ok(value) => emit_value(value),
        Err(e) => warn!("event serialize: {e}"),
    }
}

/// Avoid pulling in chrono — emit ISO-ish UTC manually using the system clock.
fn chrono_compat_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (y, mon, d, h, m, s) = ymd_hms_from_unix(secs);
    format!("{y:04}-{mon:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Cheap UTC breakdown from a unix timestamp. Good enough for log lines; not
/// for anything that needs leap-second correctness.
fn ymd_hms_from_unix(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86400) as i64;
    let s_of_day = (secs % 86400) as u32;
    let h = s_of_day / 3600;
    let m = (s_of_day % 3600) / 60;
    let s = s_of_day % 60;

    // Civil-from-days, Howard Hinnant's algorithm (public domain).
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
    (y, mon, d, h, m, s)
}

/// Tiny extension: non-blocking peek for ctrl-c without awaiting.
trait NowOrNever {
    fn now_or_never_ok(self) -> bool;
}

impl<F: std::future::Future<Output = std::io::Result<()>>> NowOrNever for F {
    fn now_or_never_ok(self) -> bool {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};
        let mut fut = pin!(self);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(&waker);
        matches!(fut.as_mut().poll(&mut cx), Poll::Ready(Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::detect_ring;

    const FIXTURE_RING_ACTIVE: &str = r#"{"request":"notifyState","attr":{"callStateArray":[{"smartPNo":1,"mainCall":{"deviceName":"door","deviceNo":1,"isRingSetting":true,"ringCounter":1}}]}}"#;

    /// notifyState after the ring stopped — `callStateArray` exists but no
    /// entry has `mainCall.isRingSetting = true`.
    const FIXTURE_NO_RING: &str = r#"{"request":"notifyState","attr":{"callStateArray":[{"smartPNo":1,"subCall":{}}]}}"#;

    /// notifyState that is not call-related. detect_ring should return None.
    const FIXTURE_NONCALL_NOTIFY: &str = r#"{"request":"notifyState","attr":{"doorState":{}}}"#;

    #[test]
    fn detects_active_ring() {
        let r = detect_ring(FIXTURE_RING_ACTIVE).expect("notifyState");
        assert!(r.active, "ring should be active");
        assert_eq!(r.device_name.as_deref(), Some("door"));
        assert_eq!(r.device_no, Some(1));
        assert_eq!(r.ring_counter, Some(1));
        assert_eq!(r.smartp_no, Some(1));
    }

    #[test]
    fn returns_none_for_non_notifystate_json() {
        // A getState reply, NOT a notifyState — should be None.
        let r = detect_ring(r#"{"request":"foo","attr":{}}"#);
        assert!(r.is_none());
    }

    #[test]
    fn returns_inactive_for_ring_stopped() {
        // After the ring stops, the next notifyState's callStateArray no
        // longer has a `mainCall` element — only subCalls / smartPNo.
        let r = detect_ring(FIXTURE_NO_RING).expect("notifyState");
        assert!(!r.active, "ring should NOT be active after ring stops");
        assert!(r.device_name.is_none());
    }

    #[test]
    fn returns_none_for_noncall_notifystate() {
        // notifyState messages also fire for non-call events (door state
        // updates, etc.). Those have no callStateArray — detect_ring must
        // return None so the caller doesn't spuriously emit a ring event.
        assert!(detect_ring(FIXTURE_NONCALL_NOTIFY).is_none());
    }
}
