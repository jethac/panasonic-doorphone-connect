//! End-to-end pair flow: discovery → mint → SIP MESSAGE → SIP REGISTER →
//! local CGI 107 → local CGI 108 → success.
//!
//! Returns everything the daemon needs to write into `config.toml` and
//! switch to paired mode. Does not write the file itself — the caller owns
//! persistence so it can decide whether to atomic-rename, broadcast a
//! "config changed" event, etc.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::net::UdpSocket;
use tracing::info;

use crate::discover::{self, DiscoverOutcome};
use crate::identity::{self};
use crate::local_cgi::LocalCgiClient;
use crate::sip::{self, PairContext};

/// Bind an ephemeral UDP socket for a SIP transaction. The legitimate
/// Galaxy app uses arbitrary high ephemeral ports (47480 for MESSAGE,
/// 47082 for REGISTER in the captured pair) — the base addresses both
/// responses and the post-REGISTER NOTIFY back to whatever source port
/// each request came from. So we just bind ephemeral and let the kernel
/// pick.
async fn bind_sip_socket(requested_port: u16) -> std::io::Result<UdpSocket> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, requested_port)).await?;
    info!(port = sock.local_addr()?.port(), "bound SIP socket");
    Ok(sock)
}

#[derive(Debug, thiserror::Error)]
pub enum PairError {
    #[error("no Panasonic base found on this LAN")]
    NoBaseOnLan,
    #[error("base found but pair button was not pressed within the window")]
    PairButtonTimeout,
    #[error("base login password rejected (CGI 107 result={0})")]
    LoginRejected(i32),
    #[error("base did not return its viana_id during CGI 108 (result={0})")]
    BaseRegistrationFailed(i32),
    #[error("base did not return its viana_id during CGI 108 (response missing vianaID)")]
    BaseRegistrationNoVianaId,
    #[error("network error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTPS error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("identity error: {0}")]
    Identity(#[from] crate::error::Error),
}

/// Output of a successful pair. The caller persists this to `config.toml`'s
/// `[base]` table.
#[derive(Debug, Clone, Serialize)]
pub struct PairResult {
    pub base_viana_id: String,
    pub base_lan_ip: Ipv4Addr,
    pub base_mac: String,
    pub base_model: String,
    pub base_cert: Option<String>,
    /// Slot the base assigned us in the WiFi-handset range (21-28).
    pub assigned_terminal: u32,
    /// Synthetic MAC we generated and registered with — needs to be
    /// persisted because the SIP REGISTER digest auth (and any future
    /// re-pair) keys off it.
    pub synthetic_mac: String,
}

/// Inputs the daemon collects from the HA Config Flow before driving the
/// flow. `our_viana_id` and `our_cert` come from the daemon's already-minted
/// kiki.dat (`identity::decode_kiki`); the daemon mints if necessary.
pub struct PairInputs<'a> {
    /// Our local IPv4 (the SIP `Contact` and tgdect callback use this).
    pub local_ip: Ipv4Addr,
    /// Local UDP port to bind for the SIP exchange. Pass 0 to let the OS
    /// pick — the assigned port is what we stamp into the `Contact` header.
    pub local_sip_port: u16,
    /// User-supplied login password they previously set on the base unit's
    /// own menu. CGI 107 will validate this.
    pub base_login_password: &'a str,
    /// HA's user-supplied display name. Used in our log lines only; the
    /// SIP-level Name= field is hardcoded to a Galaxy device model in
    /// sip.rs to look indistinguishable from a real handset.
    pub phone_name: &'a str,
    /// Our 16-digit decimal viana_id (from kiki).
    pub our_viana_id: &'a str,
    /// Our certificate (from kiki).
    pub our_cert: &'a str,
    /// Persisted synthetic MAC for this bridge install. Generated once at
    /// first /pair and reused forever — see `viana_ha::identity`. NEVER
    /// roll per attempt: every fresh MAC from the same IP is an audit
    /// signal that this isn't a real handset install.
    pub synthetic_mac: &'a str,
    /// Previously-known 16-digit base VIANA id. Some bases ack CGI 108 with
    /// an empty body; pass a stored id (re-pair, or a value the user put in
    /// `config.toml`) so kick targeting still works.
    pub base_viana_id_hint: Option<&'a str>,
    /// How long to wait for the user to press the pair button.
    pub pair_window: Duration,
}

/// Returned alongside `PairResult` so the caller can spawn the
/// long-running SIP maintenance task (re-REGISTER every 15s + NOTIFY
/// ack). Dropping these aborts the maintenance immediately.
///
/// `sock` is `Arc<UdpSocket>` because pair::run shares it between the
/// pair-window NOTIFY-acker task (which runs concurrently with the CGI
/// 107/108 calls) and the eventual long-running maintenance task.
pub struct PairSipMaintenance {
    pub sock: Arc<UdpSocket>,
    pub ctx: sip::PairContext,
    pub register_state: sip::RegisterResult,
}

/// Drive the full pair flow. Returns either the successful result + the
/// SIP-maintenance handle (so the daemon can keep the registration
/// alive forever) or a structured error the HA Config Flow can render.
pub async fn run(
    inputs: PairInputs<'_>,
) -> Result<(PairResult, PairSipMaintenance), PairError> {
    info!(
        local_ip = %inputs.local_ip,
        phone_name = %inputs.phone_name,
        pair_window_secs = inputs.pair_window.as_secs(),
        "pair flow starting"
    );
    // 1. Discover the base + wait for pair-accept status.
    let outcome = discover::wait_for_accepting(inputs.pair_window).await?;
    let discovered = match outcome {
        DiscoverOutcome::Accepted(b) => b,
        DiscoverOutcome::TimedOutWaiting { .. } => return Err(PairError::PairButtonTimeout),
        DiscoverOutcome::NoBaseOnLan => return Err(PairError::NoBaseOnLan),
    };
    info!(
        base_ip = %discovered.lan_ip,
        base_mac = %discovered.mac,
        base_model = %discovered.model,
        "base in pair-accept mode"
    );

    // 2. SIP exchanges. The legitimate Galaxy uses TWO separate UDP
    //    sockets and TWO separate Call-IDs for MESSAGE vs REGISTER —
    //    reusing the MESSAGE Call-ID for REGISTER causes the base to 500
    //    (treats the REGISTER as an in-dialog continuation that doesn't
    //    fit). Match that: one socket+ctx for MESSAGE, regenerate
    //    Call-ID/from-tag and bind a fresh socket for REGISTER.
    //
    // synthetic_mac comes from the persisted identity sidecar — never
    // generate fresh per attempt (audit signal).
    let synthetic_mac = inputs.synthetic_mac.to_string();

    let msg_sock = bind_sip_socket(inputs.local_sip_port).await?;
    let msg_port = msg_sock.local_addr()?.port();
    let mut ctx = PairContext::new(
        discovered.lan_ip,
        inputs.local_ip,
        msg_port,
        synthetic_mac.clone(),
        inputs.phone_name.to_string(),
    );

    info!(msg_port, mac = %synthetic_mac, "sending SIP MESSAGE pair bootstrap");
    let assigned_slot = sip::send_pair_message(&msg_sock, &ctx).await?.unwrap_or(21);
    info!(assigned_slot, "MESSAGE complete; opening REGISTER transaction");
    drop(msg_sock); // close the MESSAGE socket — REGISTER uses its own.

    let reg_sock = Arc::new(bind_sip_socket(0).await?);
    let reg_port = reg_sock.local_addr()?.port();
    ctx.local_port = reg_port;
    ctx.regenerate_for_register();
    info!(reg_port, "REGISTER socket bound; new Call-ID + from-tag rolled");
    let reg_result = sip::register(&*reg_sock, &ctx, assigned_slot).await?;
    let assigned_terminal = reg_result.terminal;
    info!(assigned_terminal, "REGISTER cycle completed; running CGI 107 + 108");

    // After REGISTER the base immediately starts blasting NOTIFYs at our
    // reg_sock (pcap evidence: /tmp/pair_capture.pcap 2026-05-12, port
    // 5060 NOTIFYs at +63ms, +83ms, +599ms, +602ms, +1.6s, +1.6s, ...).
    // If we don't ack them while CGI 107/108 is in flight, the base
    // treats us as a sick terminal and CGI 108 returns
    // {"detail":"","result":0} with no data.vianaID — pair fails. Galaxy
    // doesn't see this because its background SIP UA always runs. Spawn
    // a NOTIFY-acker on a clone of the Arc'd socket so it polls the
    // socket concurrently with the CGI calls below.
    let acker_sock = Arc::clone(&reg_sock);
    let acker_ctx = ctx.clone();
    let acker_handle = tokio::spawn(async move {
        if let Err(e) = sip::ack_notifies_forever(acker_sock, acker_ctx).await {
            tracing::warn!(err = %e, "pair-window NOTIFY acker exited");
        }
    });

    // 3. Local CGI: 107 (auth with user's login password) → 108 (plant
    //    our viana_id + cert into the base's baseinfo row).
    let cgi = LocalCgiClient::new(discovered.lan_ip, synthetic_mac.clone())?;
    let login_res = cgi.login(inputs.base_login_password).await;
    let login = match login_res {
        Ok(l) => l,
        Err(e) => {
            acker_handle.abort();
            return Err(PairError::Http(e));
        }
    };
    if login.result != 0 {
        acker_handle.abort();
        return Err(PairError::LoginRejected(login.result));
    }
    let registered_res = cgi
        .register(inputs.our_viana_id, inputs.our_cert, Some(inputs.our_viana_id))
        .await;
    let registered = match registered_res {
        Ok(r) => r,
        Err(e) => {
            acker_handle.abort();
            return Err(PairError::Http(e));
        }
    };
    if registered.result != 0 {
        acker_handle.abort();
        return Err(PairError::BaseRegistrationFailed(registered.result));
    }
    // Some bases ack CGI 108 with an empty {"result":0,"detail":""}
    // instead of returning data.vianaID. Treat result:0 as success and
    // use a configured hint when the body is empty.
    let base_viana_id = match registered.base_viana_id() {
        Some(id) => id,
        None => {
            if let Some(hint) = inputs.base_viana_id_hint.filter(|s| !s.is_empty()) {
                tracing::warn!(
                    hint,
                    "CGI 108 did not return data.vianaID; using configured hint"
                );
                hint.to_string()
            } else {
                tracing::warn!(
                    "CGI 108 did not return data.vianaID and no hint was configured; \
                     storing an empty base viana_id. Set [base].viana_id in config.toml \
                     if kick targeting fails."
                );
                String::new()
            }
        }
    };
    let base_cert = registered.cert();
    if base_cert.is_none() {
        tracing::warn!(
            "CGI 108 did not return data.cert; daemon will operate without it. \
             If subsequent operations fail, we'll need to capture/extract the \
             base cert separately."
        );
    }

    // CGI 108 succeeded — kill the temporary acker, the caller will
    // start the full maintain_registration loop which acks NOTIFYs AND
    // re-REGISTERs every 15s.
    acker_handle.abort();

    // Quiet the unused-import warning when identity isn't reached at compile
    // time (the daemon side mints separately; this module is intentionally
    // I/O-only on the base side).
    let _ = identity::decode_kiki;

    let result = PairResult {
        base_viana_id,
        base_lan_ip: discovered.lan_ip,
        base_mac: discovered.mac,
        base_model: discovered.model,
        base_cert,
        assigned_terminal,
        synthetic_mac,
    };

    let maintenance = PairSipMaintenance {
        sock: reg_sock,
        ctx,
        register_state: reg_result,
    };

    Ok((result, maintenance))
}
