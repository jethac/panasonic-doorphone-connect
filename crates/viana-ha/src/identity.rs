//! Identity bootstrap for the daemon — wraps `viana_protocol::mint` and
//! `viana_protocol::identity::decode_kiki` with on-disk persistence.
//!
//! On disk we keep three files side-by-side:
//!   * `<kiki_path>` — the AES-encrypted kiki.dat blob (binary-NOT'd wire form,
//!     same shape the legitimate Galaxy app stores).
//!   * `<kiki_path>.disp_id` — plain ASCII 16-digit `disp_id` returned by the
//!     mint endpoint. The kiki blob alone doesn't carry this; we need it for
//!     the pair handshake's CGI 108 (`vianaID` field).
//!   * `<kiki_path>.synthetic_mac` — 12 lowercase hex chars. Generated ONCE
//!     on first /pair attempt and reused for the lifetime of this install.
//!     The legitimate Galaxy app generates this at first launch and stores
//!     it in `securitysettings.db.generalsettings.smartphone_mac_address`;
//!     it persists across re-pairs of the same device. Re-rolling it per
//!     attempt would be observable — every fresh MAC from the same IP
//!     looks like a new "phone install" in any per-base telemetry
//!     Panasonic ships.
//!
//! Used both by the cold-start path (in `main.rs`) and by the HTTP `/pair`
//! endpoint (in `http.rs`), which is why this lives in its own module.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use tracing::{debug, info};

use viana_protocol::identity::{decode_kiki, from_wire_form};
use viana_protocol::mint::{MintRequest, build_mint_request, send_request as send_mint};
use viana_protocol::sip::fresh_synthetic_mac;

const DISP_ID_SIDECAR_EXT: &str = "disp_id";
const SYNTHETIC_MAC_SIDECAR_EXT: &str = "synthetic_mac";

/// What every consumer of the daemon's identity needs.
#[derive(Debug, Clone)]
pub struct DaemonIdentity {
    /// Base64'd `<USER_HEX>:<PW_HEX>` — used as the WSS Basic-Auth header
    /// AND as the `cert` field in the pair handshake's CGI 108.
    pub signature_device_id: String,
    /// 16-digit decimal device id allocated by the mint endpoint. Used as
    /// the `vianaID` field in the pair handshake's CGI 108.
    pub disp_id: String,
    /// Stable 12-hex synthetic MAC; generated once, persisted, reused.
    pub synthetic_mac: String,
}

/// Full kiki + disp_id + synthetic_mac. Mints kiki+disp_id if either is
/// missing; generates the synthetic MAC if its sidecar is missing. Either
/// way, on return the three files exist on disk and will be reused on
/// subsequent calls.
///
/// The synthetic MAC is generated independently of the mint — the mint
/// endpoint doesn't know about it. Galaxy app behaviour: created at
/// first launch, persisted forever.
pub async fn load_or_mint_with_disp_id(
    kiki_path: &Path,
    unique_id: &str,
) -> Result<DaemonIdentity> {
    let disp_id_path = kiki_path.with_extension(DISP_ID_SIDECAR_EXT);
    let mac_path = kiki_path.with_extension(SYNTHETIC_MAC_SIDECAR_EXT);
    let kiki_present = tokio::fs::try_exists(kiki_path).await?;
    let disp_id_present = tokio::fs::try_exists(&disp_id_path).await?;

    let (signature_device_id, disp_id) = if kiki_present && disp_id_present {
        let raw = tokio::fs::read(kiki_path).await?;
        let decoded = decode_kiki(&raw)?;
        let disp_id = tokio::fs::read_to_string(&disp_id_path).await?.trim().to_owned();
        info!(bytes = raw.len(), disp_id_chars = disp_id.len(), "loaded existing identity");
        (decoded.signature_device_id, disp_id)
    } else {
        info!("identity incomplete — minting fresh kiki + disp_id");
        let mint_req: MintRequest = build_mint_request(unique_id);
        debug!(?mint_req, "mint request");

        let public_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("")
            .build()?;

        let mint_resp = send_mint(&public_client, &mint_req).await?;
        info!(disp_id = %mint_resp.disp_id, "mint succeeded");

        // kiki on disk is the bytewise-NOT of the wire form (Base64 ciphertext).
        let on_disk: Vec<u8> = mint_resp.kiki_wire_bytes.iter().map(|b| !b).collect();
        if let Some(parent) = kiki_path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }
        tokio::fs::write(kiki_path, &on_disk).await?;
        tokio::fs::write(&disp_id_path, mint_resp.disp_id.as_bytes()).await?;
        info!(path = %kiki_path.display(), bytes = on_disk.len(), "wrote kiki.dat + disp_id sidecar");

        let decoded = from_wire_form(&mint_resp.kiki_wire_bytes)?;
        (decoded.signature_device_id, mint_resp.disp_id)
    };

    // Synthetic MAC: load if present, else generate + persist.
    let synthetic_mac = if tokio::fs::try_exists(&mac_path).await? {
        let mac = tokio::fs::read_to_string(&mac_path).await?.trim().to_owned();
        info!(mac = %mac, "loaded existing synthetic MAC");
        mac
    } else {
        let mac = fresh_synthetic_mac();
        tokio::fs::write(&mac_path, mac.as_bytes()).await?;
        info!(mac = %mac, path = %mac_path.display(), "generated and persisted synthetic MAC");
        mac
    };

    Ok(DaemonIdentity {
        signature_device_id,
        disp_id,
        synthetic_mac,
    })
}

