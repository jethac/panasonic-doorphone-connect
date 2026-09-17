//! Persistent runtime configuration for `viana-ha`.
//!
//! On boot the daemon reads `config.toml` from `--config-path` (default
//! `/opt/viana-ha/config.toml`). If `[base]` is missing the daemon enters
//! **unpaired mode** — it brings up only the HTTP server with the
//! `/pair` endpoint exposed; no VIANA WSS, no heartbeats. Once pairing
//! completes the daemon writes the freshly-discovered base info back to
//! the same file and the operator (or a systemd-restart) brings it up
//! into **paired mode**.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub base: Option<BaseConfig>,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdentityConfig {
    /// Path to the AES-encrypted kiki.dat. Created during pairing if absent.
    pub kiki_path: PathBuf,
    /// Panasonic root CA in PEM. Required to verify their `*.s2.vianaaws.jp`
    /// X.509 v1 chain.
    pub ca_cert_path: PathBuf,
    /// Optional override of the unique_id passed to the mint endpoint.
    /// Production should leave this default; tests may want determinism.
    #[serde(default)]
    pub unique_id: Option<String>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            kiki_path: PathBuf::from("/opt/viana-ha/identity/kiki.dat"),
            ca_cert_path: PathBuf::from("/opt/viana-ha/identity/ca.pem"),
            unique_id: None,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct BaseConfig {
    /// 16-digit decimal viana_id of the BASE. Recovered from the base's
    /// pairing response (originally seen in `securitysettings.db`).
    pub viana_id: String,
    /// LAN IP of the base. Used to send the SIP MESSAGE pairing handshake;
    /// not strictly needed for VIANA-cloud-only operation.
    #[serde(default)]
    pub lan_ip: Option<String>,
    /// Hardware MAC of the base. For displaying / re-detection on a
    /// network with DHCP-shuffled IPs.
    #[serde(default)]
    pub mac: Option<String>,
    /// Hardware model string the base reports (e.g. "SWD505" for the
    /// VL-MWD505 family).
    #[serde(default)]
    pub model: Option<String>,
    /// Human-friendly name set during pairing (e.g. "front gate").
    #[serde(default)]
    pub display_name: Option<String>,
    /// ISO-8601 timestamp pairing finished.
    #[serde(default)]
    pub paired_at: Option<String>,
    /// Synthetic MAC the bridge presented during pair. Persisted because
    /// the SIP REGISTER digest password (`md5(MAC).upper()`) keys off it,
    /// and any future re-pair must reuse the same value.
    #[serde(default)]
    pub synthetic_mac: Option<String>,
    /// Slot the base assigned us in the WiFi-handset range (21-28).
    #[serde(default)]
    pub assigned_terminal: Option<u32>,
    /// Base's TLS certificate, returned by CGI 108. Constant per device;
    /// stashed for future direct-to-base operations.
    #[serde(default)]
    pub cert: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    /// Address:port the local HTTP API binds to. 0.0.0.0:7878 by default so
    /// the debug client can reach the daemon from elsewhere on the LAN /
    /// Tailscale; HA running on the same box hits it via 127.0.0.1.
    pub listen: String,
    /// Bearer token required on every HTTP request. Auto-generated on
    /// first run and persisted; rotate by deleting from the file and
    /// restarting the daemon.
    pub auth_token: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:7878".to_string(),
            auth_token: random_token(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeartbeatConfig {
    /// VIANA cloud has been seen to drop idle WSS at ~25s; the legitimate
    /// app polls every ~200ms but 10s is plenty for our use case.
    pub interval_secs: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self { interval_secs: 10 }
    }
}

impl Config {
    /// Load from disk. Returns an empty (default) Config if the file is
    /// missing, so the daemon can boot in unpaired mode and the operator
    /// can pair via the HTTP API. Returns an error only on parse failure.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text)
                .with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let text = toml::to_string_pretty(self).context("serialising config")?;
        // Atomic write: stage to .tmp, fsync-ish via rename. Token is in
        // here, mode 0600 if we can.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, path).with_context(|| format!("renaming {}", tmp.display()))?;
        Ok(())
    }

    pub fn is_paired(&self) -> bool {
        self.base.is_some()
    }
}

fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
