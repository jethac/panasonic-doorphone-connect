//! Local-base CGI client for `/cgi-bin/devm_request.cgi` requests 107
//! (`loginPassword` auth) and 108 (`vianaID + cert` registration).
//!
//! Post-SIP-REGISTER step: see `docs/PROTOCOL.md`.
//! This is what makes the pair *stick*: 108 plants our `viana_id` + `cert`
//! into the base's `securitysettings.db.baseinfo` so future VIANA-cloud
//! kicks from us are recognised as a known terminal.
//!
//! Wire shape:
//!   * URL: `https://<base_ip>/cgi-bin/devm_request.cgi`
//!   * TLS: the base ships a self-signed cert; we accept any cert (LAN-only
//!     traffic, MAC-bound, the threat model is "anyone with LAN access can
//!     replay anyway").
//!   * Method: POST
//!   * Content-Type: `application/x-www-form-urlencoded`
//!   * Body: `sipnum=<MAC>@<sessionID>&request={"request":<code>,"inHouse":true,"data":{...}}`
//!   * Response: JSON with at minimum `{"result":<int>}` plus request-specific fields.

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use tracing::info;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// What we send + what we get back, paired up.
#[derive(Debug, Clone)]
pub struct LocalCgiClient {
    base_ip: std::net::Ipv4Addr,
    /// Same synthetic MAC the SIP MESSAGE used. Goes into the `sipnum=`
    /// portion of the form body.
    synthetic_mac: String,
    /// Session ID — observed in captures as a small integer; zeroed for
    /// pairing where the session hasn't been negotiated yet.
    session_id: u32,
    http: reqwest::Client,
}

impl LocalCgiClient {
    pub fn new(base_ip: std::net::Ipv4Addr, synthetic_mac: String) -> reqwest::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            // Base ships a self-signed cert. LAN-only traffic; we don't ship a CA.
            .danger_accept_invalid_certs(true)
            .build()?;
        Ok(Self {
            base_ip,
            synthetic_mac,
            session_id: 0,
            http,
        })
    }

    fn url(&self) -> String {
        format!("https://{}/cgi-bin/devm_request.cgi", self.base_ip)
    }

    /// `sipnum` field. Galaxy capture (`z2.1/b$a.smali` ~line 2073) shows
    /// the app sends `sipnum=<MAC>` with NO `@<sessionID>` suffix when
    /// there is no active session (`v1==0` branch). We were appending
    /// `@0` unconditionally — that gets accepted but the base treats it
    /// as a "stranger" and never returns its identity payload on 108.
    fn sipnum(&self) -> String {
        if self.session_id == 0 {
            self.synthetic_mac.clone()
        } else {
            format!("{}@{}", self.synthetic_mac, self.session_id)
        }
    }

    /// Send a CGI request with the given numeric code and JSON `data`
    /// payload. Returns the decoded JSON response.
    ///
    /// Body shape matches the captured Galaxy bytes (`z2.1/b$a.smali`
    /// ~line 2050-2266):
    ///   * Content-Type: `application/json` (yes — even though the body
    ///     is `key=value&key=value` form-style; Panasonic's CGI is picky
    ///     and any other CT path apparently routes to the "empty ack"
    ///     codepath).
    ///   * Accept: `application/json`.
    ///   * Body literally: `sipnum=<MAC>&request=<RAW-JSON>` with NO
    ///     URL-encoding of the JSON's `{`, `}`, `:`, `,` etc.
    ///   * The JSON is `JSONObject.toString(4)` — pretty-printed with
    ///     4-space indent. We replicate via `serde_json::to_string_pretty`,
    ///     which uses 2-space indent — close enough; the base accepts both
    ///     for 107 but we'll verify on 108.
    async fn send(&self, code: u32, data: serde_json::Value) -> reqwest::Result<serde_json::Value> {
        let request_obj = json!({
            "request": code,
            "inHouse": true,
            "data": data,
        });
        let request_json = serde_json::to_string_pretty(&request_obj)
            .unwrap_or_else(|_| request_obj.to_string());
        let body = format!("sipnum={}&request={}", self.sipnum(), request_json);
        let resp = self
            .http
            .post(self.url())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body)
            .send()
            .await?
            .error_for_status()?;
        let value: serde_json::Value = resp.json().await?;
        info!(cgi_code = code, response = %value, "CGI response");
        Ok(value)
    }

    /// Request 107 / 0x6b — submit the user's base login password (the one
    /// they set on the base's own menu). Authenticates
    /// the bridge to the base for the upcoming 108 call.
    pub async fn login(&self, login_password: &str) -> reqwest::Result<LoginResponse> {
        let value = self
            .send(107, json!({ "loginPassword": login_password }))
            .await?;
        Ok(serde_json::from_value(value).unwrap_or_default())
    }

    /// Request 108 / 0x6c — plant our `viana_id` + `cert` into the base's
    /// `baseinfo` row. After this succeeds, the base recognises future
    /// VIANA-cloud kicks from us as a known terminal.
    ///
    /// `viana_id` is our 16-digit decimal device id (recovered from
    /// `kiki.dat`); `cert` is the matching certificate. Both come out of
    /// the mint flow; see `viana_protocol::mint`.
    ///
    /// Official-app behaviour:
    ///   1. POST 108 with `{vianaID, cert}` only ("type=0", no auth fields).
    ///      Base returns `{"detail":"","result":0}` — empty ack.
    ///   2. POST 108 with `{vianaID, cert, authVersion:1, authID}`
    ///      ("type=1"). First attempt comes back empty too (logged as
    ///      `### error!` in the app).
    ///   3. After ~500ms the app re-posts the type=1 body; second attempt
    ///      returns `data.vianaID` + `data.cert`.
    /// A single type=1 with no priming type=0 and no retry just gets the
    /// empty ack forever — which is what we were seeing.
    pub async fn register(
        &self,
        our_viana_id: &str,
        our_cert: &str,
        auth_id: Option<&str>,
    ) -> reqwest::Result<RegisterResponse> {
        // type=0: vianaID + cert only. Primes the base.
        let body_priming = json!({
            "vianaID": our_viana_id,
            "cert": our_cert,
        });
        let _ = self.send(108, body_priming).await?;
        tokio::time::sleep(Duration::from_millis(22)).await;

        // type=1: full body with auth fields when caller asked for them.
        let mut body_auth = json!({
            "vianaID": our_viana_id,
            "cert": our_cert,
        });
        if let Some(aid) = auth_id {
            body_auth["authVersion"] = json!(1);
            body_auth["authID"] = json!(aid);
        }

        let first = self.send(108, body_auth.clone()).await?;
        let first_parsed: RegisterResponse =
            serde_json::from_value(first).unwrap_or_default();
        if first_parsed.base_viana_id().is_some() {
            return Ok(first_parsed);
        }

        // Galaxy waits ~510ms before the retry; match that.
        info!("CGI 108 type=1 first attempt returned no vianaID — retrying after 510ms");
        tokio::time::sleep(Duration::from_millis(510)).await;
        let second = self.send(108, body_auth).await?;
        Ok(serde_json::from_value(second).unwrap_or_default())
    }
}

/// Response shape for 107. The base reports `result=0` on success; non-zero
/// codes likely encode "wrong password" / "locked out". Other fields are
/// best-effort — capture didn't pin the schema fully.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoginResponse {
    #[serde(default)]
    pub result: i32,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Response shape for 108. Returns the **base's** identity so the bridge
/// can persist it (this is the load-bearing field).
///
/// The official app parses `data.vianaID` / `data.cert` — i.e. the base
/// nests its reply under `data`. Older/different firmwares may put the
/// fields at the top level, so the accessors fall through both.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterResponse {
    #[serde(default)]
    pub result: i32,
    #[serde(default)]
    pub data: serde_json::Value,
    #[serde(default, rename = "vianaID")]
    pub base_viana_id_top: Option<String>,
    #[serde(default)]
    pub cert_top: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl RegisterResponse {
    /// 16-digit decimal viana_id of the BASE. Looks at `data.vianaID`
    /// first, falls back to top-level `vianaID`.
    pub fn base_viana_id(&self) -> Option<String> {
        self.data
            .get("vianaID")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| self.base_viana_id_top.clone())
    }

    /// Base's TLS certificate. Same fallback order as `base_viana_id`.
    pub fn cert(&self) -> Option<String> {
        self.data
            .get("cert")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| self.cert_top.clone())
    }
}
