//! Live VIANA mint test, Rust port of `tools/empirical_mint_test.py`.
//!
//! Sends one canonical mint request to `dipapp.bb-cygnus.jp`, decodes the
//! response into a usable identity bundle, and prints fingerprints. Allocates
//! one orphaned identity on Panasonic's VIANA side per run — harmless.
//!
//! Run with: `cargo run --example mint_live -p viana-protocol`

use std::time::Duration;

use viana_protocol::{
    identity::{from_wire_form, SELF_ID_RECORD_LEN},
    mint::{build_mint_request, send_request, DEFAULT_UNIQUE_ID},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,viana_protocol=debug".parse().unwrap()),
        )
        .compact()
        .init();

    let req = build_mint_request(DEFAULT_UNIQUE_ID);
    println!("DAC : {}", req.dac);
    println!("PW  : {}", req.pw);
    println!("UA  : {}", req.user_agent);
    println!();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("") // server expects User-agent header set by us, not reqwest's default
        .build()?;

    let resp = send_request(&client, &req).await?;
    println!("dispID: {}", resp.disp_id);
    println!("kiki body: {} bytes", resp.kiki_wire_bytes.len());

    let decoded = from_wire_form(&resp.kiki_wire_bytes)?;
    println!(
        "ciphertext: {} B, plaintext: {} B, signatureDeviceId: {} chars",
        decoded.ciphertext.len(),
        decoded.plaintext.len(),
        decoded.signature_device_id.len(),
    );
    println!("signatureDeviceId: {}", decoded.signature_device_id);

    assert_eq!(decoded.plaintext.len() >= SELF_ID_RECORD_LEN, true);
    Ok(())
}
