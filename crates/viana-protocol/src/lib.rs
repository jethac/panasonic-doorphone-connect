//! VIANA protocol crate — identity, ELB-auth, kick-XML, SIP, SDP, and
//! discovery used by the doorphoneconnect Android app. The daemon wires
//! this into HTTP/WSS in `viana-ha`. See `docs/PROTOCOL.md`.

pub mod discover;
pub mod elb;
pub mod error;
pub mod identity;
pub mod kick;
pub mod local_cgi;
pub mod mint;
pub mod pair;
pub mod sdp;
pub mod sip;

pub use error::{Error, Result};
