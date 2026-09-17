use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("base64 decode failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("AES ciphertext length {len} is not block-aligned (16)")]
    UnalignedCiphertext { len: usize },

    #[error("AES plaintext too short: {actual} < {required}")]
    PlaintextTooShort { actual: usize, required: usize },

    #[error("AES decrypt failed: {0}")]
    AesDecrypt(String),

    #[error("HTTP transport error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("server returned an unexpected response shape: {0}")]
    BadResponse(String),

    #[error("server returned non-success status {status}: {body}")]
    ServerError { status: u16, body: String },
}
