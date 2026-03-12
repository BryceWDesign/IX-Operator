pub mod asymmetric;
pub mod error;
pub mod kdf;
pub mod rng;
pub mod traits;
pub mod types;

pub use asymmetric::{
    derive_ed25519_public_key, generate_ed25519_keypair, generate_x25519_keypair,
    sign_ed25519, verify_ed25519, x25519_shared_secret,
};
pub use error::CryptoError;
pub use kdf::derive_session_keys;
pub use rng::{fill_random, random_nonce, random_secret};
pub use traits::Wipe;
pub use types::{
    AlgorithmId, PublicBytes, SecretBytes, SessionKeys, SignatureBytes, WireNonce,
    ED25519_PUBLIC_KEY_LEN, ED25519_SECRET_KEY_LEN, ED25519_SIGNATURE_LEN, KEY_LEN_32,
    NONCE_LEN_12, X25519_KEY_LEN,
};

pub const PRODUCT_NAME: &str = "IX-Operator";
pub const CRATE_NAME: &str = "ix_crypto";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn bootstrap_banner() -> String {
    format!("{PRODUCT_NAME}::{CRATE_NAME} v{VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_contains_product_name() {
        let banner = bootstrap_banner();
        assert!(banner.contains(PRODUCT_NAME));
    }

    #[test]
    fn banner_contains_crate_name() {
        let banner = bootstrap_banner();
        assert!(banner.contains(CRATE_NAME));
    }

    #[test]
    fn secret_bytes_redacts_debug_output() {
        let secret = SecretBytes::from_slice(b"super-secret-material");
        let rendered = format!("{secret:?}");

        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("super-secret-material"));
    }

    #[test]
    fn wire_nonce_rejects_invalid_length() {
        let result = WireNonce::from_slice(b"short");

        assert!(matches!(
            result,
            Err(CryptoError::InvalidNonceLength {
                expected: NONCE_LEN_12,
                actual: 5
            })
        ));
    }

    #[test]
    fn session_keys_require_32_byte_inputs() {
        let result = SessionKeys::new(b"too-short", &[7_u8; 32]);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: KEY_LEN_32,
                actual: 9
            })
        ));
    }

    #[test]
    fn wiping_secret_clears_len_and_contents() {
        let mut secret = SecretBytes::from_slice(b"abc123");
        secret.wipe();

        assert_eq!(secret.len(), 0);
        assert!(secret.as_slice().is_empty());
    }
}
