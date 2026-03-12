use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::CryptoError;
use crate::traits::Wipe;
use crate::types::{SecretBytes, WireNonce, NONCE_LEN_12};

pub fn fill_random(buffer: &mut [u8]) -> Result<(), CryptoError> {
    OsRng
        .try_fill_bytes(buffer)
        .map_err(|_| CryptoError::Internal("os random generator failure"))?;
    Ok(())
}

pub fn random_secret(len: usize) -> Result<SecretBytes, CryptoError> {
    if len == 0 {
        return Err(CryptoError::InvalidInput(
            "random secret length must be greater than 0",
        ));
    }

    let mut buffer = vec![0_u8; len];
    fill_random(&mut buffer)?;
    let secret = SecretBytes::from_slice(&buffer);
    buffer.wipe();
    Ok(secret)
}

pub fn random_nonce() -> Result<WireNonce, CryptoError> {
    let mut buffer = [0_u8; NONCE_LEN_12];
    fill_random(&mut buffer)?;
    WireNonce::from_slice(&buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_secret_returns_requested_length() {
        let secret = random_secret(32).expect("random secret generation should succeed");
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn random_secret_rejects_zero_length() {
        let result = random_secret(0);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidInput(
                "random secret length must be greater than 0"
            ))
        ));
    }

    #[test]
    fn random_nonce_returns_valid_wire_nonce() {
        let nonce = random_nonce().expect("random nonce generation should succeed");
        assert_eq!(nonce.as_bytes().len(), NONCE_LEN_12);
    }
}
