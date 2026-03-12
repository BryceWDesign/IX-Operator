use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::CryptoError;
use crate::types::{AlgorithmId, WireNonce, KEY_LEN_32};

pub fn encrypt(
    algorithm: AlgorithmId,
    key: &[u8],
    nonce: &WireNonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        AlgorithmId::Aes256Gcm => encrypt_aes256_gcm(key, nonce, plaintext, aad),
        AlgorithmId::ChaCha20Poly1305 => encrypt_chacha20_poly1305(key, nonce, plaintext, aad),
        _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.as_str())),
    }
}

pub fn decrypt(
    algorithm: AlgorithmId,
    key: &[u8],
    nonce: &WireNonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match algorithm {
        AlgorithmId::Aes256Gcm => decrypt_aes256_gcm(key, nonce, ciphertext, aad),
        AlgorithmId::ChaCha20Poly1305 => decrypt_chacha20_poly1305(key, nonce, ciphertext, aad),
        _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.as_str())),
    }
}

pub fn encrypt_aes256_gcm(
    key: &[u8],
    nonce: &WireNonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
        expected: KEY_LEN_32,
        actual: key.len(),
    })?;

    cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Internal("aes-256-gcm encryption failed"))
}

pub fn decrypt_aes256_gcm(
    key: &[u8],
    nonce: &WireNonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
        expected: KEY_LEN_32,
        actual: key.len(),
    })?;

    cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::IntegrityCheckFailed)
}

pub fn encrypt_chacha20_poly1305(
    key: &[u8],
    nonce: &WireNonce,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEY_LEN_32,
            actual: key.len(),
        })?;

    cipher
        .encrypt(
            chacha20poly1305::Nonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Internal("chacha20-poly1305 encryption failed"))
}

pub fn decrypt_chacha20_poly1305(
    key: &[u8],
    nonce: &WireNonce,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKeyLength {
            expected: KEY_LEN_32,
            actual: key.len(),
        })?;

    cipher
        .decrypt(
            chacha20poly1305::Nonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::IntegrityCheckFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::random_nonce;

    #[test]
    fn aes256_gcm_round_trip_succeeds() {
        let key = [7_u8; KEY_LEN_32];
        let nonce = random_nonce().expect("nonce generation should succeed");
        let plaintext = b"hello from ix-operator";
        let aad = b"session:alpha";

        let ciphertext =
            encrypt_aes256_gcm(&key, &nonce, plaintext, aad).expect("encryption should succeed");
        let decrypted =
            decrypt_aes256_gcm(&key, &nonce, &ciphertext, aad).expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes256_gcm_rejects_wrong_aad() {
        let key = [9_u8; KEY_LEN_32];
        let nonce = random_nonce().expect("nonce generation should succeed");
        let plaintext = b"important message";

        let ciphertext = encrypt_aes256_gcm(&key, &nonce, plaintext, b"aad-one")
            .expect("encryption should succeed");
        let result = decrypt_aes256_gcm(&key, &nonce, &ciphertext, b"aad-two");

        assert!(matches!(result, Err(CryptoError::IntegrityCheckFailed)));
    }

    #[test]
    fn chacha20_poly1305_round_trip_succeeds() {
        let key = [3_u8; KEY_LEN_32];
        let nonce = random_nonce().expect("nonce generation should succeed");
        let plaintext = b"agent payload";
        let aad = b"runtime:beta";

        let ciphertext = encrypt_chacha20_poly1305(&key, &nonce, plaintext, aad)
            .expect("encryption should succeed");
        let decrypted = decrypt_chacha20_poly1305(&key, &nonce, &ciphertext, aad)
            .expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chacha20_poly1305_rejects_wrong_key() {
        let key_a = [1_u8; KEY_LEN_32];
        let key_b = [2_u8; KEY_LEN_32];
        let nonce = random_nonce().expect("nonce generation should succeed");

        let ciphertext = encrypt_chacha20_poly1305(&key_a, &nonce, b"sealed", b"aad")
            .expect("encryption should succeed");
        let result = decrypt_chacha20_poly1305(&key_b, &nonce, &ciphertext, b"aad");

        assert!(matches!(result, Err(CryptoError::IntegrityCheckFailed)));
    }

    #[test]
    fn generic_encrypt_and_decrypt_switch_on_algorithm() {
        let key = [5_u8; KEY_LEN_32];
        let nonce = random_nonce().expect("nonce generation should succeed");
        let plaintext = b"switch path";
        let aad = b"aad";

        let ciphertext = encrypt(AlgorithmId::Aes256Gcm, &key, &nonce, plaintext, aad)
            .expect("generic encrypt should succeed");
        let decrypted = decrypt(AlgorithmId::Aes256Gcm, &key, &nonce, &ciphertext, aad)
            .expect("generic decrypt should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn generic_encrypt_rejects_non_aead_algorithm() {
        let key = [5_u8; KEY_LEN_32];
        let nonce = random_nonce().expect("nonce generation should succeed");

        let result = encrypt(AlgorithmId::X25519, &key, &nonce, b"msg", b"aad");

        assert!(matches!(
            result,
            Err(CryptoError::UnsupportedAlgorithm("x25519"))
        ));
    }
}
