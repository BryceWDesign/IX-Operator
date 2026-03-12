use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use crate::error::CryptoError;
use crate::rng::random_secret;
use crate::types::{
    PublicBytes, SecretBytes, SignatureBytes, ED25519_PUBLIC_KEY_LEN, ED25519_SECRET_KEY_LEN,
    ED25519_SIGNATURE_LEN, X25519_KEY_LEN,
};

pub fn generate_x25519_keypair() -> Result<(SecretBytes, PublicBytes), CryptoError> {
    let private_key = random_secret(X25519_KEY_LEN)?;
    let public_key = derive_x25519_public_key(&private_key)?;
    Ok((private_key, public_key))
}

pub fn derive_x25519_public_key(private_key: &SecretBytes) -> Result<PublicBytes, CryptoError> {
    let private_key_bytes = secret_array_32(private_key.as_slice())?;
    let public_key = x25519(private_key_bytes, X25519_BASEPOINT_BYTES);
    Ok(PublicBytes::from_slice(&public_key))
}

pub fn x25519_shared_secret(
    private_key: &SecretBytes,
    peer_public_key: &PublicBytes,
) -> Result<SecretBytes, CryptoError> {
    let private_key_bytes = secret_array_32(private_key.as_slice())?;
    let peer_public_key_bytes = public_array_32(peer_public_key.as_slice())?;

    let shared_secret = x25519(private_key_bytes, peer_public_key_bytes);
    Ok(SecretBytes::from_slice(&shared_secret))
}

pub fn generate_ed25519_keypair() -> Result<(SecretBytes, PublicBytes), CryptoError> {
    let secret_key = random_secret(ED25519_SECRET_KEY_LEN)?;
    let public_key = derive_ed25519_public_key(&secret_key)?;
    Ok((secret_key, public_key))
}

pub fn derive_ed25519_public_key(secret_key: &SecretBytes) -> Result<PublicBytes, CryptoError> {
    let secret_key_bytes = secret_array_32(secret_key.as_slice())?;
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let verifying_key = signing_key.verifying_key();
    Ok(PublicBytes::from_slice(&verifying_key.to_bytes()))
}

pub fn sign_ed25519(
    secret_key: &SecretBytes,
    message: &[u8],
) -> Result<SignatureBytes, CryptoError> {
    let secret_key_bytes = secret_array_32(secret_key.as_slice())?;
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let signature = signing_key.sign(message);
    Ok(SignatureBytes::from_slice(&signature.to_bytes()))
}

pub fn verify_ed25519(
    public_key: &PublicBytes,
    message: &[u8],
    signature: &SignatureBytes,
) -> Result<(), CryptoError> {
    let public_key_bytes = public_array_32(public_key.as_slice())?;
    let signature_bytes = signature_array_64(signature.as_slice())?;

    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| CryptoError::DecodeError("invalid ed25519 public key bytes"))?;
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

fn secret_array_32(input: &[u8]) -> Result<[u8; 32], CryptoError> {
    if input.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: input.len(),
        });
    }

    let mut output = [0_u8; 32];
    output.copy_from_slice(input);
    Ok(output)
}

fn public_array_32(input: &[u8]) -> Result<[u8; 32], CryptoError> {
    if input.len() != 32 {
        return Err(CryptoError::InvalidPublicKeyLength {
            expected: 32,
            actual: input.len(),
        });
    }

    let mut output = [0_u8; 32];
    output.copy_from_slice(input);
    Ok(output)
}

fn signature_array_64(input: &[u8]) -> Result<[u8; 64], CryptoError> {
    if input.len() != 64 {
        return Err(CryptoError::InvalidSignatureLength {
            expected: 64,
            actual: input.len(),
        });
    }

    let mut output = [0_u8; 64];
    output.copy_from_slice(input);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_keypairs_derive_matching_shared_secrets() {
        let (alice_secret, alice_public) =
            generate_x25519_keypair().expect("alice keypair should generate");
        let (bob_secret, bob_public) =
            generate_x25519_keypair().expect("bob keypair should generate");

        let alice_shared =
            x25519_shared_secret(&alice_secret, &bob_public).expect("alice secret should derive");
        let bob_shared =
            x25519_shared_secret(&bob_secret, &alice_public).expect("bob secret should derive");

        assert_eq!(alice_shared.as_slice(), bob_shared.as_slice());
        assert_eq!(alice_shared.len(), X25519_KEY_LEN);
    }

    #[test]
    fn ed25519_sign_and_verify_round_trip_succeeds() {
        let (secret_key, public_key) =
            generate_ed25519_keypair().expect("ed25519 keypair should generate");

        let signature =
            sign_ed25519(&secret_key, b"ix-operator-message").expect("sign should succeed");

        assert_eq!(public_key.len(), ED25519_PUBLIC_KEY_LEN);
        assert_eq!(signature.len(), ED25519_SIGNATURE_LEN);
        assert!(verify_ed25519(&public_key, b"ix-operator-message", &signature).is_ok());
    }

    #[test]
    fn ed25519_verify_rejects_modified_message() {
        let (secret_key, public_key) =
            generate_ed25519_keypair().expect("ed25519 keypair should generate");

        let signature =
            sign_ed25519(&secret_key, b"original-message").expect("sign should succeed");

        let result = verify_ed25519(&public_key, b"modified-message", &signature);

        assert!(matches!(result, Err(CryptoError::VerificationFailed)));
    }

    #[test]
    fn derive_x25519_public_key_rejects_invalid_secret_length() {
        let invalid_secret = SecretBytes::from_slice(b"too-short");

        let result = derive_x25519_public_key(&invalid_secret);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidKeyLength {
                expected: X25519_KEY_LEN,
                actual: 9
            })
        ));
    }

    #[test]
    fn verify_ed25519_rejects_invalid_signature_length() {
        let (_, public_key) = generate_ed25519_keypair().expect("ed25519 keypair should generate");
        let invalid_signature = SignatureBytes::from_slice(b"bad-signature");

        let result = verify_ed25519(&public_key, b"message", &invalid_signature);

        assert!(matches!(
            result,
            Err(CryptoError::InvalidSignatureLength {
                expected: ED25519_SIGNATURE_LEN,
                actual: 13
            })
        ));
    }
}
