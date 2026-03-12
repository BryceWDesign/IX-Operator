use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;
use crate::types::{SessionKeys, KEY_LEN_32};

const EXPANDED_KEY_MATERIAL_LEN: usize = KEY_LEN_32 * 2;

pub fn derive_session_keys(
    shared_secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<SessionKeys, CryptoError> {
    if shared_secret.is_empty() {
        return Err(CryptoError::InvalidInput(
            "shared_secret must not be empty",
        ));
    }

    if info.is_empty() {
        return Err(CryptoError::InvalidInput("info must not be empty"));
    }

    let hkdf = Hkdf::<Sha256>::new(salt, shared_secret);
    let mut output_key_material = [0_u8; EXPANDED_KEY_MATERIAL_LEN];

    hkdf.expand(info, &mut output_key_material)
        .map_err(|_| CryptoError::Internal("hkdf expand failure"))?;

    let encryption_key = &output_key_material[..KEY_LEN_32];
    let authentication_key = &output_key_material[KEY_LEN_32..];

    let session_keys = SessionKeys::new(encryption_key, authentication_key)?;
    output_key_material.fill(0);

    Ok(session_keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_session_keys_returns_two_32_byte_keys() {
        let keys = derive_session_keys(
            b"0123456789abcdef0123456789abcdef",
            Some(b"test-salt"),
            b"IX-Operator Session Keys",
        )
        .expect("hkdf should derive session keys");

        assert_eq!(keys.encryption_key().len(), KEY_LEN_32);
        assert_eq!(keys.authentication_key().len(), KEY_LEN_32);
    }

    #[test]
    fn derive_session_keys_is_deterministic_for_same_inputs() {
        let keys_a = derive_session_keys(
            b"0123456789abcdef0123456789abcdef",
            Some(b"salt-a"),
            b"IX-Operator Session Keys",
        )
        .expect("hkdf should derive session keys");

        let keys_b = derive_session_keys(
            b"0123456789abcdef0123456789abcdef",
            Some(b"salt-a"),
            b"IX-Operator Session Keys",
        )
        .expect("hkdf should derive session keys");

        assert_eq!(keys_a.encryption_key(), keys_b.encryption_key());
        assert_eq!(keys_a.authentication_key(), keys_b.authentication_key());
    }

    #[test]
    fn derive_session_keys_rejects_empty_shared_secret() {
        let result = derive_session_keys(b"", Some(b"salt-a"), b"IX-Operator Session Keys");

        assert!(matches!(
            result,
            Err(CryptoError::InvalidInput("shared_secret must not be empty"))
        ));
    }

    #[test]
    fn derive_session_keys_rejects_empty_info() {
        let result = derive_session_keys(b"shared-secret", Some(b"salt-a"), b"");

        assert!(matches!(
            result,
            Err(CryptoError::InvalidInput("info must not be empty"))
        ));
    }
}
