use core::fmt;

use crate::error::CryptoError;
use crate::traits::Wipe;

pub const KEY_LEN_32: usize = 32;
pub const NONCE_LEN_12: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmId {
    X25519,
    Ed25519,
    HkdfSha256,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AlgorithmId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X25519 => "x25519",
            Self::Ed25519 => "ed25519",
            Self::HkdfSha256 => "hkdf-sha256",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PublicBytes {
    inner: Vec<u8>,
}

impl PublicBytes {
    pub fn from_slice(input: &[u8]) -> Self {
        Self {
            inner: input.to_vec(),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for PublicBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicBytes")
            .field("len", &self.inner.len())
            .finish()
    }
}

pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    pub fn from_slice(input: &[u8]) -> Self {
        Self {
            inner: input.to_vec(),
        }
    }

    pub fn from_exact(input: &[u8], expected_len: usize) -> Result<Self, CryptoError> {
        if input.len() != expected_len {
            return Err(CryptoError::InvalidKeyLength {
                expected: expected_len,
                actual: input.len(),
            });
        }

        Ok(Self::from_slice(input))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(REDACTED)")
    }
}

impl Wipe for SecretBytes {
    fn wipe(&mut self) {
        self.inner.wipe();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub struct WireNonce {
    inner: [u8; NONCE_LEN_12],
}

impl WireNonce {
    pub fn from_slice(input: &[u8]) -> Result<Self, CryptoError> {
        if input.len() != NONCE_LEN_12 {
            return Err(CryptoError::InvalidNonceLength {
                expected: NONCE_LEN_12,
                actual: input.len(),
            });
        }

        let mut inner = [0_u8; NONCE_LEN_12];
        inner.copy_from_slice(input);
        Ok(Self { inner })
    }

    pub fn as_bytes(&self) -> &[u8; NONCE_LEN_12] {
        &self.inner
    }
}

impl fmt::Debug for WireNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireNonce").finish()
    }
}

pub struct SessionKeys {
    encryption_key: SecretBytes,
    authentication_key: SecretBytes,
}

impl SessionKeys {
    pub fn new(
        encryption_key: &[u8],
        authentication_key: &[u8],
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            encryption_key: SecretBytes::from_exact(encryption_key, KEY_LEN_32)?,
            authentication_key: SecretBytes::from_exact(authentication_key, KEY_LEN_32)?,
        })
    }

    pub fn encryption_key(&self) -> &[u8] {
        self.encryption_key.as_slice()
    }

    pub fn authentication_key(&self) -> &[u8] {
        self.authentication_key.as_slice()
    }
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKeys(REDACTED)")
    }
}

impl Wipe for SessionKeys {
    fn wipe(&mut self) {
        self.encryption_key.wipe();
        self.authentication_key.wipe();
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.wipe();
    }
}
