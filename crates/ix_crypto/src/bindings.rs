use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::aead::{
    decrypt_aes256_gcm, decrypt_chacha20_poly1305, encrypt_aes256_gcm,
    encrypt_chacha20_poly1305,
};
use crate::asymmetric::{
    generate_ed25519_keypair, generate_x25519_keypair, sign_ed25519, verify_ed25519,
    x25519_shared_secret,
};
use crate::error::CryptoError;
use crate::kdf::derive_session_keys;
use crate::rng::{random_nonce, random_secret};
use crate::types::{PublicBytes, SecretBytes, SignatureBytes, WireNonce};

fn map_crypto_error(error: CryptoError) -> PyErr {
    PyValueError::new_err(error.to_string())
}

fn to_pybytes(py: Python<'_>, value: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, value).into()
}

#[pyfunction]
fn random_bytes(py: Python<'_>, length: usize) -> PyResult<Py<PyBytes>> {
    let secret = random_secret(length).map_err(map_crypto_error)?;
    Ok(to_pybytes(py, secret.as_slice()))
}

#[pyfunction(name = "random_nonce")]
fn py_random_nonce(py: Python<'_>) -> PyResult<Py<PyBytes>> {
    let nonce = random_nonce().map_err(map_crypto_error)?;
    Ok(to_pybytes(py, nonce.as_bytes()))
}

#[pyfunction]
fn generate_x25519_keypair_py(py: Python<'_>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (private_key, public_key) = generate_x25519_keypair().map_err(map_crypto_error)?;
    Ok((
        to_pybytes(py, private_key.as_slice()),
        to_pybytes(py, public_key.as_slice()),
    ))
}

#[pyfunction]
fn generate_ed25519_keypair_py(py: Python<'_>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (private_key, public_key) = generate_ed25519_keypair().map_err(map_crypto_error)?;
    Ok((
        to_pybytes(py, private_key.as_slice()),
        to_pybytes(py, public_key.as_slice()),
    ))
}

#[pyfunction]
fn x25519_shared_secret_py(py: Python<'_>, private_key: &[u8], peer_public_key: &[u8]) -> PyResult<Py<PyBytes>> {
    let private_key = SecretBytes::from_slice(private_key);
    let peer_public_key = PublicBytes::from_slice(peer_public_key);

    let shared_secret =
        x25519_shared_secret(&private_key, &peer_public_key).map_err(map_crypto_error)?;
    Ok(to_pybytes(py, shared_secret.as_slice()))
}

#[pyfunction]
fn sign_ed25519_py(py: Python<'_>, secret_key: &[u8], message: &[u8]) -> PyResult<Py<PyBytes>> {
    let secret_key = SecretBytes::from_slice(secret_key);
    let signature = sign_ed25519(&secret_key, message).map_err(map_crypto_error)?;
    Ok(to_pybytes(py, signature.as_slice()))
}

#[pyfunction]
fn verify_ed25519_py(public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    let public_key = PublicBytes::from_slice(public_key);
    let signature = SignatureBytes::from_slice(signature);

    verify_ed25519(&public_key, message, &signature)
        .map(|_| true)
        .map_err(map_crypto_error)
}

#[pyfunction(name = "derive_session_keys")]
fn py_derive_session_keys(
    py: Python<'_>,
    shared_secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let session_keys =
        derive_session_keys(shared_secret, salt, info).map_err(map_crypto_error)?;
    Ok((
        to_pybytes(py, session_keys.encryption_key()),
        to_pybytes(py, session_keys.authentication_key()),
    ))
}

#[pyfunction]
fn encrypt_aes256_gcm_py(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<Py<PyBytes>> {
    let nonce = WireNonce::from_slice(nonce).map_err(map_crypto_error)?;
    let ciphertext =
        encrypt_aes256_gcm(key, &nonce, plaintext, aad).map_err(map_crypto_error)?;
    Ok(to_pybytes(py, &ciphertext))
}

#[pyfunction]
fn decrypt_aes256_gcm_py(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Py<PyBytes>> {
    let nonce = WireNonce::from_slice(nonce).map_err(map_crypto_error)?;
    let plaintext =
        decrypt_aes256_gcm(key, &nonce, ciphertext, aad).map_err(map_crypto_error)?;
    Ok(to_pybytes(py, &plaintext))
}

#[pyfunction]
fn encrypt_chacha20_poly1305_py(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<Py<PyBytes>> {
    let nonce = WireNonce::from_slice(nonce).map_err(map_crypto_error)?;
    let ciphertext =
        encrypt_chacha20_poly1305(key, &nonce, plaintext, aad).map_err(map_crypto_error)?;
    Ok(to_pybytes(py, &ciphertext))
}

#[pyfunction]
fn decrypt_chacha20_poly1305_py(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Py<PyBytes>> {
    let nonce = WireNonce::from_slice(nonce).map_err(map_crypto_error)?;
    let plaintext =
        decrypt_chacha20_poly1305(key, &nonce, ciphertext, aad).map_err(map_crypto_error)?;
    Ok(to_pybytes(py, &plaintext))
}

#[pymodule]
fn _ix_crypto_native(_py: Python<'_>, module: &PyModule) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;

    module.add_function(wrap_pyfunction!(random_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(py_random_nonce, module)?)?;
    module.add_function(wrap_pyfunction!(generate_x25519_keypair_py, module)?)?;
    module.add_function(wrap_pyfunction!(generate_ed25519_keypair_py, module)?)?;
    module.add_function(wrap_pyfunction!(x25519_shared_secret_py, module)?)?;
    module.add_function(wrap_pyfunction!(sign_ed25519_py, module)?)?;
    module.add_function(wrap_pyfunction!(verify_ed25519_py, module)?)?;
    module.add_function(wrap_pyfunction!(py_derive_session_keys, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt_aes256_gcm_py, module)?)?;
    module.add_function(wrap_pyfunction!(decrypt_aes256_gcm_py, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt_chacha20_poly1305_py, module)?)?;
    module.add_function(wrap_pyfunction!(decrypt_chacha20_poly1305_py, module)?)?;

    Ok(())
}
