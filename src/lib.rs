use aes::cipher::{
    generic_array::GenericArray, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut,
    KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek,
};
use aes::Aes256;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use sha2::{Digest, Sha256};
use std::ops::Deref;
use zeroize::Zeroize;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

const GIL_RELEASE_THRESHOLD: usize = 4096;

#[inline]
fn xor16_into(dst: &mut [u8; 16], a: &[u8], b: &[u8]) {
    for i in 0..16 {
        dst[i] = a[i] ^ b[i];
    }
}

#[inline]
fn ct_eq_16(a: &[u8; 16], b: &[u8]) -> bool {
    if b.len() != 16 {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn validate_key(key: &[u8]) -> PyResult<()> {
    if key.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "AES-256 key must be 32 bytes, got {}",
            key.len()
        )));
    }
    Ok(())
}

fn validate_auth_key(auth_key: &[u8]) -> PyResult<()> {
    if auth_key.len() != 256 {
        return Err(PyValueError::new_err(format!(
            "auth_key must be 256 bytes, got {}",
            auth_key.len()
        )));
    }
    Ok(())
}

fn validate_ige_args(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<()> {
    validate_key(key)?;
    if iv.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "AES-256-IGE IV must be 32 bytes, got {}",
            iv.len()
        )));
    }
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err(format!(
            "AES-256-IGE data length must be a multiple of 16, got {}",
            data.len()
        )));
    }
    Ok(())
}

fn validate_cbc_args(data: &[u8], key: &[u8], iv: &[u8]) -> PyResult<()> {
    validate_key(key)?;
    if iv.len() != 16 {
        return Err(PyValueError::new_err(format!(
            "AES-256-CBC IV must be 16 bytes, got {}",
            iv.len()
        )));
    }
    if data.len() % 16 != 0 {
        return Err(PyValueError::new_err(format!(
            "AES-256-CBC data length must be a multiple of 16, got {}",
            data.len()
        )));
    }
    Ok(())
}

fn ige256_encrypt_core(data: &[u8], key: &[u8], iv: &[u8], out: &mut [u8]) {
    let mut key_arr = *GenericArray::from_slice(key);
    let cipher = Aes256::new(&key_arr);
    key_arr.zeroize();

    let mut iv_c = [0u8; 16];
    let mut iv_p = [0u8; 16];
    iv_c.copy_from_slice(&iv[..16]);
    iv_p.copy_from_slice(&iv[16..32]);

    let mut block = [0u8; 16];
    for (plain_chunk, out_chunk) in data.chunks_exact(16).zip(out.chunks_exact_mut(16)) {
        xor16_into(&mut block, plain_chunk, &iv_c);
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        for i in 0..16 {
            let c = block[i] ^ iv_p[i];
            out_chunk[i] = c;
            iv_c[i] = c;
            iv_p[i] = plain_chunk[i];
        }
    }
    iv_c.zeroize();
    iv_p.zeroize();
    block.zeroize();
}

fn ige256_decrypt_core(data: &[u8], key: &[u8], iv: &[u8], out: &mut [u8]) {
    let mut key_arr = *GenericArray::from_slice(key);
    let cipher = Aes256::new(&key_arr);
    key_arr.zeroize();

    let mut iv_c = [0u8; 16];
    let mut iv_p = [0u8; 16];
    iv_c.copy_from_slice(&iv[..16]);
    iv_p.copy_from_slice(&iv[16..32]);

    let mut block = [0u8; 16];
    for (cipher_chunk, out_chunk) in data.chunks_exact(16).zip(out.chunks_exact_mut(16)) {
        xor16_into(&mut block, cipher_chunk, &iv_p);
        cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
        for i in 0..16 {
            let p = block[i] ^ iv_c[i];
            out_chunk[i] = p;
            iv_c[i] = cipher_chunk[i];
            iv_p[i] = p;
        }
    }
    iv_c.zeroize();
    iv_p.zeroize();
    block.zeroize();
}

fn ctr256_crypt_core(data: &[u8], key: &[u8], iv: &[u8], offset: u64, out: &mut [u8]) {
    out.copy_from_slice(data);
    let mut cipher = Aes256Ctr::new_from_slices(key, iv).expect("validated key and iv");
    if offset > 0 {
        cipher.seek(offset);
    }
    cipher.apply_keystream(out);
}

fn cbc256_encrypt_core(data: &[u8], key: &[u8], iv: &[u8], out: &mut [u8]) {
    out.copy_from_slice(data);
    let mut enc = Aes256CbcEnc::new_from_slices(key, iv).expect("validated key and iv");
    for chunk in out.chunks_exact_mut(16) {
        enc.encrypt_block_mut(GenericArray::from_mut_slice(chunk));
    }
}

fn cbc256_decrypt_core(data: &[u8], key: &[u8], iv: &[u8], out: &mut [u8]) {
    out.copy_from_slice(data);
    let mut dec = Aes256CbcDec::new_from_slices(key, iv).expect("validated key and iv");
    let mut blocks = [GenericArray::default(); 8];
    let mut chunks = out.chunks_exact_mut(128);
    for chunk in &mut chunks {
        for (b, c) in blocks.iter_mut().zip(chunk.chunks_exact(16)) {
            b.copy_from_slice(c);
        }
        dec.decrypt_blocks_mut(&mut blocks);
        for (b, c) in blocks.iter().zip(chunk.chunks_exact_mut(16)) {
            c.copy_from_slice(b);
        }
    }
    for rem in chunks.into_remainder().chunks_exact_mut(16) {
        dec.decrypt_block_mut(GenericArray::from_mut_slice(rem));
    }
}

fn compute_msg_key_core(auth_key: &[u8], padded_plaintext: &[u8], from_client: bool) -> [u8; 16] {
    let x = if from_client { 0 } else { 8 };
    let mut hasher = Sha256::new();
    hasher.update(&auth_key[88 + x..88 + x + 32]);
    hasher.update(padded_plaintext);
    let digest = hasher.finalize();
    let mut msg_key = [0u8; 16];
    msg_key.copy_from_slice(&digest[8..24]);
    msg_key
}

fn mtproto2_kdf_core(auth_key: &[u8], msg_key: &[u8], from_client: bool) -> ([u8; 32], [u8; 32]) {
    let x = if from_client { 0 } else { 8 };

    let mut ha = Sha256::new();
    ha.update(msg_key);
    ha.update(&auth_key[x..x + 36]);
    let mut sha_a = ha.finalize();

    let mut hb = Sha256::new();
    hb.update(&auth_key[40 + x..40 + x + 36]);
    hb.update(msg_key);
    let mut sha_b = hb.finalize();

    let mut aes_key = [0u8; 32];
    aes_key[0..8].copy_from_slice(&sha_a[0..8]);
    aes_key[8..24].copy_from_slice(&sha_b[8..24]);
    aes_key[24..32].copy_from_slice(&sha_a[24..32]);

    let mut aes_iv = [0u8; 32];
    aes_iv[0..8].copy_from_slice(&sha_b[0..8]);
    aes_iv[8..24].copy_from_slice(&sha_a[8..24]);
    aes_iv[24..32].copy_from_slice(&sha_b[24..32]);

    sha_a.zeroize();
    sha_b.zeroize();
    (aes_key, aes_iv)
}

/// Input buffer accepting `bytes`, `bytearray`, `memoryview` and any other
/// C-contiguous byte buffer. `bytes` is borrowed zero-copy; other buffer
/// types are copied once (and wiped on drop, since they may hold key material).
enum Buf<'py> {
    Bytes(Bound<'py, PyBytes>),
    Owned(Vec<u8>),
}

impl<'py> FromPyObject<'py> for Buf<'py> {
    fn extract_bound(ob: &Bound<'py, PyAny>) -> PyResult<Self> {
        if let Ok(b) = ob.downcast::<PyBytes>() {
            return Ok(Buf::Bytes(b.clone()));
        }
        let buf: PyBuffer<u8> = PyBuffer::get_bound(ob)?;
        if !buf.is_c_contiguous() {
            return Err(PyValueError::new_err("buffer must be C-contiguous"));
        }
        Ok(Buf::Owned(buf.to_vec(ob.py())?))
    }
}

impl Deref for Buf<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Buf::Bytes(b) => b.as_bytes(),
            Buf::Owned(v) => v.as_slice(),
        }
    }
}

impl Drop for Buf<'_> {
    fn drop(&mut self) {
        if let Buf::Owned(v) = self {
            v.zeroize();
        }
    }
}

#[pyfunction]
fn ige256_encrypt<'py>(
    py: Python<'py>,
    data: Buf<'py>,
    key: Buf<'py>,
    iv: Buf<'py>,
) -> PyResult<Bound<'py, PyBytes>> {
    let data: &[u8] = &data;
    let key: &[u8] = &key;
    let iv: &[u8] = &iv;
    validate_ige_args(data, key, iv)?;
    PyBytes::new_bound_with(py, data.len(), |out| {
        if data.len() >= GIL_RELEASE_THRESHOLD {
            py.allow_threads(|| ige256_encrypt_core(data, key, iv, out));
        } else {
            ige256_encrypt_core(data, key, iv, out);
        }
        Ok(())
    })
}

#[pyfunction]
fn ige256_decrypt<'py>(
    py: Python<'py>,
    data: Buf<'py>,
    key: Buf<'py>,
    iv: Buf<'py>,
) -> PyResult<Bound<'py, PyBytes>> {
    let data: &[u8] = &data;
    let key: &[u8] = &key;
    let iv: &[u8] = &iv;
    validate_ige_args(data, key, iv)?;
    PyBytes::new_bound_with(py, data.len(), |out| {
        if data.len() >= GIL_RELEASE_THRESHOLD {
            py.allow_threads(|| ige256_decrypt_core(data, key, iv, out));
        } else {
            ige256_decrypt_core(data, key, iv, out);
        }
        Ok(())
    })
}

#[pyfunction]
#[pyo3(signature = (data, key, iv, offset = 0))]
fn ctr256_crypt<'py>(
    py: Python<'py>,
    data: Buf<'py>,
    key: Buf<'py>,
    iv: Buf<'py>,
    offset: u64,
) -> PyResult<Bound<'py, PyBytes>> {
    let data: &[u8] = &data;
    let key: &[u8] = &key;
    let iv: &[u8] = &iv;
    validate_key(key)?;
    if iv.len() != 16 {
        return Err(PyValueError::new_err(format!(
            "AES-256-CTR IV must be 16 bytes, got {}",
            iv.len()
        )));
    }
    PyBytes::new_bound_with(py, data.len(), |out| {
        if data.len() >= GIL_RELEASE_THRESHOLD {
            py.allow_threads(|| ctr256_crypt_core(data, key, iv, offset, out));
        } else {
            ctr256_crypt_core(data, key, iv, offset, out);
        }
        Ok(())
    })
}

#[pyfunction]
fn cbc256_encrypt<'py>(
    py: Python<'py>,
    data: Buf<'py>,
    key: Buf<'py>,
    iv: Buf<'py>,
) -> PyResult<Bound<'py, PyBytes>> {
    let data: &[u8] = &data;
    let key: &[u8] = &key;
    let iv: &[u8] = &iv;
    validate_cbc_args(data, key, iv)?;
    PyBytes::new_bound_with(py, data.len(), |out| {
        if data.len() >= GIL_RELEASE_THRESHOLD {
            py.allow_threads(|| cbc256_encrypt_core(data, key, iv, out));
        } else {
            cbc256_encrypt_core(data, key, iv, out);
        }
        Ok(())
    })
}

#[pyfunction]
fn cbc256_decrypt<'py>(
    py: Python<'py>,
    data: Buf<'py>,
    key: Buf<'py>,
    iv: Buf<'py>,
) -> PyResult<Bound<'py, PyBytes>> {
    let data: &[u8] = &data;
    let key: &[u8] = &key;
    let iv: &[u8] = &iv;
    validate_cbc_args(data, key, iv)?;
    PyBytes::new_bound_with(py, data.len(), |out| {
        if data.len() >= GIL_RELEASE_THRESHOLD {
            py.allow_threads(|| cbc256_decrypt_core(data, key, iv, out));
        } else {
            cbc256_decrypt_core(data, key, iv, out);
        }
        Ok(())
    })
}

#[pyfunction]
#[pyo3(signature = (auth_key, padded_plaintext, from_client = true))]
fn compute_msg_key<'py>(
    py: Python<'py>,
    auth_key: Buf<'py>,
    padded_plaintext: Buf<'py>,
    from_client: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let auth_key: &[u8] = &auth_key;
    let padded_plaintext: &[u8] = &padded_plaintext;
    validate_auth_key(auth_key)?;
    let msg_key = if padded_plaintext.len() >= GIL_RELEASE_THRESHOLD {
        py.allow_threads(|| compute_msg_key_core(auth_key, padded_plaintext, from_client))
    } else {
        compute_msg_key_core(auth_key, padded_plaintext, from_client)
    };
    Ok(PyBytes::new_bound(py, &msg_key))
}

#[pyfunction]
#[pyo3(signature = (auth_key, msg_key, from_client = true))]
fn mtproto2_kdf<'py>(
    py: Python<'py>,
    auth_key: Buf<'py>,
    msg_key: Buf<'py>,
    from_client: bool,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let auth_key: &[u8] = &auth_key;
    let msg_key: &[u8] = &msg_key;
    validate_auth_key(auth_key)?;
    if msg_key.len() != 16 {
        return Err(PyValueError::new_err(format!(
            "msg_key must be 16 bytes, got {}",
            msg_key.len()
        )));
    }
    let (mut aes_key, mut aes_iv) = mtproto2_kdf_core(auth_key, msg_key, from_client);
    let key_py = PyBytes::new_bound(py, &aes_key);
    let iv_py = PyBytes::new_bound(py, &aes_iv);
    aes_key.zeroize();
    aes_iv.zeroize();
    Ok((key_py, iv_py))
}

/// Fused MTProto 2.0 packet encryption: computes `msg_key`, runs `mtproto2_kdf`
/// without exposing `aes_key`/`aes_iv` to Python heap, and encrypts via AES-256-IGE.
#[pyfunction]
#[pyo3(signature = (auth_key, padded_plaintext, from_client = true))]
fn mtproto2_encrypt_packet<'py>(
    py: Python<'py>,
    auth_key: Buf<'py>,
    padded_plaintext: Buf<'py>,
    from_client: bool,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let auth_key: &[u8] = &auth_key;
    let padded_plaintext: &[u8] = &padded_plaintext;
    validate_auth_key(auth_key)?;
    if padded_plaintext.len() % 16 != 0 {
        return Err(PyValueError::new_err(format!(
            "MTProto 2.0 padded_plaintext length must be a multiple of 16, got {}",
            padded_plaintext.len()
        )));
    }
    let mut msg_key = [0u8; 16];
    let ciphertext = PyBytes::new_bound_with(py, padded_plaintext.len(), |out| {
        let mut run = || {
            msg_key = compute_msg_key_core(auth_key, padded_plaintext, from_client);
            let (mut aes_key, mut aes_iv) = mtproto2_kdf_core(auth_key, &msg_key, from_client);
            ige256_encrypt_core(padded_plaintext, &aes_key, &aes_iv, out);
            aes_key.zeroize();
            aes_iv.zeroize();
        };
        if padded_plaintext.len() >= GIL_RELEASE_THRESHOLD {
            py.allow_threads(run);
        } else {
            run();
        }
        Ok(())
    })?;
    Ok((PyBytes::new_bound(py, &msg_key), ciphertext))
}

/// Fused MTProto 2.0 packet decryption: runs `mtproto2_kdf` in Rust stack memory,
/// decrypts via AES-256-IGE, and verifies `msg_key` in constant time before returning plaintext.
#[pyfunction]
#[pyo3(signature = (auth_key, msg_key, ciphertext, from_client = false))]
fn mtproto2_decrypt_packet<'py>(
    py: Python<'py>,
    auth_key: Buf<'py>,
    msg_key: Buf<'py>,
    ciphertext: Buf<'py>,
    from_client: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let auth_key: &[u8] = &auth_key;
    let msg_key: &[u8] = &msg_key;
    let ciphertext: &[u8] = &ciphertext;
    validate_auth_key(auth_key)?;
    if msg_key.len() != 16 {
        return Err(PyValueError::new_err(format!(
            "msg_key must be 16 bytes, got {}",
            msg_key.len()
        )));
    }
    if ciphertext.len() % 16 != 0 {
        return Err(PyValueError::new_err(format!(
            "MTProto 2.0 ciphertext length must be a multiple of 16, got {}",
            ciphertext.len()
        )));
    }
    PyBytes::new_bound_with(py, ciphertext.len(), |out| {
        let mut valid = false;
        let mut run = || {
            let (mut aes_key, mut aes_iv) = mtproto2_kdf_core(auth_key, msg_key, from_client);
            ige256_decrypt_core(ciphertext, &aes_key, &aes_iv, out);
            aes_key.zeroize();
            aes_iv.zeroize();
            let expected = compute_msg_key_core(auth_key, out, from_client);
            valid = ct_eq_16(&expected, msg_key);
        };
        if ciphertext.len() >= GIL_RELEASE_THRESHOLD {
            py.allow_threads(run);
        } else {
            run();
        }
        if !valid {
            out.zeroize();
            return Err(PyValueError::new_err("MTProto 2.0 msg_key verification failed"));
        }
        Ok(())
    })
}

#[pymodule]
fn _shircrypt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(ige256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ige256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr256_crypt, m)?)?;
    m.add_function(wrap_pyfunction!(cbc256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(cbc256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(compute_msg_key, m)?)?;
    m.add_function(wrap_pyfunction!(mtproto2_kdf, m)?)?;
    m.add_function(wrap_pyfunction!(mtproto2_encrypt_packet, m)?)?;
    m.add_function(wrap_pyfunction!(mtproto2_decrypt_packet, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ige_roundtrip() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 32];
        let plain = b"0123456789abcdefFEDCBA9876543210";
        let mut ct = vec![0u8; plain.len()];
        let mut pt = vec![0u8; plain.len()];
        ige256_encrypt_core(plain, &key, &iv, &mut ct);
        assert_ne!(&ct[..], plain);
        ige256_decrypt_core(&ct, &key, &iv, &mut pt);
        assert_eq!(&pt[..], plain);
    }

    #[test]
    fn test_ctr_roundtrip_with_offset() {
        let key = [0x33u8; 32];
        let iv = [0x44u8; 16];
        let plain = b"Hello MTProto 2.0 CTR streaming!";
        let mut ct = vec![0u8; plain.len()];
        let mut pt = vec![0u8; plain.len()];
        ctr256_crypt_core(plain, &key, &iv, 17, &mut ct);
        ctr256_crypt_core(&ct, &key, &iv, 17, &mut pt);
        assert_eq!(&pt[..], plain);
    }

    #[test]
    fn test_cbc_roundtrip_multiblock() {
        let key = [0x55u8; 32];
        let iv = [0x66u8; 16];
        // 304 bytes = 2x 128-byte batches + 48-byte remainder
        let plain = vec![0xABu8; 304];
        let mut ct = vec![0u8; plain.len()];
        let mut pt = vec![0u8; plain.len()];
        cbc256_encrypt_core(&plain, &key, &iv, &mut ct);
        assert_ne!(ct, plain);
        cbc256_decrypt_core(&ct, &key, &iv, &mut pt);
        assert_eq!(pt, plain);
    }

    #[test]
    fn test_mtproto2_packet_roundtrip() {
        let auth_key = [0x77u8; 256];
        let plain = vec![0xCDu8; 128];
        for from_client in [true, false] {
            let mk = compute_msg_key_core(&auth_key, &plain, from_client);
            let (k, iv) = mtproto2_kdf_core(&auth_key, &mk, from_client);
            let mut ct = vec![0u8; plain.len()];
            let mut pt = vec![0u8; plain.len()];
            ige256_encrypt_core(&plain, &k, &iv, &mut ct);
            ige256_decrypt_core(&ct, &k, &iv, &mut pt);
            assert_eq!(pt, plain);
            let mk_check = compute_msg_key_core(&auth_key, &pt, from_client);
            assert!(ct_eq_16(&mk_check, &mk));
        }
    }
}
