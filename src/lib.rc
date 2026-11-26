use aes::cipher::{
    generic_array::GenericArray, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut,
    KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek,
};
use aes::Aes256;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::buffer::PyBuffer;
use pyo3::types::PyBytes;
use std::ops::Deref;
use sha2::{Digest, Sha256};
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

fn validate_key(key: &[u8]) -> PyResult<()> {
    if key.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "AES-256 key must be 32 bytes, got {}",
            key.len()
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
        out.copy_from_slice(data);
        let mut run = || {
            let mut enc = Aes256CbcEnc::new_from_slices(key, iv).expect("validated key and iv");
            for chunk in out.chunks_exact_mut(16) {
                enc.encrypt_block_mut(GenericArray::from_mut_slice(chunk));
            }
        };
        if data.len() >= GIL_RELEASE_THRESHOLD {
            py.allow_threads(run);
        } else {
            run();
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
        out.copy_from_slice(data);
        let mut run = || {
            let mut dec = Aes256CbcDec::new_from_slices(key, iv).expect("validated key and iv");
            for chunk in out.chunks_exact_mut(16) {
                dec.decrypt_block_mut(GenericArray::from_mut_slice(chunk));
            }
        };
        if data.len() >= GIL_RELEASE_THRESHOLD {
            py.allow_threads(run);
        } else {
            run();
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
    if auth_key.len() != 256 {
        return Err(PyValueError::new_err(format!(
            "auth_key must be 256 bytes, got {}",
            auth_key.len()
        )));
    }
    let x = if from_client { 0 } else { 8 };
    let mut hasher = Sha256::new();
    hasher.update(&auth_key[88 + x..88 + x + 32]);
    hasher.update(padded_plaintext);
    let digest = hasher.finalize();
    Ok(PyBytes::new_bound(py, &digest[8..24]))
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
    if auth_key.len() != 256 {
        return Err(PyValueError::new_err(format!(
            "auth_key must be 256 bytes, got {}",
            auth_key.len()
        )));
    }
    if msg_key.len() != 16 {
        return Err(PyValueError::new_err(format!(
            "msg_key must be 16 bytes, got {}",
            msg_key.len()
        )));
    }
    let x = if from_client { 0 } else { 8 };

    let mut ha = Sha256::new();
    ha.update(msg_key);
    ha.update(&auth_key[x..x + 36]);
    let sha_a = ha.finalize();

    let mut hb = Sha256::new();
    hb.update(&auth_key[40 + x..40 + x + 36]);
    hb.update(msg_key);
    let sha_b = hb.finalize();

    let mut aes_key = [0u8; 32];
    aes_key[0..8].copy_from_slice(&sha_a[0..8]);
    aes_key[8..24].copy_from_slice(&sha_b[8..24]);
    aes_key[24..32].copy_from_slice(&sha_a[24..32]);

    let mut aes_iv = [0u8; 32];
    aes_iv[0..8].copy_from_slice(&sha_b[0..8]);
    aes_iv[8..24].copy_from_slice(&sha_a[8..24]);
    aes_iv[24..32].copy_from_slice(&sha_b[24..32]);

    let key_py = PyBytes::new_bound(py, &aes_key);
    let iv_py = PyBytes::new_bound(py, &aes_iv);
    aes_key.zeroize();
    aes_iv.zeroize();
    Ok((key_py, iv_py))
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
}
