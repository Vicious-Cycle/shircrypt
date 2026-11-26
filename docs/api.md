# API Reference

All functions accept `bytes`, `bytearray`, or `memoryview` and raise `ValueError` on invalid key/IV/alignment lengths.

## `shircrypt.BACKEND`
- Type: `Literal["rust", "cryptography"]`
- Indicates whether the native Rust extension (`_shircrypt`) or the pure-Python `cryptography` fallback is active.

## `ige256_encrypt(data, key, iv) -> bytes`
Encrypts `data` (length must be a multiple of 16) with AES-256-IGE using a 32-byte `key` and 32-byte `iv`.

## `ige256_decrypt(data, key, iv) -> bytes`
Decrypts `data` (length must be a multiple of 16) with AES-256-IGE using a 32-byte `key` and 32-byte `iv`.

## `ctr256_crypt(data, key, iv, offset=0) -> bytes`
Encrypts or decrypts `data` of arbitrary length with AES-256-CTR using a 32-byte `key` and 16-byte `iv`.
- `offset`: Byte offset in the keystream (useful for parallel chunked file transfers).

## `cbc256_encrypt(data, key, iv) -> bytes` / `cbc256_decrypt(data, key, iv) -> bytes`
Encrypts or decrypts `data` (length must be a multiple of 16) with AES-256-CBC using a 32-byte `key` and 16-byte `iv`.

## `compute_msg_key(auth_key, padded_plaintext, from_client=True) -> bytes`
Computes the 16-byte MTProto 2.0 `msg_key` from a 256-byte `auth_key` and `padded_plaintext`.

## `mtproto2_kdf(auth_key, msg_key, from_client=True) -> tuple[bytes, bytes]`
Derives `(aes_key, aes_iv)` (32 bytes each) according to the MTProto 2.0 key derivation specification.
