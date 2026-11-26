"""Fallback backends for shircrypt: cryptography (preferred) or pure-Python AES-256."""

from __future__ import annotations

import hashlib

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    _HAS_CRYPTOGRAPHY = True
except Exception:  # ImportError or broken _cffi_backend on Termux
    _HAS_CRYPTOGRAPHY = False

# --- Pure-Python AES-256 (used only when neither Rust nor cryptography is available) ---
_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
_INV_SBOX = tuple(_SBOX.index(i) for i in range(256))
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40)


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _mul(a: int, b: int) -> int:
    res = 0
    while b:
        if b & 1:
            res ^= a
        a = _xtime(a)
        b >>= 1
    return res


def _expand_key_256(key: bytes) -> list[list[int]]:
    w = [list(key[i : i + 4]) for i in range(0, 32, 4)]
    for i in range(8, 60):
        t = list(w[i - 1])
        if i % 8 == 0:
            t = [_SBOX[t[1]] ^ _RCON[i // 8 - 1], _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
        elif i % 8 == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    return [sum(w[r * 4 : (r + 1) * 4], []) for r in range(15)]


def _aes256_encrypt_block(rk: list[list[int]], block: bytes) -> bytes:
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, 15):
        s = [_SBOX[b] for b in s]
        # ShiftRows (column-major)
        s = [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11],
        ]
        if rnd < 14:
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
                t = a0 ^ a1 ^ a2 ^ a3
                s[c] ^= t ^ _xtime(a0 ^ a1)
                s[c + 1] ^= t ^ _xtime(a1 ^ a2)
                s[c + 2] ^= t ^ _xtime(a2 ^ a3)
                s[c + 3] ^= t ^ _xtime(a3 ^ a0)
        k = rk[rnd]
        s = [s[i] ^ k[i] for i in range(16)]
    return bytes(s)


def _aes256_decrypt_block(rk: list[list[int]], block: bytes) -> bytes:
    s = [block[i] ^ rk[14][i] for i in range(16)]
    for rnd in range(13, -1, -1):
        # InvShiftRows
        s = [
            s[0], s[13], s[10], s[7],
            s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15],
            s[12], s[9], s[6], s[3],
        ]
        s = [_INV_SBOX[b] for b in s]
        k = rk[rnd]
        s = [s[i] ^ k[i] for i in range(16)]
        if rnd > 0:
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
                s[c] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
                s[c + 1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
                s[c + 2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
                s[c + 3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)
    return bytes(s)


def _validate_key(key: bytes | bytearray | memoryview) -> bytes:
    k = bytes(key)
    if len(k) != 32:
        raise ValueError(f"AES-256 key must be 32 bytes, got {len(k)}")
    return k


def _xor16(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(16, "big")


def ige256_encrypt(
    data: bytes | bytearray | memoryview,
    key: bytes | bytearray | memoryview,
    iv: bytes | bytearray | memoryview,
) -> bytes:
    k = _validate_key(key)
    iv_b = bytes(iv)
    if len(iv_b) != 32:
        raise ValueError(f"AES-256-IGE IV must be 32 bytes, got {len(iv_b)}")
    buf = bytes(data)
    if len(buf) % 16 != 0:
        raise ValueError(f"AES-256-IGE data length must be a multiple of 16, got {len(buf)}")

    iv_c = iv_b[:16]
    iv_p = iv_b[16:]
    out = bytearray(len(buf))
    if _HAS_CRYPTOGRAPHY:
        encryptor = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
        enc_block = encryptor.update
    else:
        rk = _expand_key_256(k)
        enc_block = lambda b: _aes256_encrypt_block(rk, b)

    for offset in range(0, len(buf), 16):
        plain_block = buf[offset : offset + 16]
        enc = enc_block(_xor16(plain_block, iv_c))
        cipher_block = _xor16(enc, iv_p)
        out[offset : offset + 16] = cipher_block
        iv_c = cipher_block
        iv_p = plain_block
    if _HAS_CRYPTOGRAPHY:
        encryptor.finalize()
    return bytes(out)


def ige256_decrypt(
    data: bytes | bytearray | memoryview,
    key: bytes | bytearray | memoryview,
    iv: bytes | bytearray | memoryview,
) -> bytes:
    k = _validate_key(key)
    iv_b = bytes(iv)
    if len(iv_b) != 32:
        raise ValueError(f"AES-256-IGE IV must be 32 bytes, got {len(iv_b)}")
    buf = bytes(data)
    if len(buf) % 16 != 0:
        raise ValueError(f"AES-256-IGE data length must be a multiple of 16, got {len(buf)}")

    iv_c = iv_b[:16]
    iv_p = iv_b[16:]
    out = bytearray(len(buf))
    if _HAS_CRYPTOGRAPHY:
        decryptor = Cipher(algorithms.AES(k), modes.ECB()).decryptor()
        dec_block = decryptor.update
    else:
        rk = _expand_key_256(k)
        dec_block = lambda b: _aes256_decrypt_block(rk, b)

    for offset in range(0, len(buf), 16):
        cipher_block = buf[offset : offset + 16]
        dec = dec_block(_xor16(cipher_block, iv_p))
        plain_block = _xor16(dec, iv_c)
        out[offset : offset + 16] = plain_block
        iv_c = cipher_block
        iv_p = plain_block
    if _HAS_CRYPTOGRAPHY:
        decryptor.finalize()
    return bytes(out)


def ctr256_crypt(
    data: bytes | bytearray | memoryview,
    key: bytes | bytearray | memoryview,
    iv: bytes | bytearray | memoryview,
    offset: int = 0,
) -> bytes:
    k = _validate_key(key)
    iv_b = bytes(iv)
    if len(iv_b) != 16:
        raise ValueError(f"AES-256-CTR IV must be 16 bytes, got {len(iv_b)}")
    if offset < 0:
        raise ValueError(f"offset must be non-negative, got {offset}")
    buf = bytes(data)
    if not buf:
        return b""

    block_index, byte_offset = divmod(offset, 16)
    counter_int = (int.from_bytes(iv_b, "big") + block_index) % (1 << 128)
    if _HAS_CRYPTOGRAPHY:
        adjusted_iv = counter_int.to_bytes(16, "big")
        encryptor = Cipher(algorithms.AES(k), modes.CTR(adjusted_iv)).encryptor()
        if byte_offset:
            encryptor.update(b"\x00" * byte_offset)
        return encryptor.update(buf) + encryptor.finalize()

    rk = _expand_key_256(k)
    out = bytearray(len(buf))
    pos = 0
    while pos < len(buf):
        ks = _aes256_encrypt_block(rk, counter_int.to_bytes(16, "big"))
        counter_int = (counter_int + 1) % (1 << 128)
        take = min(16 - byte_offset, len(buf) - pos)
        for i in range(take):
            out[pos + i] = buf[pos + i] ^ ks[byte_offset + i]
        pos += take
        byte_offset = 0
    return bytes(out)


def cbc256_encrypt(
    data: bytes | bytearray | memoryview,
    key: bytes | bytearray | memoryview,
    iv: bytes | bytearray | memoryview,
) -> bytes:
    k = _validate_key(key)
    iv_b = bytes(iv)
    if len(iv_b) != 16:
        raise ValueError(f"AES-256-CBC IV must be 16 bytes, got {len(iv_b)}")
    buf = bytes(data)
    if len(buf) % 16 != 0:
        raise ValueError(f"AES-256-CBC data length must be a multiple of 16, got {len(buf)}")
    if _HAS_CRYPTOGRAPHY:
        enc = Cipher(algorithms.AES(k), modes.CBC(iv_b)).encryptor()
        return enc.update(buf) + enc.finalize()

    rk = _expand_key_256(k)
    prev = iv_b
    out = bytearray(len(buf))
    for offset in range(0, len(buf), 16):
        c = _aes256_encrypt_block(rk, _xor16(buf[offset : offset + 16], prev))
        out[offset : offset + 16] = c
        prev = c
    return bytes(out)


def cbc256_decrypt(
    data: bytes | bytearray | memoryview,
    key: bytes | bytearray | memoryview,
    iv: bytes | bytearray | memoryview,
) -> bytes:
    k = _validate_key(key)
    iv_b = bytes(iv)
    if len(iv_b) != 16:
        raise ValueError(f"AES-256-CBC IV must be 16 bytes, got {len(iv_b)}")
    buf = bytes(data)
    if len(buf) % 16 != 0:
        raise ValueError(f"AES-256-CBC data length must be a multiple of 16, got {len(buf)}")
    if _HAS_CRYPTOGRAPHY:
        dec = Cipher(algorithms.AES(k), modes.CBC(iv_b)).decryptor()
        return dec.update(buf) + dec.finalize()

    rk = _expand_key_256(k)
    prev = iv_b
    out = bytearray(len(buf))
    for offset in range(0, len(buf), 16):
        blk = buf[offset : offset + 16]
        out[offset : offset + 16] = _xor16(_aes256_decrypt_block(rk, blk), prev)
        prev = blk
    return bytes(out)


def compute_msg_key(
    auth_key: bytes | bytearray | memoryview,
    padded_plaintext: bytes | bytearray | memoryview,
    from_client: bool = True,
) -> bytes:
    ak = bytes(auth_key)
    if len(ak) != 256:
        raise ValueError(f"auth_key must be 256 bytes, got {len(ak)}")
    x = 0 if from_client else 8
    digest = hashlib.sha256(ak[88 + x : 88 + x + 32] + bytes(padded_plaintext)).digest()
    return digest[8:24]


def mtproto2_kdf(
    auth_key: bytes | bytearray | memoryview,
    msg_key: bytes | bytearray | memoryview,
    from_client: bool = True,
) -> tuple[bytes, bytes]:
    ak = bytes(auth_key)
    mk = bytes(msg_key)
    if len(ak) != 256:
        raise ValueError(f"auth_key must be 256 bytes, got {len(ak)}")
    if len(mk) != 16:
        raise ValueError(f"msg_key must be 16 bytes, got {len(mk)}")
    x = 0 if from_client else 8
    sha_a = hashlib.sha256(mk + ak[x : x + 36]).digest()
    sha_b = hashlib.sha256(ak[40 + x : 40 + x + 36] + mk).digest()
    aes_key = sha_a[0:8] + sha_b[8:24] + sha_a[24:32]
    aes_iv = sha_b[0:8] + sha_a[8:24] + sha_b[24:32]
    return aes_key, aes_iv
import hmac as _hmac


def mtproto2_encrypt_packet(
    auth_key: bytes | bytearray | memoryview,
    padded_plaintext: bytes | bytearray | memoryview,
    from_client: bool = True,
) -> tuple[bytes, bytes]:
    mk = compute_msg_key(auth_key, padded_plaintext, from_client=from_client)
    aes_key, aes_iv = mtproto2_kdf(auth_key, mk, from_client=from_client)
    return mk, ige256_encrypt(padded_plaintext, aes_key, aes_iv)


def mtproto2_decrypt_packet(
    auth_key: bytes | bytearray | memoryview,
    msg_key: bytes | bytearray | memoryview,
    ciphertext: bytes | bytearray | memoryview,
    from_client: bool = False,
) -> bytes:
    aes_key, aes_iv = mtproto2_kdf(auth_key, msg_key, from_client=from_client)
    plaintext = ige256_decrypt(ciphertext, aes_key, aes_iv)
    expected = compute_msg_key(auth_key, plaintext, from_client=from_client)
    if not _hmac.compare_digest(expected, bytes(msg_key)):
        raise ValueError("MTProto 2.0 msg_key verification failed")
    return plaintext
