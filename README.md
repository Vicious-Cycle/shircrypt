<div align="center">

# shircrypt

**A modern, memory-safe, `abi3` Rust cryptographic engine for Telegram MTProto 2.0 — built for [Shirdal](https://github.com/Vicious-Cycle/shirdal).**

**English** | [فارسی](README.fa.md)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Rust](https://img.shields.io/badge/rust-1.78+-000000.svg?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![PyPI](https://img.shields.io/pypi/v/shircrypt.svg?color=007ec6)](https://pypi.org/project/shircrypt/)
[![CI](https://github.com/Vicious-Cycle/shircrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/Vicious-Cycle/shirdal/actions/workflows/ci.yml)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL_v3-blue.svg)](LICENSE)

</div>

---

**shircrypt** replaces legacy C-based MTProto crypto extensions (like `TgCrypto`) with a tiny, self-contained **Rust + PyO3 (`abi3-py311`)** core. It compiles once for Python 3.11 through 3.15+, requires **zero C/OpenSSL system libraries**, leverages hardware **AES-NI** and **ARMv8 Crypto**, releases the **GIL** on large buffers, and wipes key material from RAM via `zeroize`.

## Architecture

```text
  Python Caller (bytes / bytearray / memoryview)
                       │
          shircrypt.__init__ (auto-select)
          ┌────────────┴────────────┐
          ▼                         ▼
   _shircrypt (Rust)        _fallback (Python)
  (PyO3 abi3-py311,       (cryptography backend
   AES-NI / ARMv8 CE,      when wheel is absent)
   zeroize, GIL-free)
```

## Why `shircrypt` over `TgCrypto`?

| Feature | `shircrypt` | `TgCrypto` | Pure Python |
| :--- | :--- | :--- | :--- |
| **Python ABI** | `abi3-py311` (one wheel for 3.11–3.15+) | Rebuilds required per Python version | Version-independent |
| **System Dependencies** | None (pure Rust crates) | C compiler + Python headers | None / OpenSSL |
| **Memory Safety & Key Wiping** | Memory-safe Rust + `zeroize` | Manual C pointers | Managed |
| **Hardware Acceleration** | AES-NI (x86_64) & ARMv8 Crypto (Termux/ARM64) | AES-NI / C loop | Slow block loop |
| **GIL Behavior** | Released for payloads `>= 4096` bytes | Released | Holds GIL |
| **MTProto 2.0 KDF** | Native `compute_msg_key` & `mtproto2_kdf` | Not included | Python `hashlib` |
| **Fallback Support** | Automatic `cryptography` fallback | Fails if not compiled | N/A |

## Installation

```bash
pip install shircrypt
```

If you want the optional fallback backend on unsupported platforms:

```bash
pip install "shircrypt[fallback]"
```

### Termux (Android)

You can use `shircrypt` on Termux in two ways:

1. **Instant install (via `cryptography` fallback, no Rust compile):**
```bash
pkg install -y python-cryptography
pip install --no-build-isolation --no-deps -e .
```

2. **Native Rust core (maximum speed with ARMv8 Crypto):**
```bash
pkg install -y rust binutils maturin
maturin develop --release
```

## Quickstart

```python
import os
import shircrypt

print("Active backend:", shircrypt.BACKEND)  # "rust" or "cryptography"

key = os.urandom(32)
iv_ige = os.urandom(32)
plaintext = b"0123456789abcdef" * 4

# AES-256-IGE (MTProto 2.0 packets)
ciphertext = shircrypt.ige256_encrypt(plaintext, key, iv_ige)
decrypted = shircrypt.ige256_decrypt(ciphertext, key, iv_ige)
assert decrypted == plaintext

# AES-256-CTR with byte-offset seeking (chunked file transfers)
iv_ctr = os.urandom(16)
stream_chunk = shircrypt.ctr256_crypt(b"chunk-data", key, iv_ctr, offset=1024)

# MTProto 2.0 Key Derivation
auth_key = os.urandom(256)
msg_key = shircrypt.compute_msg_key(auth_key, plaintext, from_client=True)
aes_key, aes_iv = shircrypt.mtproto2_kdf(auth_key, msg_key, from_client=True)
```

## Documentation

- [Architecture & Performance Design](docs/architecture.md)
- [API Reference](docs/api.md)
- [مستندات کامل فارسی](docs/fa/README.md)

## Running Tests & Benchmarks

```bash
python3 -m unittest discover -s tests -v
python3 benches/bench_shircrypt.py
```

## Security, Contributing & License

- Security vulnerabilities: [SECURITY.md](SECURITY.md)
- Contributing guidelines: [CONTRIBUTING.md](CONTRIBUTING.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- License: [LGPL-3.0-or-later](LICENSE)
