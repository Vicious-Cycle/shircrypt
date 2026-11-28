"""shircrypt — Modern, memory-safe, `abi3` Rust cryptographic extension for MTProto 2.0."""

from __future__ import annotations

try:
    from shircrypt._shircrypt import (
        NativeAuthKey,
        __version__,
        cbc256_decrypt,
        cbc256_encrypt,
        compute_msg_key,
        ctr256_crypt,
        factorize_pq,
        ige256_decrypt,
        ige256_encrypt,
        mtproto2_decrypt_packet,
        mtproto2_encrypt_packet,
        mtproto2_kdf,
    )

    BACKEND = "rust"
except ImportError:  # pragma: no cover - fallback when native wheel is not built
    from shircrypt._fallback import (
        _HAS_CRYPTOGRAPHY,
        NativeAuthKey,
        cbc256_decrypt,
        cbc256_encrypt,
        compute_msg_key,
        ctr256_crypt,
        factorize_pq,
        ige256_decrypt,
        ige256_encrypt,
        mtproto2_decrypt_packet,
        mtproto2_encrypt_packet,
        mtproto2_kdf,
    )

    __version__ = "1.1.0"
    BACKEND = "cryptography" if _HAS_CRYPTOGRAPHY else "pure-python"

__all__ = [
    "BACKEND",
    "NativeAuthKey",
    "__version__",
    "cbc256_decrypt",
    "cbc256_encrypt",
    "compute_msg_key",
    "ctr256_crypt",
    "factorize_pq",
    "ige256_decrypt",
    "ige256_encrypt",
    "mtproto2_decrypt_packet",
    "mtproto2_encrypt_packet",
    "mtproto2_kdf",
]
