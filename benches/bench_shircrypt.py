"""Micro-benchmark for shircrypt primitives."""

from __future__ import annotations

import os
import time

import shircrypt


def bench(label: str, fn, iterations: int, payload_bytes: int) -> None:
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - start
    mb_total = (iterations * payload_bytes) / (1024 * 1024)
    mb_s = mb_total / elapsed if elapsed > 0 else 0.0
    print(f"{label:28s} | {iterations:5d} iters | {elapsed:6.3f}s | {mb_s:8.2f} MB/s")


def main() -> None:
    print(f"shircrypt v{shircrypt.__version__} (backend={shircrypt.BACKEND})")
    key = os.urandom(32)
    iv_ige = os.urandom(32)
    iv_ctr = os.urandom(16)
    auth_key = os.urandom(256)
    data_64k = os.urandom(64 * 1024)
    data_1k = os.urandom(1024)

    bench("ige256_encrypt (64 KiB)", lambda: shircrypt.ige256_encrypt(data_64k, key, iv_ige), 200, len(data_64k))
    bench("ige256_decrypt (64 KiB)", lambda: shircrypt.ige256_decrypt(data_64k, key, iv_ige), 200, len(data_64k))
    bench("ctr256_crypt   (64 KiB)", lambda: shircrypt.ctr256_crypt(data_64k, key, iv_ctr), 200, len(data_64k))
    bench("cbc256_encrypt (64 KiB)", lambda: shircrypt.cbc256_encrypt(data_64k, key, iv_ctr), 200, len(data_64k))
    bench("mtproto2_kdf   (1 KiB)", lambda: shircrypt.mtproto2_kdf(auth_key, data_1k[:16]), 5000, 256)


if __name__ == "__main__":
    main()
