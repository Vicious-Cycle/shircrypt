# Architecture & Performance Design

`shircrypt` is engineered for **zero-maintenance longevity** and **predictable high throughput** in async Telegram clients.

## 1. Stable Python ABI (`abi3-py311`)
By enabling PyO3's `abi3-py311` feature, compiled wheels target CPython's Limited API. A single compiled wheel works across Python 3.11, 3.12, 3.13, 3.14, and future CPython 3.x releases without rebuilding.

## 2. Single-Allocation Output & Zero-Copy Input
- Input arguments (`bytes`, `bytearray`, `memoryview`) are borrowed directly via `&[u8]` slices with no intermediate copies.
- Output buffers are allocated once directly inside CPython using `PyBytes::new_bound_with`, eliminating double-buffering (`Vec<u8>` -> `PyBytes`).

## 3. Adaptive GIL Release
Acquiring/releasing the Python GIL has a tiny fixed overhead. `shircrypt` keeps small MTProto control packets (`< 4096` bytes) on the fast path without GIL bounce, and automatically releases the GIL (`py.allow_threads`) for payloads `>= 4096` bytes (media chunks, large RPC responses) so `asyncio` event loops remain non-blocking.

## 4. Key Hygiene (`zeroize`)
Temporary key arrays, `iv_c` / `iv_p` chaining registers, block scratchpads, and derived KDF keys/IVs are explicitly zeroized before returning to Python.

## 5. Hardware Acceleration
The `aes` crate automatically selects:
- **AES-NI** on `x86_64`
- **ARMv8 Cryptography Extensions** on `aarch64` (Android/Termux, Apple Silicon, AWS Graviton)
- Constant-time software fallback on targets without hardware AES instructions.
