# Changelog

All notable changes to `shircrypt` are documented in this file.

## [1.0.3] - 2026-11-26

### Added
- **Rust `abi3-py311` Native Core (`shircrypt._shircrypt`):**
  - `ige256_encrypt` / `ige256_decrypt` with single-allocation `PyBytes::new_bound_with`, `zeroize` key wiping, and automatic GIL release (`>= 4096` bytes).
  - `ctr256_crypt` with byte-granularity `offset` seeking for parallel chunked file transfers.
  - `cbc256_encrypt` / `cbc256_decrypt` for auxiliary MTProto / storage compatibility.
  - `compute_msg_key` and `mtproto2_kdf` implemented natively in Rust (`sha2`).
- **Automatic Fallback & Typing:**
  - Pure-Python + `cryptography` fallback (`shircrypt._fallback`) with `BACKEND` indicator (`"rust"` or `"cryptography"`).
  - Full PEP 561 type stubs (`__init__.pyi`, `py.typed`).
- **CI/CD & Benchmarks:**
  - Multi-platform `maturin` wheel builds (`x86_64`, `aarch64`, Windows, macOS) and `cargo test` + `unittest` CI.
  - Benchmark suite in `benches/bench_shircrypt.py`.
