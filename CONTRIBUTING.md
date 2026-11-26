# Contributing to shircrypt

Contributions are welcome! Please keep the core minimal, zero-C-dependency, and memory-safe.

## Local Development

```bash
git clone https://github.com/Vicious-Cycle/shircrypt.git
cd shircrypt
python3 -m pip install -e ".[dev]"
maturin develop --release
cargo test --release
python3 -m unittest discover -s tests -v
```

## Guidelines

1. Never introduce C/OpenSSL system dependencies in `Cargo.toml`.
2. Ensure all key/IV buffers are wiped via `zeroize`.
3. Keep `python/shircrypt/_fallback.py` and `python/shircrypt/__init__.pyi` in sync with `src/lib.rs`.
4. Add unit tests in both `src/lib.rs` and `tests/test_shircrypt.py` for any new primitive.
