# AegorX Rust Core

Performance-critical primitives exposed to the Python engine as `_aegorx_core`.

## Build

```bash
pip install maturin
cd rust-core
maturin develop --release     # into current venv
maturin build --release       # produces a wheel in target/wheels/
```

The Python engine automatically uses `stream_sha256` when the module is importable,
and transparently falls back to pure Python otherwise.
