# Release Process

## Cutting a release

1. Ensure `main` is green (tests, integration-linux, security jobs).
2. Bump `version` in `pyproject.toml` and `aegorx/__init__.py`; commit.
3. Tag and push:

   ```bash
   git tag -a v0.4.1 -m "v0.4.1"
   git push origin v0.4.1
   ```

4. The **Release** workflow builds automatically:
   - sdist + universal wheel (PyPI)
   - `aegorx_<version>_all.deb` (Debian/Ubuntu clients)
   - `SHA256SUMS` for the whole artifact set
   - a draft-less GitHub Release with all assets attached
   - PyPI publish via trusted publishing token (`PYPI_API_TOKEN` secret)

## What clients install

| Channel | Command |
|---|---|
| Debian / Ubuntu | `sudo apt install ./aegorx_<version>_all.deb` then enable `aegorx-monitor.service` |
| pip (any Linux) | `pip install aegorx` |
| Source | `pip install git+https://github.com/jacobtblalock3-cmd/AegorX.git@v<version>` |

After install:

```bash
sudo systemctl enable --now aegorx-monitor     # realtime protection (fanotify)
sudo systemctl enable --now aegorx-feed-update.timer  # daily signed intel
aegorx model fetch                              # ML detection out-of-the-box
```

## Integrity model

- Every release asset ships with `SHA256SUMS`.
- Signature feeds are Ed25519-signed against the root key bundled in the package.
- Model metadata sidecars carry their own Ed25519 signature; the client refuses
  to load a model whose metadata fails verification or whose sha256 mismatches.

## Secrets required by CI

| Secret | Purpose | Where to get it |
|---|---|---|
| `SIGNING_PRIVATE_KEY` | Signs feeds + model metadata | `~/.aegorx-signing/signing_private.pem` on the release host |
| `MALWAREBAZAAR_KEY` | Live IOC ingestion (optional) | free account at bazaar.abuse.ch |
| `PYPI_API_TOKEN` | PyPI publishing | pypi.org account -> API tokens |
