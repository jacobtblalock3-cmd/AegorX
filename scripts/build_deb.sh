#!/usr/bin/env bash
# Build a Debian package from the current tree.
# Usage: scripts/build_deb.sh [output-dir]
set -euo pipefail

OUT_DIR="${1:-dist}"
VERSION=$(python3 - <<'PY'
import re
print(re.search(r'^version = "(.*)"', open("pyproject.toml").read(), re.M).group(1))
PY
)
STAGE=$(mktemp -d)
PKG="$STAGE/opt/aegorx"
trap 'rm -rf "$STAGE"' EXIT

LIB_DIR="$PKG/lib/systemd/system"
APP_DIR="$STAGE/opt/aegorx/lib"
mkdir -p "$LIB_DIR" "$APP_DIR" "$PKG/DEBIAN" "$PKG/usr/bin"

pip install --quiet --no-deps --target "$APP_DIR" .

cat > "$PKG/usr/bin/aegorx" <<'WRAP'
#!/bin/sh
PYTHONPATH="/opt/aegorx/lib${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m aegorx.cli "$@"
WRAP
chmod 755 "$PKG/usr/bin/aegorx"

cp packaging/systemd/*.service packaging/systemd/*.timer "$LIB_DIR/"

SIZE_KB=$(du -sk "$APP_DIR" | cut -f1)
cat > "$PKG/DEBIAN/control" <<CTRL
Package: aegorx
Version: $VERSION
Section: utils
Priority: optional
Architecture: all
Depends: python3 (>= 3.9), python3-cryptography (>= 41.0)
Recommends: python3-yara, python3-lightgbm, python3-numpy
Suggests: systemd
Installed-Size: $SIZE_KB
Maintainer: AegorX Project <security@aegorx.invalid>
Homepage: https://github.com/jacobtblalock3-cmd/AegorX
Description: Open-source AI-assisted antivirus engine
 Multi-detector scanning (hash signatures, YARA, static-feature ML),
 real-time on-access protection via fanotify/inotify, encrypted quarantine,
 and Ed25519-signed signature feed updates.
CTRL

cat > "$PKG/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
POST
chmod 755 "$PKG/DEBIAN/postinst"

mkdir -p "$OUT_DIR"
dpkg-deb --build --root-owner-group "$PKG" "$OUT_DIR/aegorx_${VERSION}_all.deb" >/dev/null
echo "built $OUT_DIR/aegorx_${VERSION}_all.deb"
