#!/usr/bin/env python3
"""Set a GitHub Actions secret on the defentra repo via the REST API.

Usage: set_gh_secret.py NAME value-file|-  (value read from file or stdin)

GitHub secrets must arrive encrypted with the repo's libsodium sealed box;
this handles key fetch, encryption, and upload. The plaintext is never
printed, logged, or written to disk when piped via stdin.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.request

REPO = "jacobtblalock3-cmd/defentra"
API = f"https://api.github.com/repos/{REPO}"


def api(method: str, path: str, token: str, payload=None):
    url = f"{API}{path}"
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-HTTPS API URL: {url}")
    req = urllib.request.Request(
        f"{API}{path}",
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
        data=json.dumps(payload).encode() if payload else None,
    )
    # URL is validated to start with https:// above; API host is hardcoded.
    with urllib.request.urlopen(req) as resp:  # nosec B310
        body = resp.read()
    return json.loads(body) if body else {}


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    name, source = sys.argv[1], sys.argv[2]
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        print("error: GH_TOKEN not set", file=sys.stderr)
        return 1
    value = open(source, "rb").read().strip() if source != "-" else sys.stdin.buffer.read().strip()

    from nacl import encoding, public

    pk_body = api("GET", "/actions/secrets/public-key", token)
    recipient = public.PublicKey(pk_body["key"].encode(), encoding.Base64Encoder())
    sealed = public.SealedBox(recipient).encrypt(value)
    api(
        "PUT",
        f"/actions/secrets/{name}",
        token,
        {
            "encrypted_value": base64.b64encode(sealed).decode(),
            "key_id": pk_body["key_id"],
        },
    )
    print(f"secret '{name}' uploaded ({len(value)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
