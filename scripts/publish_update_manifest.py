#!/usr/bin/env python3
"""Build and sign an update-manifest.json for a Defentra release.

Run in CI (Release workflow) after artifacts are staged:

    python scripts/publish_update_manifest.py \
        --version 1.0.0 --key signing_private.pem \
        --out release-assets/update-manifest.json \
        --artifacts dist/*.whl dist/*.tar.gz release-assets/*.deb

The manifest is Ed25519-signed with the project root key; clients verify it
against the pinned package keys before trusting any download URL/hash.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from defentra.signing.feed import sign_document  # noqa: E402
from defentra.update import ARTIFACT_SUFFIXES, build_manifest  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="release version (no 'v' prefix)")
    parser.add_argument("--key", required=True, help="Ed25519 private key PEM path")
    parser.add_argument("--out", required=True, help="output manifest path")
    parser.add_argument(
        "--artifacts",
        nargs="+",
        required=True,
        help="artifact files (.deb/.whl/.tar.gz) to describe",
    )
    parser.add_argument("--ttl-hours", type=int, default=336)
    args = parser.parse_args(argv)

    descriptors = []
    for path in args.artifacts:
        if not os.path.isfile(path):
            print(f"error: artifact not found: {path}", file=sys.stderr)
            return 2
        suffix = next((s for s in ARTIFACT_SUFFIXES.values() if path.lower().endswith(s)), None)
        if suffix is None:
            print(f"error: unsupported artifact suffix: {path}", file=sys.stderr)
            return 2
        with open(path, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        url = (
            "https://github.com/jacobtblalock3-cmd/defentra/releases/download/"
            f"v{args.version}/{os.path.basename(path)}"
        )
        descriptors.append({"url": url, "sha256": digest, "size": os.path.getsize(path)})

    manifest = build_manifest(args.version, descriptors, ttl_hours=args.ttl_hours)
    signed = sign_document(manifest, args.key)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(signed, fh, indent=2, sort_keys=True)
        fh.write("\n")

    kinds = ", ".join(sorted(manifest["artifacts"]))
    print(f"signed update manifest v{args.version} [{kinds}] -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
