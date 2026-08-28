# Curated signature sources

Files in this directory are merged into the official `signatures.json` feed by
`.github/workflows/update-signature-feed.yml` (daily + manual dispatch). The
feed is signed with the project's Ed25519 root key stored as the encrypted
`SIGNING_PRIVATE_KEY` Actions secret — it never appears in logs or artifacts.

## Adding intelligence

Append entries to an existing file (or add a new one; every `*.json` passed via
`--extra feeds/*.json` is merged, later files win on sha256 conflicts):

```json
{
  "signatures": [
    {
      "sha256": "<64 hex chars, required>",
      "md5":    "<optional>",
      "sha1":   "<optional>",
      "name":   "Win32.Family.Variant",
      "family": "family-name",
      "severity": 8
    }
  ]
}
```

Rules:

- Only hashes you can attribute to actual malicious samples. Include the
  family name so analysts can correlate.
- Severity scale is 0–10.
- Submissions land in `feeds/community.json`; maintainers review via PR before
  the next scheduled build publishes them.

The built-in seed list (`aegorx/signatures/db.py`) is always included
automatically; no need to duplicate EICAR here.
