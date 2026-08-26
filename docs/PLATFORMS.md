# Platform Support

| Capability | Linux | Windows | macOS (arm64) |
|---|---|---|---|
| On-demand scanning (signatures, YARA, archives, PDF/VBA) | ✅ | ✅ | ✅ |
| ML detector (LightGBM) | ✅ | ✅ | ✅ |
| Encrypted quarantine vault | ✅ | ✅ | ✅ |
| Signed feeds / models / self-updates | ✅ | ✅ | ✅ |
| Fleet agent (check-ins, remote scans, telemetry) | ✅ | ✅ | ✅ |
| **Real-time notification + quarantine** (FSEvents / RDCW) | ✅ | ✅ | ✅ |
| **Blocking on-access protection** (fanotify / EndpointSecurity / minifilter) | ✅ root | ⚙️ requires driver | ⚙️ requires entitlement |
| `.deb` package + systemd services | ✅ | — | — |
| Standalone executable (`defentra.exe` / `defentra`) | CI-built* | ✅ | ✅ |
| Windows installer (Inno Setup) | — | ✅ | — |
| CI-validated on every push | ✅ ubuntu | ✅ windows-latest | ✅ macos-latest |

\* A Linux standalone binary can be built with the same spec
(`scripts/frozen/defentra.spec`); the deb remains the preferred Linux install.

## Installing on Windows

1. Download `DefentraSetup-<version>-windows-amd64.exe` from the project's
   GitHub Releases and run it (or grab the portable
   `defentra-<version>-windows-amd64.exe`).
2. Verify: open a terminal → `defentra --version`.
3. Scan something: `defentra scan C:\Users\you\Downloads`.
4. Enable real-time protection: `defentra monitor C:\Users\you\Downloads` (runs
   in the terminal; use Task Scheduler for persistent background protection).

Notes:

* The binaries are **not code-signed** yet, so SmartScreen may show a
  "unknown publisher" prompt — choose *More info → Run anyway*. This goes
  away once an Authenticode certificate is configured for the project.
* Real-time protection uses `ReadDirectoryChangesW` for file-change
  detection and automatic quarantine.  Blocking on-access protection
  (denying file opens) requires a filesystem minifilter driver (planned).
* To join a managed fleet: `defentra agent pair --server https://console:8477
  --ca-cert server.crt --token <TOKEN>` then run `defentra agent run`
  (a Windows service wrapper is on the roadmap; Task Scheduler works today).

## Installing on macOS

1. Download `defentra-<version>-macos-arm64` from GitHub Releases:
   ```bash
   curl -LO https://github.com/jacobtblalock3-cmd/defentra/releases/download/v<version>/defentra-<version>-macos-arm64
   chmod +x defentra-<version>-macos-arm64
   ./defentra-<version>-macos-arm64 --version
   ```
2. Gatekeeper may warn because the binary is unsigned/notarized yet — right-click → Open, or
   `xattr -d com.apple.quarantine ./defentra-*` after verifying SHA256SUMS.
3. Alternatively: `python3 -m pip install defentra` (Python 3.9+).
4. Enable real-time protection: `defentra monitor ~/Downloads /Applications` (runs
   in the terminal; use launchd for persistent background protection).

## What "scan-only" means off-Linux

Everything except kernel-enforced blocking protection works identically:
the engine, detection content updates (Ed25519-signed), quarantine,
fleet enrollment/commands/policy, telemetry, and self-updates.

**Real-time protection** is now available on all platforms:
- **Linux**: fanotify (blocking, requires root) or inotify (notification)
- **macOS**: FSEvents (notification, any user) — EndpointSecurity (blocking) requires Apple Developer ID + entitlement
- **Windows**: ReadDirectoryChangesW (notification, any user) — minifilter driver (blocking) requires WHQL signing

The notification backends detect malicious files in real-time and
quarantine them immediately.  The blocking backends additionally prevent
the malicious file from being opened/executed in the first place.

## Building the standalone binaries yourself

```bash
pip install . yara-python pyinstaller
pyinstaller --noconfirm scripts/frozen/defentra.spec
./dist-standalone/defentra --version
```

The spec bundles the pinned trust keys and YARA rules; the ML stack is
excluded from frozen builds by design (drop a fetched model next to the
binary's state dir to re-enable ML).
