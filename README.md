# omni_core_ui

Shared core for every Omniverse app. Built from the Gemini "Omni-Hub bundling" blueprint (NotebookLM, Oct 27 2026), with the parts made real.

| Module | What it really does |
|---|---|
| `OmniHubClient` | The app's **only** door out. Talks to the Omni-Hub (local daemon) over loopback: `:9100` telemetry, `:5000` IPC gateway. The daemon alone talks to peers (`:5005` P2P sync, `:9101` UDP discovery). |
| `StargateIdentity` | Per-install Ed25519 key (seed in app-private SQLite). Signs and verifies events in the exact format of `Admin/omni_signing.py`. |
| `LocalEventStore` | Offline-first, signed, hash-chained local log (SQLite). Writes are instant; `syncToHub()` pushes pending events to the hub in order. |
| `OmniOta` | OTA updates. Since 0.1.3 the local Omni Node (daemon v8.30.0+, `127.0.0.1:5000/api/updates/*`) is asked first and GitHub Releases at the same time: the Node's manifest is used only if its Ed25519 signature verifies against the pinned key and it isn't older than GitHub's; the APK comes from the Node by SHA-256, falling back to GitHub on any failure. SHA-256 checked download, Android install prompt. Apps pass the Omni Node local token with `OmniOta.localTokenProvider` (default none: the Node answers 401 and GitHub is used). |
| `MeshStatusBadge`, `HumanVerifiedBadge` | Human-first status: "Mesh online · 1 connected" / "Offline mode", and a HUMAN badge only when a signature truly verifies. |

## Honest limits
- The identity seed isn't in the Android hardware keystore yet.
- `LocalEventStore` is a per-device hash chain, not a Merkle DAG. Merging across devices is the daemon's job.
- Android always shows the install prompt for sideloaded updates. Flutter release builds can't hot-swap Dart code, so a "patch without restart" can only change assets or config.
- Signed manifests turn on when the repo secret `OMNI_OTA_SIGNING_KEY` (64-hex Ed25519 private seed) is set. Until then, manifests rely on HTTPS + SHA-256.

## Tests
`test/ota_download_test.dart` and `test/ota_sources_test.dart` are pure Dart (fake Omni Node + fake GitHub on loopback); they also run outside Flutter with `package:test`.

`flutter test`: the vectors come from the daemon's Python signer, so passing proves byte-for-byte interop (canonical JSON, event ids, signatures).

---
Split out of kiroba/The-Omniverse (packages/omni_core_ui) with history, Oct 30 2026. Apps depend on it by git tag.
