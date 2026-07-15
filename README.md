# AtomS3R signed pull-OTA bootstrap

This isolated project prepares a secure no-Steam-Deck update path for the M5Stack AtomS3R. It does **not** modify the currently working UIFlow2 device.

## Security model

- The build uses M5Stack's official AtomS3R board definition: DIO flash mode, QIO/OPI memory type, `m5stack_atoms3` variant, and `ARDUINO_M5STACK_ATOMS3R`.
- ECDSA P-256 signs a canonical four-line manifest.
- The firmware embeds only the public key.
- HTTPS validates transport; the signature remains authoritative if hosting is compromised.
- SHA-256 is streamed while writing the inactive OTA partition.
- The bootloader uses A/B partitions and rollback.
- A newly installed image is accepted only after a 128×128 display check and five-second uptime window pass.
- Versions are monotonically increasing integers; downgrades are rejected.
- Wi-Fi is provisioned locally through the `AtomS3R-Setup` captive portal.

## Manifest format

Exactly five ASCII lines:

```text
version=2
size=499184
sha256=<64 lowercase hex characters>
url=https://firmware.example/atoms3r/atoms3r-v2.bin
signature=<base64 DER ECDSA signature>
```

The signature covers the first four lines including their trailing newlines.

## Development-only test

Create an isolated Python environment:

```bash
uv venv .venv
uv pip install --python .venv/bin/python cryptography
```

Generate a disposable development key (never use it for the production bootstrap):

```bash
.venv/bin/python tools/ota_release.py generate-key \
  --private .dev/dev-private.pem --public .dev/dev-public.pem
.venv/bin/python tools/ota_release.py make-header \
  --public .dev/dev-public.pem --output include/public_key.h
```

Build:

```bash
pio run -e ota
```

Create and verify a test release:

```bash
.venv/bin/python tools/ota_release.py release \
  --private .dev/dev-private.pem \
  --firmware .pio/build/ota/firmware.bin \
  --version 2 \
  --base-url https://github.com/albertgstoehl/atoms3r-signed-ota/releases/download/v2 \
  --output-dir dist

.venv/bin/python tools/ota_release.py verify \
  --public .dev/dev-public.pem \
  --manifest dist/manifest.txt \
  --firmware dist/atoms3r-v2.bin
```

## Production signing and publication boundary

1. Production private signing stays exclusively in the local/private Hermes profile `qwen36`; never paste or print it in hosted chat.
2. `include/public_key.h` contains only the public P-256 verifier and is tracked for reproducible builds. Its authoritative key was recovered from immutable signed v1 firmware and independently verified against the v1 manifest.
3. `include/ota_config.h` contains the CA roots currently validating GitHub Raw and Release downloads. Never use `setInsecure()`.
4. Build a versioned candidate and inspect its actual bootloader header and decoded partition binary.
5. Sign locally with the existing private key whose derived public fingerprint exactly matches the embedded verifier.
6. Create the immutable GitHub Release and upload the firmware first.
7. Download the public asset and compare exact byte count and SHA-256; verify the signed manifest against it.
8. Publish `stable/manifest.txt` to the `ota` branch last, then verify the exact fixed Raw URL.

The v3 source adds a durable NVS attempt/failure ledger. A known-good image records a rolled-back `(version, firmware SHA-256)` and suppresses that exact candidate, preventing the v1→bad candidate→rollback→redownload loop observed with v2. Pending-image health now reports explicit serial reason codes and uses the proven 128×128 display plus five-second uptime path rather than the unproven v2 PSRAM predicate.

GitHub Actions uses a freshly generated disposable CI key. It never receives the production private key and cannot publish production releases.

## Important

- Stable v1 is the pinned recovery image and the only physically accepted release.
- v2 and v3 are known failed candidates that produced rollback/redownload loops. They must remain excluded from stable and must not be republished.
- `github_ca_bundle.h` contains the validated ISRG Root X1 plus USERTrust ECC public roots for GitHub Raw, Releases, and object storage.
- No further production OTA candidate should be offered until failed-candidate suppression exists in the known-good installed base and is physically proven before promotion.
- A passing compile, signature check, or download is not physical acceptance; retain the signed-v1 USB recovery image.
