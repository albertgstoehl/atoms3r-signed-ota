# AtomS3R signed pull-OTA bootstrap

This isolated project prepares a secure no-Steam-Deck update path for the M5Stack AtomS3R. It does **not** modify the currently working UIFlow2 device.

## Security model

- ECDSA P-256 signs a canonical four-line manifest.
- The firmware embeds only the public key.
- HTTPS validates transport; the signature remains authoritative if hosting is compromised.
- SHA-256 is streamed while writing the inactive OTA partition.
- The bootloader uses A/B partitions and rollback.
- A newly installed image is accepted only after PSRAM and 128x128 display self-tests pass.
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

## Production bootstrap boundary

Before the one-time USB bootstrap:

1. Switch to the local/private Hermes profile `qwen36`.
2. Generate the production private key there; never paste or print it in a hosted chat.
3. Store the private key with restrictive permissions and a separate encrypted backup.
4. Generate `include/public_key.h` from the production public key.
5. The manifest endpoint is fixed to the public `ota` branch; replace placeholder `OTA_ROOT_CA` with the CA root validating both GitHub Raw and Release downloads.
6. Rebuild and sign with a version-specific release URL such as `https://github.com/albertgstoehl/atoms3r-signed-ota/releases/download/v2`.
7. Create the immutable GitHub Release and upload `atoms3r-v2.bin` first.
8. Verify the public asset's size and SHA-256, then publish the signed `manifest.txt` to `stable/manifest.txt` on the `ota` branch last.
9. Test signature rejection, hash rejection, interrupted download, successful update, failed-health rollback, and recovery backup restoration.
10. Only then perform the one final USB bootstrap on a stable connection.

GitHub Actions uses a freshly generated disposable CI key. It never receives the production private key and cannot publish production releases.

## Important

The current `ota_config.h` points at the intended public GitHub manifest location but intentionally contains an invalid CA placeholder. A development build can compile, but cannot contact an update server. This prevents accidental deployment before production CA and key setup are complete.
