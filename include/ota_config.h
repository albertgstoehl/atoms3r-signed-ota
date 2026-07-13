#pragma once

// Stable signed manifest published only after its versioned GitHub Release asset.
static constexpr char OTA_MANIFEST_URL[] =
    "https://raw.githubusercontent.com/albertgstoehl/atoms3r-signed-ota/ota/stable/manifest.txt";

// Replace with the CA root that validates OTA_MANIFEST_URL and firmware URLs.
// Never use setInsecure() in production.
static constexpr char OTA_ROOT_CA[] = R"PEM(
-----BEGIN CERTIFICATE-----
MIIBDEV-ONLY-PLACEHOLDER-NOT-A-REAL-CERTIFICATE
-----END CERTIFICATE-----
)PEM";

static constexpr unsigned long OTA_CHECK_INTERVAL_MS = 5UL * 60UL * 1000UL;
