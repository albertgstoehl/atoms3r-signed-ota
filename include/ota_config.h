#pragma once

#include "github_ca_bundle.h"

// Stable signed manifest published only after its versioned GitHub Release asset.
static constexpr char OTA_MANIFEST_URL[] =
    "https://raw.githubusercontent.com/albertgstoehl/atoms3r-signed-ota/ota/stable/manifest.txt";

// Public CA bundle validated against GitHub Raw, Releases, and object storage.
// Never use setInsecure() in production.
static constexpr const char* OTA_ROOT_CA = GITHUB_OTA_CA_BUNDLE;

static constexpr unsigned long OTA_CHECK_INTERVAL_MS = 5UL * 60UL * 1000UL;
