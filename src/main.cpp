#include <Arduino.h>
#include <HTTPClient.h>
#include <M5Unified.h>
#include <Update.h>
#include <WiFiClientSecure.h>
#include <WiFiManager.h>
#include <esp_ota_ops.h>
#include <mbedtls/base64.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <time.h>

#include "ota_config.h"
#include "public_key.h"

#ifndef FIRMWARE_VERSION
#define FIRMWARE_VERSION 1
#endif

namespace {

struct Manifest {
  uint32_t version = 0;
  size_t size = 0;
  String sha256;
  String url;
  String signature_b64;
  String signed_payload;
};

unsigned long last_check_ms = 0;
bool update_in_progress = false;

void status_screen(const char* title, const String& detail, uint32_t color = TFT_NAVY) {
  M5.Display.fillScreen(color);
  M5.Display.setTextColor(TFT_WHITE, color);
  M5.Display.setTextDatum(middle_center);
  M5.Display.setTextSize(1);
  M5.Display.drawString(title, M5.Display.width() / 2, 44);
  M5.Display.drawString(detail, M5.Display.width() / 2, 70);
  Serial.printf("%s: %s\n", title, detail.c_str());
}

bool valid_hex_sha256(const String& value) {
  if (value.length() != 64) return false;
  for (char c : value) {
    if (!isxdigit(static_cast<unsigned char>(c))) return false;
  }
  return true;
}

bool parse_manifest(const String& body, Manifest& out) {
  String values[5];
  const char* keys[] = {"version=", "size=", "sha256=", "url=", "signature="};
  int start = 0;
  for (int i = 0; i < 5; ++i) {
    int end = body.indexOf('\n', start);
    if (end < 0) end = body.length();
    String line = body.substring(start, end);
    if (line.endsWith("\r")) line.remove(line.length() - 1);
    if (!line.startsWith(keys[i])) return false;
    values[i] = line.substring(strlen(keys[i]));
    if (values[i].isEmpty()) return false;
    start = end + 1;
  }
  while (start < static_cast<int>(body.length())) {
    const char c = body[start++];
    if (c != '\r' && c != '\n' && !isspace(static_cast<unsigned char>(c))) return false;
  }

  char* endptr = nullptr;
  const unsigned long parsed_version = strtoul(values[0].c_str(), &endptr, 10);
  if (!endptr || *endptr != '\0' || parsed_version == 0 || parsed_version > UINT32_MAX) return false;
  endptr = nullptr;
  const unsigned long parsed_size = strtoul(values[1].c_str(), &endptr, 10);
  if (!endptr || *endptr != '\0' || parsed_size == 0 || parsed_size > 0x330000UL) return false;
  values[2].toLowerCase();
  if (!valid_hex_sha256(values[2])) return false;
  if (!values[3].startsWith("https://")) return false;

  out.version = static_cast<uint32_t>(parsed_version);
  out.size = static_cast<size_t>(parsed_size);
  out.sha256 = values[2];
  out.url = values[3];
  out.signature_b64 = values[4];
  out.signed_payload =
      String("version=") + values[0] + "\n" +
      "size=" + values[1] + "\n" +
      "sha256=" + values[2] + "\n" +
      "url=" + values[3] + "\n";
  return true;
}

bool verify_manifest_signature(const Manifest& manifest) {
  uint8_t digest[32];
  if (mbedtls_sha256_ret(
          reinterpret_cast<const unsigned char*>(manifest.signed_payload.c_str()),
          manifest.signed_payload.length(), digest, 0) != 0) {
    return false;
  }

  size_t signature_capacity = manifest.signature_b64.length();
  std::unique_ptr<unsigned char[]> signature(new unsigned char[signature_capacity]);
  size_t signature_length = 0;
  if (mbedtls_base64_decode(
          signature.get(), signature_capacity, &signature_length,
          reinterpret_cast<const unsigned char*>(manifest.signature_b64.c_str()),
          manifest.signature_b64.length()) != 0) {
    return false;
  }

  mbedtls_pk_context key;
  mbedtls_pk_init(&key);
  const int parse_result = mbedtls_pk_parse_public_key(
      &key,
      reinterpret_cast<const unsigned char*>(OTA_SIGNING_PUBLIC_KEY),
      strlen(OTA_SIGNING_PUBLIC_KEY) + 1);
  if (parse_result != 0) {
    mbedtls_pk_free(&key);
    return false;
  }
  if (!mbedtls_pk_can_do(&key, MBEDTLS_PK_ECDSA)) {
    mbedtls_pk_free(&key);
    return false;
  }
  mbedtls_ecp_keypair* ec = mbedtls_pk_ec(key);
  if (ec == nullptr || ec->grp.id != MBEDTLS_ECP_DP_SECP256R1) {
    mbedtls_pk_free(&key);
    return false;
  }
  const int verify_result = mbedtls_pk_verify(
      &key, MBEDTLS_MD_SHA256, digest, sizeof(digest),
      signature.get(), signature_length);
  mbedtls_pk_free(&key);
  return verify_result == 0;
}

String digest_to_hex(const uint8_t digest[32]) {
  static const char* digits = "0123456789abcdef";
  String result;
  result.reserve(64);
  for (size_t i = 0; i < 32; ++i) {
    result += digits[digest[i] >> 4];
    result += digits[digest[i] & 0x0f];
  }
  return result;
}

bool fetch_manifest(Manifest& manifest) {
  WiFiClientSecure tls;
  tls.setCACert(OTA_ROOT_CA);
  HTTPClient http;
  http.setConnectTimeout(10000);
  http.setTimeout(15000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  http.setRedirectLimit(3);
  if (!http.begin(tls, OTA_MANIFEST_URL)) return false;
  const int code = http.GET();
  if (code != HTTP_CODE_OK) {
    http.end();
    return false;
  }
  const String body = http.getString();
  http.end();
  return parse_manifest(body, manifest) && verify_manifest_signature(manifest);
}

bool install_update(const Manifest& manifest) {
  WiFiClientSecure tls;
  tls.setCACert(OTA_ROOT_CA);
  HTTPClient http;
  http.setConnectTimeout(10000);
  http.setTimeout(15000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  http.setRedirectLimit(3);
  if (!http.begin(tls, manifest.url)) return false;
  const int code = http.GET();
  if (code != HTTP_CODE_OK) {
    http.end();
    return false;
  }
  const int content_length = http.getSize();
  if (content_length <= 0 || static_cast<size_t>(content_length) != manifest.size) {
    http.end();
    return false;
  }
  if (!Update.begin(manifest.size, U_FLASH)) {
    http.end();
    return false;
  }

  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts_ret(&sha, 0);
  WiFiClient* stream = http.getStreamPtr();
  uint8_t buffer[4096];
  size_t written = 0;
  unsigned long last_data_ms = millis();

  while (written < manifest.size) {
    const size_t available = stream->available();
    if (available == 0) {
      if (!http.connected() || millis() - last_data_ms > 30000UL) break;
      delay(5);
      continue;
    }
    const size_t wanted = min(sizeof(buffer), min(available, manifest.size - written));
    const int received = stream->readBytes(buffer, wanted);
    if (received <= 0) break;
    last_data_ms = millis();
    mbedtls_sha256_update_ret(&sha, buffer, received);
    if (Update.write(buffer, received) != static_cast<size_t>(received)) break;
    written += received;
    const unsigned progress = static_cast<unsigned>((written * 100ULL) / manifest.size);
    M5.Display.drawString(String(progress) + "%", M5.Display.width() / 2, 92);
  }

  uint8_t digest[32];
  mbedtls_sha256_finish_ret(&sha, digest);
  mbedtls_sha256_free(&sha);
  http.end();

  if (written != manifest.size || digest_to_hex(digest) != manifest.sha256) {
    Update.abort();
    return false;
  }
  if (!Update.end(false)) {
    Update.abort();
    return false;
  }
  return true;
}

void check_for_update() {
  if (update_in_progress || WiFi.status() != WL_CONNECTED) return;
  update_in_progress = true;
  status_screen("OTA check", "verifying manifest", TFT_DARKCYAN);

  Manifest manifest;
  if (!fetch_manifest(manifest)) {
    status_screen("OTA idle", "manifest rejected", TFT_MAROON);
    update_in_progress = false;
    return;
  }
  if (manifest.version <= static_cast<uint32_t>(FIRMWARE_VERSION)) {
    status_screen("OTA current", String("version ") + FIRMWARE_VERSION, TFT_DARKGREEN);
    update_in_progress = false;
    return;
  }

  status_screen("OTA update", String("version ") + manifest.version, TFT_PURPLE);
  if (!install_update(manifest)) {
    status_screen("OTA failed", "old image retained", TFT_MAROON);
    update_in_progress = false;
    return;
  }
  status_screen("OTA verified", "restarting", TFT_DARKGREEN);
  delay(1000);
  ESP.restart();
}

bool synchronize_clock() {
  configTime(0, 0, "pool.ntp.org", "time.cloudflare.com");
  const unsigned long started = millis();
  while (millis() - started < 20000UL) {
    const time_t now = time(nullptr);
    if (now >= 1700000000) return true;
    delay(250);
  }
  return false;
}

void validate_pending_image() {
  const esp_partition_t* running = esp_ota_get_running_partition();
  esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
  if (esp_ota_get_state_partition(running, &state) != ESP_OK || state != ESP_OTA_IMG_PENDING_VERIFY) {
    return;
  }
  status_screen("OTA self-test", "checking hardware", TFT_ORANGE);
  const bool healthy = psramFound() && M5.Display.width() == 128 && M5.Display.height() == 128;
  delay(5000);
  if (healthy) {
    esp_ota_mark_app_valid_cancel_rollback();
    status_screen("OTA accepted", String("version ") + FIRMWARE_VERSION, TFT_DARKGREEN);
  } else {
    status_screen("OTA rollback", "health check failed", TFT_MAROON);
    delay(1000);
    esp_ota_mark_app_invalid_rollback_and_reboot();
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  auto cfg = M5.config();
  M5.begin(cfg);
  M5.Display.setRotation(0);
  status_screen("AtomS3R OTA", String("version ") + FIRMWARE_VERSION);
  validate_pending_image();

  WiFiManager wifi_manager;
  wifi_manager.setConfigPortalTimeout(180);
  status_screen("Wi-Fi", "connect or portal", TFT_DARKCYAN);
  if (!wifi_manager.autoConnect("AtomS3R-Setup")) {
    status_screen("Wi-Fi offline", "tap to retry", TFT_MAROON);
  } else if (!synchronize_clock()) {
    status_screen("OTA blocked", "clock not synchronized", TFT_MAROON);
  } else {
    status_screen("OTA ready", WiFi.localIP().toString(), TFT_DARKGREEN);
    check_for_update();
  }
  last_check_ms = millis();
}

void loop() {
  M5.update();
  if (M5.BtnA.wasPressed()) {
    if (WiFi.status() == WL_CONNECTED) {
      check_for_update();
    } else {
      ESP.restart();
    }
  }
  if (millis() - last_check_ms >= OTA_CHECK_INTERVAL_MS) {
    last_check_ms = millis();
    check_for_update();
  }
  delay(10);
}
