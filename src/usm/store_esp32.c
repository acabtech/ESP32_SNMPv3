// store_esp32.c — NVS-backed AgentStore for the ESP32 family (M2).
//
// Uses the Arduino-ESP32 Preferences wrapper around NVS (littlefs-free,
// wear-leveled). The "snmpv3" namespace holds:
//   boots (u32)     — RFC 3414 §2.3: must survive power cycles; incremented
//                      exactly once per boot by the agent core.
//   engineId (bytes) — optional RFC 3411 §4 override (setEngineId); persisted
//                      so the identity — and therefore all localized keys —
//                      survives reboots (docs/DESIGN.md NVS layout).
//
// Compiled on every target by the Arduino library build; on non-ESP32
// platforms the functions are compiled out (the host suite injects its own
// RAM store instead).
//
// SPDX-License-Identifier: GPL-3.0
#include "store.h"

#if defined(ARDUINO_ARCH_ESP32)

#include <Preferences.h>

static bool store_load_boots_esp32(uint32_t* boots) {
  Preferences prefs;
  if (!prefs.begin("snmpv3", true /* read-only */)) return false;
  bool ok = prefs.isKey("boots");
  if (ok) *boots = prefs.getUInt("boots", 0);
  prefs.end();
  return ok;
}

static bool store_save_boots_esp32(uint32_t boots) {
  Preferences prefs;
  if (!prefs.begin("snmpv3", false /* read-write */)) return false;
  bool ok = prefs.putUInt("boots", boots) == 1;
  prefs.end();
  return ok;
}

static bool store_load_engineid_esp32(uint8_t* out, size_t cap, size_t* outLen) {
  Preferences prefs;
  if (!prefs.begin("snmpv3", true /* read-only */)) return false;
  bool ok = prefs.isKey("engineId");
  if (ok) {
    size_t n = prefs.getBytes("engineId", out, cap);
    if (n == 0 || n > cap) ok = false;   // empty / oversized -> treat as absent
    else *outLen = n;
  }
  prefs.end();
  return ok;
}

static bool store_save_engineid_esp32(const uint8_t* id, size_t len) {
  Preferences prefs;
  if (!prefs.begin("snmpv3", false /* read-write */)) return false;
  bool ok = prefs.putBytes("engineId", id, len) == len;
  prefs.end();
  return ok;
}

const AgentStore SNMPV3_ESP_STORE = {
    .loadBoots = store_load_boots_esp32,
    .saveBoots = store_save_boots_esp32,
    .loadEngineId = store_load_engineid_esp32,
    .saveEngineId = store_save_engineid_esp32,
};

#else
// Host/other builds: no NVS. A weak empty symbol keeps the translation unit
// meaningful without dragging Arduino headers into the host suite.
typedef int snmpv3_store_esp32_disabled_t;
#endif  // ARDUINO_ARCH_ESP32
