// store_esp32.c — NVS-backed AgentStore for the ESP32 family (M2).
//
// Uses the Arduino-ESP32 Preferences wrapper around NVS (littlefs-free,
// wear-leveled). The "snmpv3" namespace holds:
//   boots (u32) — RFC 3414 §2.3: must survive power cycles; incremented
//                 exactly once per boot by the agent core.
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

const AgentStore SNMPV3_ESP_STORE = {
    .loadBoots = store_load_boots_esp32,
    .saveBoots = store_save_boots_esp32,
};

#else
// Host/other builds: no NVS. A weak empty symbol keeps the translation unit
// meaningful without dragging Arduino headers into the host suite.
typedef int snmpv3_store_esp32_disabled_t;
#endif  // ARDUINO_ARCH_ESP32
