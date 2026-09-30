// test_store.c — AgentStore persistence seam tests (src/usm/store.h).
//
// The ESP32 build wires this seam to NVS (store_esp32.c); the host suite
// injects a RAM-backed store to validate the contract SnmpV3Agent.cpp relies
// on: boots survive reboots (RFC 3414 §2.3) and an engineID override is
// persisted so the identity — and therefore all localized keys — stays valid
// across power cycles (docs/DESIGN.md NVS layout).
//
// SPDX-License-Identifier: GPL-3.0
#include <stdio.h>
#include <string.h>

#include "usm/store.h"

static int fails = 0;
static int checks = 0;

static void ok_(int cond, const char* what) {
  checks++;
  if (!cond) { fails++; printf("  FAIL: %s\n", what); }
}

// --- RAM-backed store (mirrors the NVS semantics) ---------------------------
static uint32_t s_boots;
static bool     s_hasBoots;
static uint8_t  s_engineId[32];
static size_t   s_engineIdLen;
static bool     s_hasEngineId;

static bool ram_load_boots(uint32_t* boots) {
  if (!s_hasBoots) return false;
  *boots = s_boots;
  return true;
}
static bool ram_save_boots(uint32_t boots) {
  s_boots = boots; s_hasBoots = true; return true;
}
static bool ram_load_engineid(uint8_t* out, size_t cap, size_t* outLen) {
  if (!s_hasEngineId) return false;
  if (s_engineIdLen > cap) return false;
  memcpy(out, s_engineId, s_engineIdLen);
  *outLen = s_engineIdLen;
  return true;
}
static bool ram_save_engineid(const uint8_t* id, size_t len) {
  if (len > sizeof s_engineId) return false;
  memcpy(s_engineId, id, len);
  s_engineIdLen = len;
  s_hasEngineId = true;
  return true;
}

static AgentStore ram_store(void) {
  AgentStore s;
  memset(&s, 0, sizeof s);
  s.loadBoots = ram_load_boots;
  s.saveBoots = ram_save_boots;
  s.loadEngineId = ram_load_engineid;
  s.saveEngineId = ram_save_engineid;
  return s;
}

static void test_boots(void) {
  s_hasBoots = false;
  AgentStore s = ram_store();
  uint32_t b = 0;
  ok_(!s.loadBoots(&b), "boots: first boot -> nothing stored");
  ok_(s.saveBoots(7), "boots: save 7");
  ok_(s.loadBoots(&b) && b == 7, "boots: reload 7");
  ok_(s.saveBoots(8), "boots: save 8 (next boot)");
  ok_(s.loadBoots(&b) && b == 8, "boots: reload 8");
}

static void test_engineid(void) {
  s_hasEngineId = false;
  AgentStore s = ram_store();
  uint8_t out[32]; size_t outLen = 0;
  ok_(!s.loadEngineId(out, sizeof out, &outLen), "engineId: none stored");
  static const uint8_t id[] = {0x80, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  ok_(s.saveEngineId(id, sizeof id), "engineId: save override");
  ok_(s.loadEngineId(out, sizeof out, &outLen) && outLen == sizeof id &&
      memcmp(out, id, sizeof id) == 0, "engineId: reload override");
  // cap too small -> load fails (caller falls back to MAC-derived)
  outLen = 0;
  ok_(!s.loadEngineId(out, 4, &outLen), "engineId: cap too small rejected");
}

int test_store(void) {
  printf("== store seam ==\n");
  test_boots();
  test_engineid();
  printf("  %d checks, %d failures\n", checks, fails);
  return fails;
}
