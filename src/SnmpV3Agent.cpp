// SnmpV3Agent.cpp — the agent: Arduino layer over the host-testable core (M2).
//
// Owns everything hardware-adjacent:
//   • UDP :161 socket (WiFiUDP, non-blocking pump)
//   • engine ID (MAC-derived, RFC 3411 §4 local format; override supported)
//   • NVS persistence of snmpEngineBoots (store_esp32.cpp)
//   • key localization at addUser() time
// All protocol logic lives in the host-tested core:
//   src/agent/AgentCore.c (request gate + dispatch), src/mib/MIB.c,
//   src/ber/BER.c, src/usm/USM.c.
//
// SPDX-License-Identifier: GPL-3.0
#include "SnmpV3Agent.h"

#include <string.h>

#include "agent/AgentCore.h"
#include "ber/BER.h"
#include "mib/MIB.h"
#include "usm/USM.h"
#include "usm/store.h"

#if defined(ARDUINO_ARCH_ESP32)
#include <WiFiUdp.h>
#include <esp_mac.h>

extern const AgentStore SNMPV3_ESP_STORE;   // store_esp32.cpp
static const AgentStore* s_store = &SNMPV3_ESP_STORE;
#else
// Host builds of this translation unit (none today — the host suite links
// AgentCore.c directly) would need a store; keep a placeholder.
static AgentStore s_dummyStore = {0, 0};
static const AgentStore* s_store = &s_dummyStore;
#endif

static AgentState s_state;
static bool       s_begun = false;
static uint32_t   s_upStartMs = 0;
static bool       s_storeOk = false;

#if defined(ARDUINO_ARCH_ESP32)
static WiFiUDP s_udp;          // agent listener (requests)
static WiFiUDP s_trapUdp;      // outbound notifications (M3)
static IPAddress s_trapIp;
static uint16_t s_trapPort = 162;
#endif

// engine ID override (setEngineId before begin)
static uint8_t  s_engineIdOverride[32];
static size_t   s_engineIdOverrideLen = 0;

// --- system hooks (MIB <-> agent state glue) --------------------------------

static uint32_t hook_sysUpTime(void) {
  return (millis() - s_upStartMs) / 10;   // TimeTicks: hundredths of seconds
}

static const uint8_t* hook_engineId(void)      { return s_state.engineId; }
static size_t         hook_engineIdLen(void)   { return s_state.engineIdLen; }
static uint32_t       hook_engineBoots(void)   { return s_state.clock.boots; }
static uint32_t       hook_engineTime(void)    { return s_state.clock.time; }
static uint32_t       hook_engineMaxMsg(void)  { return s_state.maxMessageSize; }
static uint32_t       hook_usmStat(size_t i)   { return s_state.stats[i]; }

// --- engine ID helpers ------------------------------------------------------

// RFC 3411 §4: locally defined engineID = <128|len><octets>; MAC-derived
// variant used here: 0x80, 0x06, <6 MAC octets>.
static bool deriveEngineIdFromMac(uint8_t* out, size_t* outLen) {
#if defined(ARDUINO_ARCH_ESP32)
  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  out[0] = 0x80;
  out[1] = 6;
  memcpy(out + 2, mac, 6);
  *outLen = 8;
  return true;
#else
  (void)out; (void)outLen;
  return false;
#endif
}

// --- public API -------------------------------------------------------------

bool SnmpV3Agent::begin(uint16_t agentPort) {
  if (s_begun) return true;

  uint8_t engineId[32];
  size_t engineIdLen = 0;
  if (s_engineIdOverrideLen != 0) {
    // Explicit override this session: use it and persist it so the identity
    // (and all localized keys) survives the next reboot (docs/DESIGN.md).
    memcpy(engineId, s_engineIdOverride, s_engineIdOverrideLen);
    engineIdLen = s_engineIdOverrideLen;
    if (s_store->saveEngineId) s_store->saveEngineId(engineId, engineIdLen);
  } else if (s_store->loadEngineId &&
             s_store->loadEngineId(engineId, sizeof engineId, &engineIdLen)) {
    // A persisted override from a previous boot — reuse it unchanged.
  } else if (!deriveEngineIdFromMac(engineId, &engineIdLen)) {
    // no MAC source (e.g., host build) — refuse rather than run unidentifiable
    return false;
  }

  // RFC 3414 §2.3: boots is persistent and incremented once per boot.
  uint32_t boots = 0;
  s_storeOk = s_store->loadBoots && s_store->loadBoots(&boots);
  boots += 1;
  if (s_storeOk && s_store->saveBoots) s_storeOk = s_store->saveBoots(boots);

  agentInit(&s_state, engineId, engineIdLen, boots, millis(), AGENT_MAX_MSG);
  s_upStartMs = millis();

  MibSystemHooks hooks;
  memset(&hooks, 0, sizeof hooks);
  hooks.sysUpTime = hook_sysUpTime;
  hooks.engineId = hook_engineId;
  hooks.engineIdLen = hook_engineIdLen;
  hooks.engineBoots = hook_engineBoots;
  hooks.engineTime = hook_engineTime;
  hooks.engineMaxMessage = hook_engineMaxMsg;
  hooks.usmStat = hook_usmStat;
  mibSetSystemHooks(&hooks);
  if (mibRegisterSystem() < 0) return false;

#if defined(ARDUINO_ARCH_ESP32)
  if (!s_udp.begin(agentPort)) return false;
#endif

  s_begun = true;
  return true;
}

void SnmpV3Agent::loop() {
  if (!s_begun) return;
#if defined(ARDUINO_ARCH_ESP32)
  // Non-blocking pump: at most one datagram per call keeps loop() << 1 ms
  // when idle and bounds worst-case latency at one loop() period under load.
  static uint8_t rx[AGENT_MAX_MSG + 64];
  static uint8_t tx[AGENT_MAX_MSG + 64];
  int n = s_udp.parsePacket();
  if (n > 0) {
    if ((size_t)n <= sizeof rx) {
      s_udp.read(rx, n);
      size_t outLen = 0;
      int res = agentProcess(&s_state, rx, (size_t)n, millis(),
                             tx, sizeof tx, &outLen);
      if (res == AGENT_RESPONSE && outLen > 0) {
        s_udp.beginPacket(s_udp.remoteIP(), s_udp.remotePort());
        s_udp.write(tx, outLen);
        s_udp.endPacket();
      }
      // AGENT_NO_RESPONSE / AGENT_ERR_DROP: silence (RFC 3412 reportable=0)
    }
    s_udp.clear();
  }
#endif
}

bool SnmpV3Agent::addUser(const char* username,
                          const char* authPassphrase,
                          const char* privPassphrase) {
  if (!s_begun) return false;   // engine ID must exist to localize keys
  if (username == NULL || authPassphrase == NULL || privPassphrase == NULL)
    return false;
  size_t nameLen = strlen(username);
  size_t authLen = strlen(authPassphrase);
  size_t privLen = strlen(privPassphrase);
  // RFC 3414 §11.2: passphrases >= 8 octets; practical cap 64.
  if (nameLen == 0 || nameLen >= AGENT_NAME_MAX) return false;
  if (authLen < 8 || authLen > 64 || privLen < 8 || privLen > 64) return false;

  uint8_t authKu[SNMPV3_SHA256_KEY];
  uint8_t privKu[SNMPV3_SHA256_KEY];
  if (usmKeyLocalize((const uint8_t*)authPassphrase, authLen,
                     s_state.engineId, s_state.engineIdLen, authKu) < 0)
    return false;
  if (usmKeyLocalize((const uint8_t*)privPassphrase, privLen,
                     s_state.engineId, s_state.engineIdLen, privKu) < 0)
    return false;
  // RFC 3826 §3.1.2.1: AES key = first 16 octets of the localized priv key.
  return agentAddUser(&s_state, username, authKu, privKu) >= 0;
}

bool SnmpV3Agent::setEngineId(const char* engineIdHex) {
  if (s_begun) return false;   // must precede begin()
  if (engineIdHex == NULL) return false;
  size_t hexLen = strlen(engineIdHex);
  if (hexLen < 10 || hexLen > 64 || (hexLen % 2) != 0) return false;  // 5..32 octets
  size_t octets = hexLen / 2;
  for (size_t i = 0; i < octets; i++) {
    uint8_t hi = (uint8_t)((engineIdHex[2 * i]     <= '9')
                               ? engineIdHex[2 * i] - '0'
                               : (engineIdHex[2 * i] | 0x20) - 'a' + 10);
    uint8_t lo = (uint8_t)((engineIdHex[2 * i + 1] <= '9')
                               ? engineIdHex[2 * i + 1] - '0'
                               : (engineIdHex[2 * i + 1] | 0x20) - 'a' + 10);
    if (hi > 15 || lo > 15) return false;
    s_engineIdOverride[i] = (uint8_t)((hi << 4) | lo);
  }
  s_engineIdOverrideLen = octets;
  return true;
}

bool SnmpV3Agent::registerScalar(const char* oid, int32_t (*getter)(void)) {
  if (oid == NULL || getter == NULL) return false;
  return mibRegisterInt32(oid, getter, NULL) >= 0;
}

bool SnmpV3Agent::registerScalar(const char* oid,
                                 int32_t (*getter)(void),
                                 bool (*setter)(int32_t value)) {
  if (oid == NULL || getter == NULL) return false;
  return mibRegisterInt32(oid, getter, setter) >= 0;
}

bool SnmpV3Agent::registerTable(const char* baseOid,
                                size_t (*rows)(void),
                                int32_t (*cell)(size_t row, size_t col)) {
  if (baseOid == NULL || rows == NULL || cell == NULL) return false;
  uint32_t arcs[64];
  int n = mibParseOid(baseOid, arcs, 64);
  if (n < 0) return false;
  return mibRegisterTableBase(arcs, (size_t)n, rows, cell) >= 0;
}

void SnmpV3Agent::setTrapManager(IPAddress ip, uint16_t port) {
#if defined(ARDUINO_ARCH_ESP32)
  s_trapIp = ip;
  s_trapPort = port;
#else
  (void)ip; (void)port;
#endif
}

bool SnmpV3Agent::sendTrap(const char* oid, uint32_t instance) {
  (void)oid; (void)instance;
  return false;   // M3: notifications + soak (docs/ROADMAP.md)
}

bool SnmpV3Agent::sendInform(const char* oid, uint32_t instance) {
  (void)oid; (void)instance;
  return false;   // M3
}

uint32_t SnmpV3Agent::engineBoots() { return s_state.clock.boots; }

uint8_t SnmpV3Agent::engineIdLen() { return (uint8_t)s_state.engineIdLen; }

uint8_t SnmpV3Agent::state() {
  if (!s_begun) return 0;
#if defined(ARDUINO_ARCH_ESP32)
  return !s_storeOk ? 3 : (WiFi.status() == WL_CONNECTED ? 2 : 1);
#else
  return !s_storeOk ? 3 : 1;
#endif
}

bool SnmpV3Agent::connected() {
#if defined(ARDUINO_ARCH_ESP32)
  return s_begun && WiFi.status() == WL_CONNECTED;
#else
  return s_begun;
#endif
}

// Process-wide singleton, Arduino style (like `WiFi`, `Serial2`).
SnmpV3Agent SNMPv3;