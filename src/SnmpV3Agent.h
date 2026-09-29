// SnmpV3Agent.h — public API for the ESP32-SNMPv3-Agent library (M0 scaffold)
//
// Status: M0 scaffold. The class surface is final for v0.1; method bodies are
// stubs until the BER / USM / MIB core lands (see docs/ROADMAP.md).
//
// Scope lock (approved by maintainer):
//   • SNMPv3 agent role ONLY (responds to manager polls on UDP :161, sends
//     v3 traps/informs to a configured manager on UDP :162). No manager role,
//     no v1/v2c.
//   • USM security: authPriv only — HMAC-SHA-256 auth (RFC 7860) + AES-128
//     CFB privacy (RFC 3826). All other auth/priv combinations are dropped
//     for v0.1 (RFC 3414 discovery reports still answered unauthenticated,
//     as the protocol requires).
//   • Hardware-accelerated SHA-256 / AES via the ESP32 family crypto engines
//     (through the ESP-IDF mbedtls layer shipped inside arduino-esp32 v3.x).
//
// SPDX-License-Identifier: GPL-3.0
#ifndef SNMPV3AGENT_H
#define SNMPV3AGENT_H

#include <stdint.h>
#include <stddef.h>

#if defined(ARDUINO_ARCH_ESP32)
#include <WiFi.h>
#include <IPAddress.h>
#endif

// --- OID helpers -----------------------------------------------------------
// OIDs are registered as dotted strings, e.g. "1.3.6.1.4.1.99999.1.1.0".
// The library parses them once at registration into 32-bit arc vectors.

// --- Public agent API ------------------------------------------------------
class SnmpV3Agent {
 public:
  // Start the agent: computes engine ID (MAC-derived, RFC 3411 §4 format),
  // reads/increments engineBoots from NVS, restores/advances engineTime,
  // opens the UDP :161 listener. Returns false if radio/NVS unavailable.
  bool begin(uint16_t agentPort = 161);

  // Must be called from loop(); pumps the UDP socket, dispatches requests,
  // retries informs. Non-blocking, returns in << 1 ms when idle.
  void loop();

  // --- USM users -----------------------------------------------------------
  // Add an authPriv user (SHA-256 + AES-128). Passphrases must be >= 8
  // characters (RFC 3414 §11.2). Localized keys are derived at add-time
  // using the local engine ID; call AFTER begin(). Returns false on invalid
  // arguments or if the user table is full (v0.1: max 4 users).
  bool addUser(const char* username,
               const char* authPassphrase,
               const char* privPassphrase);

  // Override the MAC-derived engine ID (hex string, 5..32 octets, RFC 3411
  // §4 rules apply). Returns false on malformed input. Must be called before
  // begin() — changing the engine ID invalidates all localized keys.
  bool setEngineId(const char* engineIdHex);

  // --- MIB registration ----------------------------------------------------
  // Register a scalar (signed 32-bit). Getter is invoked synchronously the
  // moment the varbind is built; keep it fast / non-blocking (return a
  // cached sensor reading, do NOT read the sensor inside the getter).
  bool registerScalar(const char* oid, int32_t (*getter)(void));

  // Scalar with write access (SNMP Set). Setter returns true on accept.
  bool registerScalar(const char* oid,
                      int32_t (*getter)(void),
                      bool (*setter)(int32_t value));

  // EXPERIMENTAL (v0.1 stretch): columnar table at baseOid. Cell(row, col)
  // returns column col (0-based) of table row `row`; rows() returns current
  // row count. Instance = row + 1.
  bool registerTable(const char* baseOid,
                     size_t (*rows)(void),
                     int32_t (*cell)(size_t row, size_t col));

  // --- v3 notifications (traps/informs) ------------------------------------
  // Target NMS for traps/informs (UDP :162 by default).
  void setTrapManager(IPAddress ip, uint16_t port = 162);
  // Send a v3 trap for the given OID (instance optional). Fire-and-forget.
  bool sendTrap(const char* oid, uint32_t instance = 0);
  // Send a v3 inform: waits for the NMS response PDU, retries per RFC 3416
  // (max 3 retries/5 s). Returns true when acknowledged.
  bool sendInform(const char* oid, uint32_t instance = 0);

  // --- introspection --------------------------------------------------------
  uint32_t engineBoots();  // current value of snmpEngineBoots
  uint8_t  engineIdLen();
  // 0 = stopped, 1 = listening, 2 = run, 3 = error
  uint8_t  state();
  bool     connected();    // Wi-Fi + UDP socket healthy

 private:
  // TODO(M1): agent state machine, UDP sockets, USM engine, MIB tree.
};

// Process-wide singleton, Arduino style (like `WiFi`, `Serial2`).
extern SnmpV3Agent SNMPv3;

#endif  // SNMPV3AGENT_H