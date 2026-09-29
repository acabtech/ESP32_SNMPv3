/*
 * minimal_authpriv — smallest SNMPv3 agent for a bare board (no sensors).
 *
 * Exposes two scalars so you can smoke-test the agent from any NMS:
 *   .1.0  appUptimeSeconds      → millis()/1000
 *   .1.1  appFreeHeapBytes      → ESP.getFreeHeap()
 *
 * Manager sanity check (net-snmp):
 *   snmpwalk -v3 -l authPriv -u smoke -a SHA-256 -A auth-passphrase \
 *            -x AES -X priv-passphrase udp:DEVICE_IP:161 1.3.6.1.4.1.99999
 *
 * GPL-3.0 — PT Alat Cerdas Adikarya Bersama, 2026.
 */
#include <Arduino.h>
#include <WiFi.h>
#include <SnmpV3Agent.h>

#define WIFI_SSID "CHANGE_ME"
#define WIFI_PASS "CHANGE_ME"

#define OID_UPTIME  "1.3.6.1.4.1.99999.2.1.0"
#define OID_FREEHEAP "1.3.6.1.4.1.99999.2.1.1"

int32_t getUptime()  { return (int32_t)(millis() / 1000); }
int32_t getFreeHeap(){ return (int32_t)ESP.getFreeHeap(); }

void setup() {
  Serial.begin(115200);
  delay(200);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print('.'); }
  Serial.printf("\nWi-Fi connected: %s\n", WiFi.localIP().toString().c_str());

  if (!SNMPv3.begin()) {
    Serial.println("[SNMP] agent failed to start (M0 scaffold)");
    return;
  }
  SNMPv3.addUser("smoke", "auth-passphrase", "priv-passphrase");
  SNMPv3.registerScalar(OID_UPTIME, getUptime);
  SNMPv3.registerScalar(OID_FREEHEAP, getFreeHeap);
  Serial.println("[SNMP] agent ready on UDP :161 (authPriv, SHA-256 + AES-128)");
}

void loop() {
  SNMPv3.loop();
  delay(5);
}