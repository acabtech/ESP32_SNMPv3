/*
 * trap_notification — v3 trap demo: a button press emits an authenticated
 * and encrypted trap to a manager, proving the notification path.
 *
 *   Button on pin 18 (pull-up; change BTN_PIN for your board).
 *
 * Manager side (PC with net-snmp):
 *   # snmptrapd.conf
 *   authCommunity log exec
 *   disableAuthorization yes
 *
 *   snmptrapd -f -Lo
 *
 * On press the device sends an authPriv v3 trap:
 *   .1.2.0  appButtonPressed (value 1)
 *
 * GPL-3.0 — PT Alat Cerdas Adikarya Bersama, 2026.
 */
#include <Arduino.h>
#include <WiFi.h>
#include <SnmpV3Agent.h>

#define WIFI_SSID "CHANGE_ME"
#define WIFI_PASS "CHANGE_ME"

#define BTN_PIN   18
#define OID_BTN   "1.3.6.1.4.1.67018.2.2.0"

// Manager that should receive v3 traps/informs (UDP :162).
// Replace with the NMS IP on your network (e.g. your Zabbix or PC).
IPAddress TRAP_MANAGER(192, 168, 1, 10);

void setup() {
  Serial.begin(115200);
  delay(200);

  pinMode(BTN_PIN, INPUT_PULLUP);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print('.'); }
  Serial.printf("\nWi-Fi connected: %s\n", WiFi.localIP().toString().c_str());

  if (!SNMPv3.begin()) {
    Serial.println("[SNMP] agent failed to start (M0 scaffold)");
    return;
  }
  SNMPv3.addUser("telemetry", "auth-passphrase", "priv-passphrase");
  SNMPv3.setTrapManager(TRAP_MANAGER);
  Serial.println("[SNMP] agent ready — press the button to fire a v3 trap");
}

void loop() {
  SNMPv3.loop();

  static bool last = HIGH;
  bool now = digitalRead(BTN_PIN);
  if (last == HIGH && now == LOW) {
    Serial.println("[SNMP] sending v3 trap");
    // TODO(M3): sendTrap/oid, returns once the core lands.
    if (SNMPv3.sendTrap(OID_BTN)) {
      Serial.println("[SNMP] trap sent");
    } else {
      Serial.println("[SNMP] sendTrap unavailable (M0 scaffold)");
    }
  }
  last = now;
}