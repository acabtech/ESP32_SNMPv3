/*
 * DHT22 telemetry over SNMPv3 — flagship example for ESP32-SNMPv3-Agent.
 *
 * Board : ESP32 / ESP32-S2 / ESP32-S3 (arduino-esp32 core v3.x)
 * Sensor: DHT22 wired to pin 4 (change DHT_PIN for your board).
 *
 * The agent answers SNMPv3 queries with authPriv (HMAC-SHA-256 + AES-128):
 *
 *   Manager side (pick one):
 *
 *   net-snmp:
 *     snmpget -v3 -l authPriv -u telemetry -a SHA-256 -A auth-passphrase \
 *             -x AES -X priv-passphrase udp:DEVICE_IP:161 \
 *             1.3.6.1.4.1.99999.1.1.0
 *
 *   Zabbix:  Host → SNMP interface → "Use SNMPv3" →
 *            security level: auth+priv, auth protocol SHA-256,
 *            privacy protocol AES-128, user "telemetry".
 *
 *   Home Assistant (configuration.yaml):
 *     sensor:
 *       - platform: snmp
 *         host: DEVICE_IP
 *         version: 3
 *         username: telemetry
 *         auth_key: auth-passphrase
 *         priv_key: priv-passphrase
 *         auth_protocol: sha256
 *         priv_protocol: aes
 *         accept_errors: true
 *         scan_interval: 30
 *         oid: 1.3.6.1.4.1.99999.1.1.0  # degrees C * 10
 *
 * NOTE: OIDs below use placeholder enterprise 99999 under the enterprises
 * subtree (1.3.6.1.4.1). Before shipping a product, PT Alat Cerdas Adikarya Bersama should
 * request a private enterprise number (IANA PEN) and re-prefix the OIDs.
 *
 * GPL-3.0 — PT Alat Cerdas Adikarya Bersama, 2026.
 */
#include <Arduino.h>
#include <WiFi.h>
#include <DHT.h>
#include <SnmpV3Agent.h>

#define WIFI_SSID "CHANGE_ME"
#define WIFI_PASS "CHANGE_ME"

#define DHT_PIN 4
DHT dht(DHT_PIN, DHT22);

// --- OID layout ------------------------------------------------------------
// enterprises.alatcerdas.example = 1.3.6.1.4.1.99999 (placeholder)
//   .1.1.0  sensorTemperature  (degrees C * 10, signed)
//   .1.1.1  sensorHumidity     (% RH * 10, signed)
#define OID_TEMP "1.3.6.1.4.1.99999.1.1.0"
#define OID_HUM  "1.3.6.1.4.1.99999.1.1.1"

// --- Cached readings (DHT22 needs >= 2 s between reads; getters must be
// --- cheap and non-blocking, so the loop() below refreshes the cache).
float t = NAN, h = NAN;
uint32_t lastRead = 0;

int32_t getTemp() { return isnan(t) ? INT32_MIN : (int32_t)(t * 10.0f + 0.5f); }
int32_t getHum()  { return isnan(h) ? INT32_MIN : (int32_t)(h * 10.0f + 0.5f); }

void setup() {
  Serial.begin(115200);
  delay(200);

  dht.begin();

  Serial.print("Connecting to Wi-Fi");
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print('.'); }
  Serial.printf("\nWi-Fi connected: %s\n", WiFi.localIP().toString().c_str());

  // --- SNMPv3 agent (authPriv only: HMAC-SHA-256 + AES-128) ----------------
  if (!SNMPv3.begin()) {
    Serial.println("[SNMP] agent failed to start (M0 scaffold — core not built yet)");
    return;
  }

  // Passphrases must each be >= 8 characters (RFC 3414 §11.2).
  SNMPv3.addUser("telemetry", "auth-passphrase", "priv-passphrase");

  SNMPv3.registerScalar(OID_TEMP, getTemp);
  SNMPv3.registerScalar(OID_HUM, getHum);

  Serial.printf("[SNMP] agent ready on UDP :161  engBoots=%lu\n",
                (unsigned long)SNMPv3.engineBoots());
}

void loop() {
  SNMPv3.loop();  // pump the agent — always, first thing

  if (millis() - lastRead >= 2000) {
    lastRead = millis();
    t = dht.readTemperature();
    h = dht.readHumidity();
    if (!isnan(t))
      Serial.printf("temp=%.1f C  hum=%.1f %%\n", t, h);
  }
}