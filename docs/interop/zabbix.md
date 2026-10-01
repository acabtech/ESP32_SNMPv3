# Zabbix interop — SNMPv3 authPriv (dogfood target)

The PT Alat Cerdas Adikarya Bersama homelab runs **Zabbix 8.0.0-beta2** at
`http://192.168.100.127` (zabbix-vm). This runbook wires the ESP32-SNMPv3-Agent
device into it by walking OIDs over SNMPv3.

## 1. Device side

Flash `examples/dht22_telemetry` (or `minimal_authpriv`) with:

- user `telemetry` / auth `auth-passphrase` / priv `priv-passphrase`
- device IP, e.g. `192.168.100.50`

## 2. Zabbix side: add the host

Configuration → Hosts → **Create host**:

- **Host name**: `esp32-dht22`
- **Interfaces → SNMP** (add interface)
  - **Use SNMP bulk requests** ✓
  - **Use SNMPv3** ✓
  - **Security level**: `auth + priv`
  - **Auth protocol**: `SHA-256`   *(Zabbix 6.x+ lists SHA-224/256/384/512)*
  - **Auth passphrase**: `auth-passphrase`
  - **Privacy protocol**: `AES-128` *(Zabbix labels: AES / AES-128)*
  - **Privacy passphrase**: `priv-passphrase`
  - **Username**: `telemetry`
  - **Port**: `161`

Click **Test** — you should see a successful SNMP test (Zabbix performs a
discovery round automatically; the device answers the `report` PDU and Zabbix
completes the handshake).

> Zabbix stores the engine ID it learned. If the device is later re-flashed
> (engineBoots increments) the interface may briefly show
> `Not in time window` — re-running the test re-syncs. Nothing to fix.

## 3. Items & triggers

Configuration → Hosts → `esp32-dht22` → **Items → Create item**:

- **Name**: `Temperature`
- **Type**: `SNMP agent`
- **OID**: `1.3.6.1.4.1.67018.1.1.0`
- **Type of information**: `Numeric (unsigned)`
- **Units**: `C`
- **Custom multipliers**: `0.1` in the value multiplier — readings are
  °C × 10 as integers.

Repeat for humidity OID `1.3.6.1.4.1.67018.1.1.1`.

Then Graphs → create a graph with both items. Wait for the first poll cycle
(default 30 s update) — you now have a live, authenticated, encrypted
telemetry graph from a $3 board.

## 4. Triggers (optional)

- Add trigger: `last(/Host/esp32-dht22/sensorTemperature/)<10` →
  Notification via any channel (telegram, email…). Shows SET-free operation.

## 5. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `Cannot connect to SNMP host` | UDP :161 blocked / wrong IP; check `SNMPv3.begin()` printed + device Wi-Fi IP |
| Time-window errors after flash | Re-run interface test (engine re-learn) |
| `No SNMP data` + item red | Wrong OID; verify with `snmpwalk` from net-snmp runbook first |
| Zabbix doesn't list SHA-256 | Zabbix < 6.0 — upgrade; our dogfood box is 8.0.0-beta2, fine |