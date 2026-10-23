# Getting Started — ESP32-SNMPv3-Agent

The single end-to-end guide: **flash → poll → Zabbix → Home Assistant → traps →
troubleshooting**. For per-manager deep dives (engine-cache notes, edge cases),
follow the links to the [interop runbooks](interop/) at each step.

## 1. What you need

| Item | Example | Notes |
|------|---------|-------|
| ESP32 board | ESP32-DevKitC v1 | ESP32 / ESP32-S2 / ESP32-S3, arduino-esp32 v3.x |
| DHT22 sensor (optional) | AM2302 | DATA → GPIO 4, with a 10 kΩ pull-up to VCC |
| Wi-Fi network | Your home AP | 2.4 GHz |
| A manager | Zabbix 8 or Home Assistant | Already running |
| Micro-USB cable | — | Power + flashing |

No PSRAM is required — the agent runs entirely in the chip's SRAM.

## 2. Flash the firmware

1. Install [arduino-cli](https://arduino.github.io/arduino-cli/latest/).
2. Install the library:

   ```bash
   arduino-cli lib install ESP32-SNMPv3-Agent
   ```

   Or copy this repo into `~/Arduino/libraries/esp32-snmpv3-agent`.

3. Open the flagship example and edit the settings **before** flashing:

   | Setting | What to change |
   |---------|----------------|
   | `WIFI_SSID` | Your Wi-Fi name |
   | `WIFI_PASS` | Your Wi-Fi password |
   | `auth-passphrase` | Any passphrase ≥ 8 characters |
   | `priv-passphrase` | Any passphrase ≥ 8 characters |

   **Never ship a board with the default passphrases.**

4. Compile and upload:

   ```bash
   arduino-cli compile --fqbn esp32:esp32:esp32 examples/dht22_telemetry
   arduino-cli upload -p /dev/ttyUSB0 examples/dht22_telemetry
   ```

   The example exposes two OIDs under `enterprises.67018`:

   | OID | Description | Unit |
   |-----|-------------|------|
   | `1.3.6.1.4.1.67018.1.1.0` | Temperature | °C × 10 (integer) |
   | `1.3.6.1.4.1.67018.1.1.1` | Humidity | % RH × 10 (integer) |

## 3. Find the board's IP

Open the Serial Monitor at **115200 baud**. You'll see:

```
Wi-Fi connected: 192.168.1.50
[SNMP] agent ready on UDP :161  engBoots=1
```

Write down the IP (`192.168.1.50` in this example).

## 4. Poll it (net-snmp)

```bash
snmpget -v3 -l authPriv -u telemetry \
        -a SHA-256 -A auth-passphrase \
        -x AES -X priv-passphrase \
        udp:192.168.1.50:161 \
        1.3.6.1.4.1.67018.1.1.0
```

Expected:

```
SNMPv2-SMI::enterprises.67018.1.1.0 = INTEGER: 245
```

That's 24.5 °C. Full CLI reference (walk/bulk/set, `snmp.conf`, engine-cache
troubleshooting): [net-snmp runbook](interop/net-snmp.md).

## 5. Zabbix

1. **Configuration → Hosts → Create host**
   - Host name: `esp32-dht22`
   - Add an **SNMP interface** on port 161
   - Enable **SNMPv3**:
     - Security level: `auth + priv`
     - Auth protocol: `SHA-256`, passphrase `auth-passphrase`
     - Privacy protocol: `AES-128`, passphrase `priv-passphrase`
     - Username: `telemetry`
2. Click **Test** — expect "Successful".
3. Add two items:

   | Name | OID | Type | Multiplier | Unit |
   |------|-----|------|------------|------|
   | Temperature | `1.3.6.1.4.1.67018.1.1.0` | Numeric (unsigned) | 0.1 | °C |
   | Humidity | `1.3.6.1.4.1.67018.1.1.1` | Numeric (unsigned) | 0.1 | % |

4. Create a graph with both items. Wait one 30 s poll cycle — you have a live,
   authenticated, encrypted telemetry graph.

Optional trigger: `last(/esp32-dht22/sensorTemperature/) > 30`.

Full runbook (triggers, time-window notes): [Zabbix runbook](interop/zabbix.md).

## 6. Home Assistant

Add to `configuration.yaml`:

```yaml
sensor:
  - platform: snmp
    name: "ESP32 Temperature"
    host: 192.168.1.50
    port: 161
    version: 3
    username: telemetry
    auth_key: auth-passphrase
    priv_key: priv-passphrase
    auth_protocol: sha256
    priv_protocol: aes
    oid: 1.3.6.1.4.1.67018.1.1.0
    accept_errors: true
    unit_of_measurement: "°C"
    value_template: "{{ value | float | multiply(0.1) | round(1) }}"
    scan_interval: 30

  - platform: snmp
    name: "ESP32 Humidity"
    host: 192.168.1.50
    port: 161
    version: 3
    username: telemetry
    auth_key: auth-passphrase
    priv_key: priv-passphrase
    auth_protocol: sha256
    priv_protocol: aes
    oid: 1.3.6.1.4.1.67018.1.1.1
    accept_errors: true
    unit_of_measurement: "%"
    value_template: "{{ value | float | multiply(0.1) | round(1) }}"
    scan_interval: 30
```

Restart Home Assistant. Add a **Gauge** or **History** card for
`sensor.esp32_temperature` and `sensor.esp32_humidity`.

Full runbook: [Home Assistant runbook](interop/home-assistant.md).

## 7. Traps & informs

The `trap_notification` example demonstrates the alerting path:

1. Flash `examples/trap_notification` with the same credentials.
2. Set the manager IP: `SNMPv3.setTrapManager(IPAddress(192, 168, 1, 100))`.
3. Press the button on GPIO 18 — the board sends an authPriv v3 trap/inform.
4. Receive it with `snmptrapd` (see the [net-snmp runbook](interop/net-snmp.md))
   or forward it into Zabbix / Home Assistant.

`sendTrap()` is fire-and-forget; `sendInform()` waits (up to 5 s) for the
manager's acknowledgement.

## 8. Troubleshooting

| Problem | Fix |
|---------|-----|
| `Cannot connect to SNMP host` | Check the board IP and that UDP :161 is reachable |
| `Authentication failure` | Passphrases don't match between board and manager |
| `Not in time window` after re-flash | Re-run the Zabbix interface test; HA re-syncs automatically |
| No data after first poll | Wait 30 s — that's the default poll interval |
| SHA-256 "unknown auth protocol" | net-snmp < 5.8 without SHA-2 — use `pysnmp_check.py` instead |

Per-manager troubleshooting tables live in the interop runbooks.

## 9. Next steps

- **API reference**: [`src/README.md`](../src/README.md)
- **Design & scope lock**: [`docs/DESIGN.md`](DESIGN.md)
- **SNMPv3 in 10 minutes**: [`docs/SNMPV3-BACKGROUND.md`](SNMPV3-BACKGROUND.md)
- **Interop runbooks**: [`docs/interop/`](interop/)
- **Test the configs without hardware**: [`tests/interop/mock_agent.py`](../tests/interop/mock_agent.py)
