# Home Assistant interop — SNMPv3 authPriv

Home Assistant's built-in `snmp` integration supports SNMPv3 with per-protocol
auth/priv selection (HA ≥ 2021.x). Verified config keys below; double-check
against your HA version's docs since the integration was modernized over time.

## Device side

Same as the Zabbix runbook: user `telemetry` / `auth-passphrase` /
`priv-passphrase`, e.g. IP `192.168.100.50`.

## HA configuration.yaml

```yaml
sensor:
  - platform: snmp
    name: "ESP32 Temperature"
    host: 192.168.100.50
    port: 161
    version: 3
    username: telemetry
    auth_key: auth-passphrase
    priv_key: priv-passphrase
    auth_protocol: sha256      # md5 | sha | sha224 | sha256 | sha384 | sha512
    priv_protocol: aes         # des | aes
    oid: 1.3.6.1.4.1.99999.1.1.0
    accept_errors: true        # agent may answer Report() while re-syncing
    unit_of_measurement: "°C"
    value_template: "{{ value | float | multiply(0.1) | round(1) }}"
    scan_interval: 30

  - platform: snmp
    name: "ESP32 Humidity"
    host: 192.168.100.50
    port: 161
    version: 3
    username: telemetry
    auth_key: auth-passphrase
    priv_key: priv-passphrase
    auth_protocol: sha256
    priv_protocol: aes
    oid: 1.3.6.1.4.1.99999.1.1.1
    accept_errors: true
    unit_of_measurement: "%"
    value_template: "{{ value | float | multiply(0.1) | round(1) }}"
    scan_interval: 30
```

Notes:

- `baseoid` (a common subtree) may replace repeating the root per sensor in
  newer HA versions; both patterns work with the agent.
- If a sensor shows `unknown` right after a device re-flash, HA re-learns the
  engine via the report exchange automatically on the next poll.
- `auth_protocol: sha256` + `priv_protocol: aes` is exactly the library's
  authPriv mode.

## Verify

HA → Settings → Devices → the sensor entities should read legit values.
To exercise the trap path, use an HA `snmptrapd` bridge or an automation
polling more frequently — traps are optional in v0.1 anyway.