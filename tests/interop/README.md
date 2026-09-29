# tests/interop — scripted interop tooling (M1+)

- `pysnmp_check.py` — SNMPv3 authPriv get/walk/bulk/set from a PC.
  Runs against: a real device, a pysnmp **mock agent** (below), or any
  standards-compliant SNMPv3 node (even a PC running net-snmp's `snmpd`
  as a reference agent while the library is under construction).

## Mock agent (planned, M1)

A pysnmp `CommandResponder` configured with exactly one user
(`telemetry` / `auth-passphrase` / `priv-passphrase`, SHA-256 + AES-128)
that mimics the board's OIDs (`1.3.6.1.4.1.99999.*`). Purpose:

- Validate the **Zabbix** and **Home Assistant** runbooks **before any
  hardware exists** — if the config works against the mock, it works
  against the board.
- A fixture for the agent's own interop CI later (optional, network-gated).

pysnmp's mock responder supports SHA-2 only in newer pysnmp builds — pin and
verify during M1; fallback is `-a SHA` + config.USM_AUTH_SHA2_256 if the
installed tree exposes it.