# tests/interop — scripted interop tooling

- `pysnmp_check.py` — SNMPv3 authPriv get/walk/bulk/set from a PC.
  Runs against: a real device, a pysnmp **mock agent** (below), or any
  standards-compliant SNMPv3 node (even a PC running net-snmp's `snmpd`
  as a reference agent while the library is under construction).

## Python environment (oracle + checker)

    python3 -m venv /tmp/pv
    /tmp/pv/bin/pip install pysnmp==6.2.6 cryptography

pysnmp **6.2.6** is the pinned oracle/checker version (SHA-2 USM auth lives
at `pysnmp.proto.secmod.rfc7860.auth.hmacsha2`; the sync `pysnmp.hlapi`
facade is retained). The same venv drives
`tests/host/vgen/gen_vectors.py`.

## Mock agent (planned, M2)

A pysnmp `CommandResponder` configured with exactly one user
(`telemetry` / `auth-passphrase` / `priv-passphrase`, SHA-256 + AES-128)
that mimics the board's OIDs (`1.3.6.1.4.1.99999.*`). Purpose:

- Validate the **Zabbix** and **Home Assistant** runbooks **before any
  hardware exists** — if the config works against the mock, it works
  against the board.
- A fixture for the agent's own interop CI later (optional, network-gated).