# tests/interop — scripted interop tooling

- `pysnmp_check.py` — SNMPv3 authPriv get/walk/bulk/set from a PC.
  Runs against: a real device, the **mock agent** (below), or any
  standards-compliant SNMPv3 node.
- `mock_agent.py` — a pysnmp `CommandResponder` that mimics the board's OIDs
  and authPriv user, so manager configs can be validated **without hardware**.

## Python environment (oracle + checker + mock)

    python3 -m venv tests/.venv
    tests/.venv/bin/pip install pysnmp==6.2.6 cryptography

pysnmp **6.2.6** is the pinned oracle/checker/mock version. Note that in
6.2.6 the synchronous `pysnmp.hlapi` facade is gone — the tooling uses
`pysnmp.hlapi.asyncio` (`getCmd` / `walkCmd` / `bulkWalkCmd` / `setCmd`).
The same venv drives `tests/host/vgen/gen_vectors.py`.

## Mock agent

`mock_agent.py` registers exactly one user
(`telemetry` / `auth-passphrase` / `priv-passphrase`, SHA-256 + AES-128) and
mimics the board's OIDs under `1.3.6.1.4.1.67018`:

| OID | Name | Access |
|-----|------|--------|
| `.1.1.0` | sensorTemperature (°C × 10) | read-only |
| `.1.1.1` | sensorHumidity (%RH × 10) | read-only |
| `.1.2.0` | appSetpoint | read-write |
| `.2.1.0` | appUptimeSeconds | read-only |
| `.2.1.1` | appFreeHeapBytes | read-only |
| `.2.2.0` | appButtonPressed | read-only |

Purpose:

- Validate the **Zabbix** and **Home Assistant** runbooks **before any
  hardware exists** — if the config works against the mock, it works
  against the board.
- A fixture for the agent's own interop CI later (optional, network-gated).

### Run it

    # listen on all interfaces, port 1161 (port 161 needs privileges)
    tests/.venv/bin/python tests/interop/mock_agent.py --host 0.0.0.0 --port 1161

    # point Zabbix / HA at <this-host>:1161 with the credentials above,
    # or drive it from the checker:
    tests/.venv/bin/python tests/interop/pysnmp_check.py --host 127.0.0.1 --port 1161 \
        --user telemetry --auth-pass auth-passphrase \
        --priv-pass priv-passphrase walk 1.3.6.1.4.1.67018

Options: `--static` freezes the sensor values (no time-based variation);
`--user`, `--auth-pass`, `--priv-pass` override the credentials.