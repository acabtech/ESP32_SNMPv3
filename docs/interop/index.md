# Interop runbooks

The agent speaks **SNMPv3 authPriv only** (HMAC-SHA-256 + AES-128 CFB), so the
manager must be configured for `authPriv` with `SHA-256` and `AES`. These
runbooks cover the managers the project is tested against.

| Manager | Runbook | Focus |
|---------|---------|-------|
| Zabbix 8 | [Zabbix](zabbix.md) | SNMPv3 interface, items, triggers, engine-cache notes |
| Home Assistant | [Home Assistant](home-assistant.md) | `snmp` sensor platform, YAML, value templates |
| net-snmp | [net-snmp](net-snmp.md) | `snmpget`/`walk`/`bulk`/`set`, `snmptrapd`, engine cache |

If you have no hardware yet, use the [interop tooling](../testing/interop.md):
`mock_agent.py` mimics the board's OIDs and credentials, and
`pysnmp_check.py` exercises authPriv get/walk/bulk/set from a PC.

For the complete flash → poll → dashboard → traps walkthrough, start with
[Getting Started](../GETTING-STARTED.md).
