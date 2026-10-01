# net-snmp interop — the engineering toolchain

net-snmp is how we debug the agent day-to-day. Install: `apt install snmp`.

> SHA-256 support needs net-snmp ≥ 5.8 compiled with SHA-2 enabled. Debian
> ships 5.9.x; verify quickly:
> `snmpget -h 2>&1 | grep -i "SHA-256"`

## ~/.snmp/snmp.conf

```ini
defVersion 3
defSecurityName telemetry
defSecurityLevel authPriv
defAuthType SHA-256
defAuthPassphrase auth-passphrase
defPrivType AES
defPrivPassphrase priv-passphrase
```

## Reads (device IP 192.168.100.50)

```bash
snmpget    -v3 -l authPriv -u telemetry -a SHA-256 -A auth-passphrase \
           -x AES -X priv-passphrase udp:192.168.100.50:161 \
           1.3.6.1.4.1.67018.1.1.0

snmpwalk   -v3 -l authPriv -u telemetry -a SHA-256 -A auth-passphrase \
           -x AES -X priv-passphrase udp:192.168.100.50:161 \
           1.3.6.1.4.1.67018

snmpgetnext / snmpgetbulk (replace snmpget with snmpgetnext / snmpgetbulk -C r10 ...)

# Engine state (should echo the device's boots/time):
snmpget -v3 -l authNoPriv -u telemetry -a SHA-256 -A auth-passphrase \
        udp:192.168.100.50:161 1.3.6.1.6.3.1.1.5.1    # snmpEngineBoots
```

## Writes

```bash
snmpset -v3 -l authPriv -u telemetry -a SHA-256 -A auth-passphrase \
        -x AES -X priv-passphrase udp:192.168.100.50:161 \
        1.3.6.1.4.1.67018.1.2.0 i 42
```

## Traps (M3; test the agent's notification path)

```bash
# snmptrapd.conf
authCommunity log exec
disableAuthorization yes

# listener
snmptrapd -f -Lo

# press the button on the trap_notification example — expect a line like:
#   TRAP ... UDP: [192.168.100.50]:162 ... 1.3.6.1.4.1.67018.2.2.0
```

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `Authentication failure (incorrect password, community or user)` | Localized keys changed (device re-flashed / engineID changed). Clear the net-snmp engine cache: delete files under `~/.snmp/` for that host (or do a fresh `snmpget` with `-Cc`? not applicable — just rm the cache and retry; discovery re-runs). |
| `Response from ... did not match` engine ID | Cache cleanup as above. |
| `Unknown user name` | Wrong username vs `SNMPv3.addUser(...)` on device. |
| `Report command failed: Unsupported security level` | You sent noAuthPriv/noPriv; library only speaks **authPriv** — listener and `snmp.conf` must agree. |
| SHA-256 "unknown auth protocol" from CLI | Distro build lacks SHA-2 — use `-a SHA` won't help (SHA-256 only): build/backport net-snmp, or test with pysnmp_check.py instead. |