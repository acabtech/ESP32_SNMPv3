#!/usr/bin/env python3
"""
pysnmp_check.py — SNMPv3 authPriv (SHA-256 + AES-128) interop checker.

Targets the ESP32-SNMPv3-Agent's wire behavior from a PC, no hardware needed
to develop the script: point it at a device, at a pysnmp mock agent, or at
any standards-compliant SNMPv3 node.

Requirements (pysnmp 6.2.x — see tests/interop/README.md):
  python3 -m venv /tmp/pv
  /tmp/pv/bin/pip install pysnmp==6.2.6

Usage:
  /tmp/pv/bin/python pysnmp_check.py --host 192.168.100.50 --user telemetry \
      --auth-pass auth-passphrase --priv-pass priv-passphrase \
      get 1.3.6.1.4.1.67018.1.1.0
  ... walk 1.3.6.1.4.1.67018
  ... bulk 1.3.6.1.4.1.67018 --max-repetitions 10
  ... set 1.3.6.1.4.1.67018.1.2.0 42

Exit code 0 = success, 1 = SNMP error, 2 = usage/connect error.
"""
import argparse
import sys

from pysnmp.hlapi import (
    SnmpEngine, UsmUserData, UdpTransportTarget,
    getCmd, nextCmd, bulkCmd, setCmd,
)
# authPriv protocol identifiers (pysnmp 6.2.x)
try:
    from pysnmp.hlapi import (usmHMAC192SHA256AuthProtocol as AUTH_PROTO,
                              usmAesCfb128Protocol as PRIV_PROTO)
except ImportError:  # older trees keep them under hlapi.asyncio.auth
    from pysnmp.hlapi.asyncio.auth import (usmHMAC192SHA256AuthProtocol as AUTH_PROTO,
                                           usmAesCfb128Protocol as PRIV_PROTO)
from pysnmp.proto.rfc1902 import Integer32, ObjectType, ObjectName


def main():
    ap = argparse.ArgumentParser(description="SNMPv3 authPriv check")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=161)
    ap.add_argument("--user", default="telemetry")
    ap.add_argument("--auth-pass", required=True)
    ap.add_argument("--priv-pass", required=True)
    ap.add_argument("--max-repetitions", type=int, default=10)
    ap.add_argument("action", choices=["get", "walk", "bulk", "set"])
    ap.add_argument("oid")
    ap.add_argument("set_value", type=int, nargs="?", default=None)
    args = ap.parse_args()

    udp = UdpTransportTarget((args.host, args.port), timeout=3.0, retries=2)
    user = UsmUserData(
        args.user,
        authKey=args.auth_pass, privKey=args.priv_pass,
        authProtocol=AUTH_PROTO, privProtocol=PRIV_PROTO,
    )

    def show(tag, error_ind, error_status, var_binds):
        if error_ind:
            print(f"[{tag}] ERROR: {error_ind}"); sys.exit(2)
        if error_status:
            print(f"[{tag}] SNMP error: {error_status.prettyPrint()}")
            sys.exit(1)
        for name, val in var_binds:
            print(f"[{tag}] {name.prettyPrint()} = {val.prettyPrint()}")

    if args.action == "get":
        show("get", *getCmd(SnmpEngine(), user, udp,
                            ObjectType(ObjectName(args.oid))))
    elif args.action == "walk":
        for row in nextCmd(SnmpEngine(), user, udp,
                           ObjectType(ObjectName(args.oid)),
                           lexicographicMode=True):
            err_ind, err_stat, var_binds = row[0], row[1], row[2]
            show("walk", err_ind, err_stat, var_binds)
    elif args.action == "bulk":
        for row in bulkCmd(SnmpEngine(), user, udp, 0,
                           args.max_repetitions,
                           ObjectType(ObjectName(args.oid)),
                           lexicographicMode=True):
            err_ind, err_stat, var_binds = row[0], row[1], row[2]
            show("bulk", err_ind, err_stat, var_binds)
    elif args.action == "set":
        if args.set_value is None:
            print("set requires a value"); sys.exit(2)
        show("set", *setCmd(SnmpEngine(), user, udp,
                            ObjectType(ObjectName(args.oid),
                                       Integer32(args.set_value))))
    return 0


if __name__ == "__main__":
    sys.exit(main())