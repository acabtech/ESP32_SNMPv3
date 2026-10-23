#!/usr/bin/env python3
"""
pysnmp_check.py — SNMPv3 authPriv (SHA-256 + AES-128) interop checker.

Targets the ESP32-SNMPv3-Agent's wire behavior from a PC, no hardware needed
to develop the script: point it at a device, at the pysnmp mock agent
(`mock_agent.py`), or at any standards-compliant SNMPv3 node.

Requirements (pysnmp 6.2.x — see tests/interop/README.md):
  python3 -m venv tests/.venv
  tests/.venv/bin/pip install pysnmp==6.2.6

Usage:
  tests/.venv/bin/python tests/interop/pysnmp_check.py --host 192.168.100.50 --user telemetry \
      --auth-pass auth-passphrase --priv-pass priv-passphrase \
      get 1.3.6.1.4.1.67018.1.1.0
  ... walk 1.3.6.1.4.1.67018
  ... bulk 1.3.6.1.4.1.67018 --max-repetitions 10
  ... set 1.3.6.1.4.1.67018.1.2.0 42

Exit code 0 = success, 1 = SNMP error, 2 = usage/connect error.
"""
import argparse
import asyncio
import sys

from pysnmp.hlapi.asyncio import (
    SnmpEngine, UsmUserData, UdpTransportTarget, ContextData,
    getCmd, walkCmd, bulkWalkCmd, setCmd,
    usmHMAC192SHA256AuthProtocol as AUTH_PROTO,
    usmAesCfb128Protocol as PRIV_PROTO,
    ObjectType, ObjectIdentity, Integer32,
)


def show(tag, error_ind, error_status, error_index, var_binds):
    if error_ind:
        print(f"[{tag}] ERROR: {error_ind}")
        sys.exit(2)
    if error_status:
        print(f"[{tag}] SNMP error: {error_status.prettyPrint()}")
        sys.exit(1)
    for name, val in var_binds:
        print(f"[{tag}] {name.prettyPrint()} = {val.prettyPrint()}")


async def run(args):
    engine = SnmpEngine()
    user = UsmUserData(
        args.user,
        authKey=args.auth_pass, privKey=args.priv_pass,
        authProtocol=AUTH_PROTO, privProtocol=PRIV_PROTO,
    )
    target = UdpTransportTarget((args.host, args.port), timeout=3.0, retries=2)
    ctx = ContextData()
    oid = ObjectType(ObjectIdentity(args.oid))

    if args.action == "get":
        show("get", *(await getCmd(engine, user, target, ctx, oid)))
    elif args.action == "walk":
        async for row in walkCmd(engine, user, target, ctx, oid,
                                 lexicographicMode=False):
            show("walk", *row)
    elif args.action == "bulk":
        async for row in bulkWalkCmd(engine, user, target, ctx, 0,
                                     args.max_repetitions, oid,
                                     lexicographicMode=False):
            show("bulk", *row)
    elif args.action == "set":
        if args.set_value is None:
            print("set requires a value")
            sys.exit(2)
        show("set", *(await setCmd(
            engine, user, target, ctx,
            ObjectType(ObjectIdentity(args.oid), Integer32(args.set_value)),
        )))
    return 0


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
    try:
        return asyncio.run(run(args))
    except SystemExit:
        raise
    except Exception as exc:  # client-side config / transport errors
        print(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
