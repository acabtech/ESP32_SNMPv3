#!/usr/bin/env python3
"""
mock_agent.py — a pysnmp SNMPv3 authPriv agent that mimics the
ESP32-SNMPv3-Agent board, so Zabbix / Home Assistant configs can be
validated **without hardware**.

It answers Get / GetNext / GetBulk / Set for the board's OIDs under
`enterprises.67018` with the same authPriv user (HMAC-SHA-256 + AES-128 CFB)
that the examples use. If a manager's config works against this mock, it will
work against the board.

Requirements (pysnmp 6.2.x — see tests/interop/README.md):
    python3 -m venv tests/.venv
    tests/.venv/bin/pip install pysnmp==6.2.6

Usage:
    tests/.venv/bin/python tests/interop/mock_agent.py --host 0.0.0.0 --port 1161
    # then point Zabbix / HA at <this-host>:1161 with:
    #   user telemetry, auth-passphrase / priv-passphrase, SHA-256 + AES-128

    # freeze the sensor values (no time-based variation):
    tests/.venv/bin/python tests/interop/mock_agent.py --static

Exit code 0 = clean shutdown (Ctrl-C), 1 = startup error.
"""
import argparse
import asyncio
import math
import sys
import time

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto import rfc1902
from pysnmp.smi import error

# --- OID layout (mirrors examples/dht22_telemetry + minimal_authpriv) --------
# enterprises.67018 = 1.3.6.1.4.1.67018 (IANA PEN, PT Alat Cerdas Adikarya
# Bersama)
#   .1.1.0  sensorTemperature  (degC * 10, signed, read-only)
#   .1.1.1  sensorHumidity     (% RH * 10, signed, read-only)
#   .1.2.0  appSetpoint        (read-write, mirrors the net-snmp SET example)
#   .2.1.0  appUptimeSeconds
#   .2.1.1  appFreeHeapBytes
#   .2.2.0  appButtonPressed
#
# A scalar's object OID excludes the trailing instance sub-id; the single
# instance lives at .0 (or .1 for the second column of the .1.1 object).
# Each instance maps to (label, maxAccess).
SCALARS = {
    (1, 3, 6, 1, 4, 1, 67018, 1, 1): {
        (0,): ("sensorTemperature", "read-only"),
        (1,): ("sensorHumidity", "read-only"),
    },
    (1, 3, 6, 1, 4, 1, 67018, 1, 2): {
        (0,): ("appSetpoint", "read-write"),
    },
    (1, 3, 6, 1, 4, 1, 67018, 2, 1): {
        (0,): ("appUptimeSeconds", "read-only"),
        (1,): ("appFreeHeapBytes", "read-only"),
    },
    (1, 3, 6, 1, 4, 1, 67018, 2, 2): {
        (0,): ("appButtonPressed", "read-only"),
    },
}

START = time.time()
STATIC = False


def _temp():
    """Temperature in tenths of a degree (slowly varying, ~21-27 C)."""
    if STATIC:
        return 245
    return int(240 + 30 * math.sin(time.time() / 60.0))


def _hum():
    """Relative humidity in tenths of a percent (slowly varying, ~40-60%)."""
    if STATIC:
        return 512
    return int(500 + 100 * math.sin(time.time() / 90.0))


def _uptime():
    return int(time.time() - START)


def _freeheap():
    return 180000


def _button():
    return 0


def _setpoint():
    return 0


VALUE_FNS = {
    "sensorTemperature": _temp,
    "sensorHumidity": _hum,
    "appSetpoint": _setpoint,
    "appUptimeSeconds": _uptime,
    "appFreeHeapBytes": _freeheap,
    "appButtonPressed": _button,
}


def build_mib(mib_builder):
    """Register the board's OIDs as dynamic read-only scalar instances."""
    MibScalar, MibScalarInstance = mib_builder.importSymbols(
        "SNMPv2-SMI", "MibScalar", "MibScalarInstance"
    )

    class DynInstance(MibScalarInstance):
        """A scalar instance whose value is computed on every read.

        Read-write instances remember the last SET value; read-only ones
        reject writes with NotWritableError (matching the board).
        """

        def __init__(self, typeName, instId, syntax, fn, writable=False):
            MibScalarInstance.__init__(self, typeName, instId, syntax)
            self._fn = fn
            self._writable = writable
            self._stored = None

        def getValue(self, name, idx):
            if self._writable and self._stored is not None:
                return self.syntax.clone(self._stored)
            return self.syntax.clone(self._fn())

        def setValue(self, value, name, idx):
            if not self._writable:
                raise error.NotWritableError(idx=idx, name=name)
            self._stored = int(value)
            return self.syntax.clone(self._stored)

    symbols = {}
    for i, (scalar_oid, instances) in enumerate(SCALARS.items()):
        # The parent scalar's access gates the write path, so it must be at
        # least as permissive as any of its instances.
        scalar_access = "read-write" if any(
            access == "read-write" for _, access in instances.values()
        ) else "read-only"
        scalar = MibScalar(scalar_oid, rfc1902.Integer32())
        scalar.setMaxAccess(scalar_access)
        symbols["scalar%d" % i] = scalar
        for j, (inst_id, (label, access)) in enumerate(instances.items()):
            inst = DynInstance(scalar.name, inst_id, scalar.syntax,
                               VALUE_FNS[label],
                               writable=(access == "read-write"))
            inst.setMaxAccess(access)
            symbols["inst%d_%d" % (i, j)] = inst

    mib_builder.exportSymbols("ESP32-SNMPV3-MOCK-MIB", **symbols)


def main():
    global STATIC

    ap = argparse.ArgumentParser(description="SNMPv3 authPriv mock agent")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; use 0.0.0.0 to "
                         "expose to Zabbix/HA)")
    ap.add_argument("--port", type=int, default=1161,
                    help="UDP port (default 1161; use 161 with privileges)")
    ap.add_argument("--user", default="telemetry")
    ap.add_argument("--auth-pass", default="auth-passphrase")
    ap.add_argument("--priv-pass", default="priv-passphrase")
    ap.add_argument("--static", action="store_true",
                    help="freeze sensor values (no time-based variation)")
    args = ap.parse_args()
    STATIC = args.static

    # Python 3.10+ no longer creates an implicit event loop; pysnmp's asyncio
    # transport needs one to exist before the engine is built.
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())

    snmp_engine = engine.SnmpEngine()

    # Transport: UDP server
    config.addTransport(
        snmp_engine,
        udp.domainName,
        udp.UdpTransport().openServerMode((args.host, args.port)),
    )

    # USM user: authPriv only (HMAC-SHA-256 + AES-128 CFB)
    config.addV3User(
        snmp_engine,
        args.user,
        config.usmHMAC192SHA256AuthProtocol, args.auth_pass,
        config.usmAesCfb128Protocol, args.priv_pass,
    )

    # VACM: full read/write access under 1.3.6 for this user
    config.addVacmUser(
        snmp_engine, 3, args.user, "authPriv", (1, 3, 6), (1, 3, 6)
    )

    # SNMP context + the board's MIB data
    snmp_context = context.SnmpContext(snmp_engine)
    build_mib(snmp_engine.msgAndPduDsp.mibInstrumController.mibBuilder)

    # Register the command responders
    cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
    cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
    cmdrsp.BulkCommandResponder(snmp_engine, snmp_context)
    cmdrsp.SetCommandResponder(snmp_engine, snmp_context)

    print("[mock] SNMPv3 authPriv agent on udp:%s:%d" % (args.host, args.port))
    print("[mock] user=%s  auth=SHA-256  priv=AES-128" % args.user)
    print("[mock] OIDs: 1.3.6.1.4.1.67018.1.1.0/.1, .2.1.0/.1, .2.2.0")
    print("[mock] Ctrl-C to stop")

    snmp_engine.transportDispatcher.jobStarted(1)
    try:
        snmp_engine.transportDispatcher.runDispatcher()
    except KeyboardInterrupt:
        pass
    finally:
        snmp_engine.transportDispatcher.closeDispatcher()
    return 0


if __name__ == "__main__":
    sys.exit(main())
