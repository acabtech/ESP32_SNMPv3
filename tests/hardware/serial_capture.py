#!/usr/bin/env python3
"""Configurable serial capture for on-device (hardware) testing.

Reads the ESP32-S3 USB-Serial console, optionally resets the board first so
boot-time messages (Wi-Fi IP, "[SNMP] agent ready ...") are captured, and
prints every line. Exits early when --expect matches, or after --duration.

Requires pyserial:  tests/.venv/bin/pip install pyserial

Examples:
    # capture 20 s of boot output from the default port
    tests/.venv/bin/python tests/hardware/serial_capture.py

    # different port / baud, stop as soon as the IP line appears
    tests/.venv/bin/python tests/hardware/serial_capture.py \
        --port /dev/ttyUSB0 --baud 115200 --expect "Wi-Fi connected"

    # no reset (just tail a running board)
    tests/.venv/bin/python tests/hardware/serial_capture.py --no-reset
"""
from __future__ import annotations

import argparse
import re
import sys
import time

try:
    import serial  # pyserial
except ImportError:  # pragma: no cover - environment guard
    sys.exit("pyserial is required: tests/.venv/bin/pip install pyserial")


def hard_reset(ser: "serial.Serial") -> None:
    """Pulse the ESP32-S3 reset line via the USB-Serial/JTAG bridge.

    DTR drives GPIO0 (boot strap), RTS drives EN (chip reset). Keeping DTR
    low holds GPIO0 high so the chip boots normally (not into the ROM
    bootloader) when EN is released.
    """
    ser.dtr = False  # GPIO0 high -> normal boot
    ser.rts = True   # EN low -> reset asserted
    time.sleep(0.1)
    ser.rts = False  # EN high -> release reset, run
    time.sleep(0.05)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="/dev/ttyACM0",
                    help="serial device (default: /dev/ttyACM0)")
    ap.add_argument("--baud", type=int, default=115200,
                    help="baud rate (default: 115200)")
    ap.add_argument("--duration", type=float, default=20.0,
                    help="max seconds to capture (default: 20)")
    ap.add_argument("--expect", default=None,
                    help="regex; stop as soon as a line matches")
    ap.add_argument("--no-reset", action="store_true",
                    help="do not reset the board before capturing")
    args = ap.parse_args()

    pattern = re.compile(args.expect) if args.expect else None

    def open_port() -> "serial.Serial":
        try:
            return serial.Serial(args.port, args.baud, timeout=0.2)
        except serial.SerialException as exc:
            sys.exit(f"cannot open {args.port}: {exc}")

    ser = open_port()
    if not args.no_reset:
        # With USB CDC on boot the device re-enumerates when the sketch takes
        # over, so the handle opened before reset goes stale. Reset, then
        # reopen after the USB device has come back.
        hard_reset(ser)
        ser.close()
        time.sleep(1.5)
        ser = open_port()

    with ser:
        deadline = time.monotonic() + args.duration
        buf = b""
        while time.monotonic() < deadline:
            try:
                chunk = ser.read(256)
            except serial.SerialException:
                # Re-enumeration mid-capture: reopen and keep going.
                ser.close()
                time.sleep(0.5)
                ser = open_port()
                continue
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode("utf-8", "replace").rstrip("\r")
                print(text, flush=True)
                if pattern and pattern.search(text):
                    return 0
        if buf:
            print(buf.decode("utf-8", "replace").rstrip("\r"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
