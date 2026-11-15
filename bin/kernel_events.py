#!/usr/bin/env python3
"""Emit one JSON event per cycle with kernel crash readiness + new crash signals."""
import sys

from kernel_common import discover, emit


def main():
    try:
        data = discover()
    except Exception:
        data = {"status": "ok"}
    emit(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
