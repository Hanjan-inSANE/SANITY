#!/usr/bin/env python3
"""Scapy packet-craft template (tool_id=scapy).

AUTHORIZED TESTBED ONLY. Sends --count crafted UDP packets to --target:--port.
Edit craft() for the real protocol/payload you need to exercise.
"""
import argparse, json, sys


def craft(target, port):
    from scapy.all import IP, UDP, Raw
    # Customize this payload for the target protocol under test.
    return IP(dst=target) / UDP(dport=port) / Raw(load=b"\xfe\x00\x00\x00")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None)
    ap.add_argument("--target", required=True)
    ap.add_argument("--port", type=int, default=14550)
    ap.add_argument("--count", type=int, default=10)
    a = ap.parse_args()
    try:
        from scapy.all import send
    except ImportError:
        print(json.dumps({"ok": False, "error": "scapy not installed (pip install scapy)"}))
        return 3
    send(craft(a.target, a.port), count=a.count, iface=a.iface, verbose=0)
    print(json.dumps({"ok": True, "sent": a.count, "target": a.target, "port": a.port}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
