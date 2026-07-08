#!/usr/bin/env python3
"""Enable MAVLink2 message signing (tool_id=mavlink_signing) — DEFENSE.

Installs a signing key on the link so unsigned injected messages are rejected.
Verify by replaying an unsigned inject afterwards: it should be dropped.
"""
import argparse, hashlib, json, sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", required=True)
    ap.add_argument("--key", required=True, help="passphrase; sha256 -> 32-byte signing secret")
    a = ap.parse_args()
    try:
        from pymavlink import mavutil
    except ImportError:
        print(json.dumps({"ok": False, "error": "pymavlink not installed"}))
        return 3
    m = mavutil.mavlink_connection(a.conn)
    m.wait_heartbeat(timeout=10)
    m.setup_signing(hashlib.sha256(a.key.encode()).digest(), sign_outgoing=True)
    print(json.dumps({"ok": True, "signing": "enabled", "link": a.conn}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
