#!/usr/bin/env python3
"""Failsafe/RTL trigger (tool_id=failsafe_trigger) — DEFENSIVE RESPONSE.

Commands the vehicle into RTL or LAND flight mode as an active countermeasure.
"""
import argparse, json, sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", required=True)
    ap.add_argument("--action", choices=["rtl", "land"], default="rtl")
    a = ap.parse_args()
    try:
        from pymavlink import mavutil
    except ImportError:
        print(json.dumps({"ok": False, "error": "pymavlink not installed"}))
        return 3
    m = mavutil.mavlink_connection(a.conn)
    m.wait_heartbeat(timeout=10)
    mode = {"rtl": "RTL", "land": "LAND"}[a.action]
    mode_id = (m.mode_mapping() or {}).get(mode)
    if mode_id is None:
        print(json.dumps({"ok": False, "error": f"mode {mode} not in vehicle mode map"}))
        return 1
    m.set_mode(mode_id)
    print(json.dumps({"ok": True, "action": a.action, "mode": mode}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
