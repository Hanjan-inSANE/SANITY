#!/usr/bin/env python3
"""MAVLink heartbeat listener (tool_id=mav_heartbeat).

AUTHORIZED TESTBED ONLY (e.g. Damn Vulnerable Drone / ArduPilot SITL you own).
Prints the first HEARTBEAT's system/component id as JSON so the Toolset evidence
ledger records the recon result. Non-zero exit = no heartbeat / error.
"""
import argparse, json, sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", required=True, help="pymavlink connection, e.g. udpin:0.0.0.0:14550")
    ap.add_argument("--timeout", type=float, default=10.0)
    a = ap.parse_args()
    try:
        from pymavlink import mavutil
    except ImportError:
        print(json.dumps({"ok": False, "error": "pymavlink not installed (pip install pymavlink)"}))
        return 3
    m = mavutil.mavlink_connection(a.conn)
    hb = m.wait_heartbeat(timeout=a.timeout)
    if hb is None:
        print(json.dumps({"ok": False, "error": "no HEARTBEAT within timeout", "conn": a.conn}))
        return 1
    print(json.dumps({"ok": True, "system_id": m.target_system, "component_id": m.target_component,
                      "type": hb.type, "autopilot": hb.autopilot, "base_mode": hb.base_mode}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
