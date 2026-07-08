#!/usr/bin/env python3
"""ArduPilot parameter hardening (tool_id=ardupilot_param_harden) — DEFENSE.

Applies safe PARAM_SET values from --set JSON, e.g. {"ARMING_CHECK":1,"FS_GCS_ENABLE":1}.
"""
import argparse, json, sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", required=True)
    ap.add_argument("--set", required=True, help='JSON {PARAM: value}')
    a = ap.parse_args()
    try:
        from pymavlink import mavutil
    except ImportError:
        print(json.dumps({"ok": False, "error": "pymavlink not installed"}))
        return 3
    try:
        kv = json.loads(a.set)
    except json.JSONDecodeError as e:
        print(json.dumps({"ok": False, "error": f"bad --set JSON: {e}"}))
        return 2
    m = mavutil.mavlink_connection(a.conn)
    m.wait_heartbeat(timeout=10)
    applied = {}
    for k, v in kv.items():
        m.mav.param_set_send(m.target_system, m.target_component,
                             k.encode()[:16], float(v),
                             mavutil.mavlink.MAV_PARAM_TYPE_REAL32)
        applied[k] = v
    print(json.dumps({"ok": True, "applied": applied}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
