#!/usr/bin/env python3
"""MAVLink message/command injector (tool_id=pymavlink_inject).

AUTHORIZED TESTBED ONLY. Sends an arbitrary MAVLink message named by --msg with
JSON fields from --params to the target --sys/--comp. Examples:
  --msg COMMAND_LONG --params '{"command":400,"confirmation":0,"param1":1,"param2":0,
     "param3":0,"param4":0,"param5":0,"param6":0,"param7":0}'   # MAV_CMD_COMPONENT_ARM_DISARM
  --msg SET_MODE     --params '{"base_mode":1,"custom_mode":4}'
"""
import argparse, json, sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", required=True)
    ap.add_argument("--sys", type=int, default=1)
    ap.add_argument("--comp", type=int, default=1)
    ap.add_argument("--msg", required=True, help="MAVLink message name, e.g. COMMAND_LONG")
    ap.add_argument("--params", default="{}", help="JSON object of message fields")
    a = ap.parse_args()
    try:
        from pymavlink import mavutil
    except ImportError:
        print(json.dumps({"ok": False, "error": "pymavlink not installed"}))
        return 3
    try:
        fields = json.loads(a.params)
    except json.JSONDecodeError as e:
        print(json.dumps({"ok": False, "error": f"bad --params JSON: {e}"}))
        return 2
    m = mavutil.mavlink_connection(a.conn)
    m.wait_heartbeat(timeout=10)
    m.target_system, m.target_component = a.sys, a.comp
    send = getattr(m.mav, a.msg.lower() + "_send", None)
    if send is None:
        print(json.dumps({"ok": False, "error": f"unknown MAVLink message: {a.msg}"}))
        return 2
    # COMMAND_LONG/SET_MODE etc. carry their own target fields; inject sensible defaults.
    fields.setdefault("target_system", a.sys)
    fields.setdefault("target_component", a.comp)
    try:
        send(**fields)
    except TypeError as e:
        print(json.dumps({"ok": False, "error": f"field mismatch for {a.msg}: {e}"}))
        return 2
    print(json.dumps({"ok": True, "sent": a.msg, "target_system": a.sys,
                      "target_component": a.comp, "fields": fields}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
