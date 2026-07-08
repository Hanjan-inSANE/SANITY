#!/usr/bin/env python3
"""boofuzz session skeleton (tool_id=boofuzz).

AUTHORIZED TESTBED ONLY. Minimal generic TCP fuzz session. Replace the s_initialize
block with the real protocol definition. Crashes/timeouts land in boofuzz's own db;
point Toolset collect_findings at that dir or parse the printed summary.
"""
import argparse, json, sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--runs", type=int, default=200)
    a = ap.parse_args()
    try:
        from boofuzz import Session, Target, TCPSocketConnection, Request, Block, String, Static
    except Exception as e:  # noqa: BLE001 - boofuzz API varies across versions
        print(json.dumps({"ok": False, "error": f"boofuzz not installed/incompatible: {e}"}))
        return 3
    try:
        session = Session(target=Target(connection=TCPSocketConnection(a.host, a.port)),
                          receive_data_after_fuzz=True)
        req = Request("generic", children=(Block("body", children=(
            Static(name="prefix", default_value=b""),
            String(name="fuzz", default_value="A"),
        )),))
        session.connect(req)
        session.fuzz(max_depth=a.runs)
        print(json.dumps({"ok": True, "host": a.host, "port": a.port, "note": "customize protocol block"}))
        return 0
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ok": False, "error": f"boofuzz session error: {e}"}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
