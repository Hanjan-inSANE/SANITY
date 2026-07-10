#!/usr/bin/env python3
"""Small MAVLink TCP target for local SANITY/QGC smoke tests.

This is not ArduPilot and not Damn Vulnerable Drone. It exists so the
compose target containers expose a real MAVLink-speaking endpoint instead of
sleeping forever. QGroundControl can connect to tcp://127.0.0.1:5760 and
SANITY tools can perform basic command/telemetry probes.
"""
from __future__ import annotations

import os
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field


CRC_EXTRA = {
    0: 50,    # HEARTBEAT
    1: 124,   # SYS_STATUS
    11: 89,   # SET_MODE
    22: 220,  # PARAM_VALUE
    23: 168,  # PARAM_SET
    24: 24,   # GPS_RAW_INT
    30: 39,   # ATTITUDE
    33: 104,  # GLOBAL_POSITION_INT
    76: 152,  # COMMAND_LONG
    77: 143,  # COMMAND_ACK
}

MAV_TYPE_QUADROTOR = 2
MAV_AUTOPILOT_ARDUPILOTMEGA = 3
MAV_MODE_FLAG_CUSTOM_MODE_ENABLED = 1
MAV_MODE_FLAG_SAFETY_ARMED = 128
MAV_STATE_ACTIVE = 4
MAV_RESULT_ACCEPTED = 0
MAV_PARAM_TYPE_REAL32 = 9

MAV_CMD_DO_SET_HOME = 179
MAV_CMD_DO_REPOSITION = 192
MAV_CMD_COMPONENT_ARM_DISARM = 400


def x25_crc(data: bytes, extra: int) -> int:
    crc = 0xFFFF
    for byte in data + bytes([extra]):
        tmp = byte ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


@dataclass
class VehicleState:
    sysid: int = int(os.getenv("SYSID_THISMAV", "1"))
    compid: int = int(os.getenv("MAV_COMP_ID", "1"))
    seq: int = 0
    armed: bool = False
    custom_mode: int = 0
    lat: int = int(float(os.getenv("MAV_LAT", "37.5665")) * 1e7)
    lon: int = int(float(os.getenv("MAV_LON", "126.9780")) * 1e7)
    alt_mm: int = int(float(os.getenv("MAV_ALT_M", "30.0")) * 1000)
    home_lat: int = field(init=False)
    home_lon: int = field(init=False)
    boot_time: float = field(default_factory=time.monotonic)
    params: dict[str, float] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self.home_lat = self.lat
        self.home_lon = self.lon

    def packet(self, msgid: int, payload: bytes) -> bytes:
        with self.lock:
            seq = self.seq
            self.seq = (self.seq + 1) % 256
        header = struct.pack("<BBBBB", len(payload), seq, self.sysid, self.compid, msgid)
        crc = x25_crc(header + payload, CRC_EXTRA[msgid])
        return b"\xfe" + header + payload + struct.pack("<H", crc)

    def time_boot_ms(self) -> int:
        return int((time.monotonic() - self.boot_time) * 1000) & 0xFFFFFFFF

    def heartbeat(self) -> bytes:
        base_mode = MAV_MODE_FLAG_CUSTOM_MODE_ENABLED
        if self.armed:
            base_mode |= MAV_MODE_FLAG_SAFETY_ARMED
        payload = struct.pack(
            "<IBBBBB",
            self.custom_mode,
            MAV_TYPE_QUADROTOR,
            MAV_AUTOPILOT_ARDUPILOTMEGA,
            base_mode,
            MAV_STATE_ACTIVE,
            3,
        )
        return self.packet(0, payload)

    def sys_status(self) -> bytes:
        payload = struct.pack(
            "<IIIHHhBHHHHHH",
            0,
            0,
            0,
            500,
            12000,
            0,
            95,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        return self.packet(1, payload)

    def gps_raw_int(self) -> bytes:
        payload = struct.pack(
            "<QiiiHHHHBB",
            int(time.time() * 1_000_000),
            self.lat,
            self.lon,
            self.alt_mm,
            100,
            100,
            0,
            0,
            3,
            12,
        )
        return self.packet(24, payload)

    def global_position_int(self) -> bytes:
        payload = struct.pack(
            "<IiiiihhhH",
            self.time_boot_ms(),
            self.lat,
            self.lon,
            self.alt_mm,
            self.alt_mm,
            0,
            0,
            0,
            0xFFFF,
        )
        return self.packet(33, payload)

    def attitude(self) -> bytes:
        payload = struct.pack("<Iffffff", self.time_boot_ms(), 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        return self.packet(30, payload)

    def command_ack(self, command: int) -> bytes:
        return self.packet(77, struct.pack("<HB", command, MAV_RESULT_ACCEPTED))

    def param_value(self, name: str, value: float, index: int = 0) -> bytes:
        param_id = name.encode("ascii", "ignore")[:16].ljust(16, b"\0")
        payload = struct.pack("<fHH16sB", value, max(1, len(self.params)), index, param_id, MAV_PARAM_TYPE_REAL32)
        return self.packet(22, payload)


def parse_packets(buffer: bytearray) -> list[tuple[int, bytes]]:
    packets: list[tuple[int, bytes]] = []
    while buffer:
        magic = buffer[0]
        if magic not in (0xFE, 0xFD):
            del buffer[0]
            continue
        if magic == 0xFE:
            if len(buffer) < 8:
                break
            length = buffer[1]
            total = 8 + length
            if len(buffer) < total:
                break
            msgid = buffer[5]
            payload = bytes(buffer[6 : 6 + length])
            del buffer[:total]
            packets.append((msgid, payload))
        else:
            if len(buffer) < 12:
                break
            length = buffer[1]
            signed = bool(buffer[2] & 0x01)
            total = 12 + length + (13 if signed else 0)
            if len(buffer) < total:
                break
            msgid = buffer[7] | (buffer[8] << 8) | (buffer[9] << 16)
            payload = bytes(buffer[10 : 10 + length])
            del buffer[:total]
            packets.append((msgid, payload))
    return packets


def handle_packet(conn: socket.socket, state: VehicleState, msgid: int, payload: bytes) -> None:
    if msgid == 11 and len(payload) >= 6:
        custom_mode, target_system, base_mode = struct.unpack("<IBB", payload[:6])
        if target_system in (0, state.sysid):
            state.custom_mode = custom_mode
            state.armed = bool(base_mode & MAV_MODE_FLAG_SAFETY_ARMED) or state.armed
            print(f"[target] SET_MODE custom_mode={custom_mode} base_mode={base_mode}", flush=True)
    elif msgid == 23 and len(payload) >= 23:
        value, target_system, _target_component, raw_name, _param_type = struct.unpack("<fBB16sB", payload[:23])
        if target_system in (0, state.sysid):
            name = raw_name.split(b"\0", 1)[0].decode("ascii", "ignore") or "PARAM"
            state.params[name] = value
            conn.sendall(state.param_value(name, value))
            print(f"[target] PARAM_SET {name}={value}", flush=True)
    elif msgid == 76 and len(payload) >= 33:
        fields = struct.unpack("<fffffffHBBB", payload[:33])
        p1, _p2, _p3, _p4, p5, p6, p7, command, target_system, _target_component, _confirmation = fields
        if target_system not in (0, state.sysid):
            return
        if command == MAV_CMD_COMPONENT_ARM_DISARM:
            state.armed = p1 > 0.5
        elif command == MAV_CMD_DO_SET_HOME:
            if p5 and p6:
                state.home_lat = int(p5 * 1e7)
                state.home_lon = int(p6 * 1e7)
                state.alt_mm = int(p7 * 1000)
        elif command == MAV_CMD_DO_REPOSITION:
            if p5 and p6:
                state.lat = int(p5 * 1e7)
                state.lon = int(p6 * 1e7)
                state.alt_mm = int(p7 * 1000)
        conn.sendall(state.command_ack(command))
        print(f"[target] COMMAND_LONG command={command} accepted", flush=True)


def client_loop(conn: socket.socket, addr: tuple[str, int], state: VehicleState) -> None:
    print(f"[target] client connected {addr[0]}:{addr[1]}", flush=True)
    conn.setblocking(False)
    buf = bytearray()
    next_tx = 0.0
    try:
        while True:
            now = time.monotonic()
            if now >= next_tx:
                for packet in (
                    state.heartbeat(),
                    state.sys_status(),
                    state.gps_raw_int(),
                    state.global_position_int(),
                    state.attitude(),
                ):
                    conn.sendall(packet)
                next_tx = now + 1.0

            readable, _, _ = select.select([conn], [], [], 0.2)
            if readable:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                for msgid, payload in parse_packets(buf):
                    handle_packet(conn, state, msgid, payload)
    except (ConnectionError, OSError) as exc:
        print(f"[target] client disconnected: {exc}", flush=True)
    finally:
        conn.close()


def main() -> None:
    host = os.getenv("MAV_TCP_HOST", "0.0.0.0")
    port = int(os.getenv("MAV_TCP_PORT", "5760"))
    state = VehicleState()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(8)
        print(
            f"[target] MAVLink smoke target listening on {host}:{port} "
            f"sysid={state.sysid}; this is not ArduPilot/DVD",
            flush=True,
        )
        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=client_loop, args=(conn, addr, state), daemon=True)
            thread.start()


if __name__ == "__main__":
    main()