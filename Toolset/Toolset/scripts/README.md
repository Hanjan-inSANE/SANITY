# Toolset glue scripts

These are the helper programs referenced by registry descriptors whose
`command_template` runs an interpreter over a script (e.g. `python … inject.py`,
`gdb --batch -x default.gdb`). The Tool Executor runs them argv-only and records
evidence; the scripts themselves live here so a descriptor can point at a stable,
bundled path via the auto-injected `{toolset_root}` parameter.

> SAFETY: the MAVLink/network scripts are offensive/defensive research tooling for
> an **authorized testbed you own** (Damn Vulnerable Drone / ArduPilot SITL in a
> sandboxed network). Do not point them at systems you are not authorized to test.

## MAVLink (ArduPilot) — `scripts/mavlink/`
| script | tool_id | key args | purpose |
|---|---|---|---|
| heartbeat.py | mav_heartbeat | --conn --timeout | recon: read system/component id |
| inject.py | pymavlink_inject | --conn --sys --comp --msg --params(JSON) | send any MAVLink msg/command |
| gps_spoof.py | gps_input_spoof | --conn --lat --lon --rate --duration | stream fake GPS_INPUT |
| signing.py | mavlink_signing | --conn --key | DEFENSE: enable MAVLink2 signing |
| param_harden.py | ardupilot_param_harden | --conn --set(JSON) | DEFENSE: safe PARAM_SET |
| failsafe.py | failsafe_trigger | --conn --action rtl|land | DEFENSE: force RTL/LAND |

## Network — `scripts/net/`
| script | tool_id | key args | purpose |
|---|---|---|---|
| scapy_attack.py | scapy | --target --port --count --iface | packet-craft template (edit craft()) |
| boofuzz_session.py | boofuzz | --host --port --runs | protocol fuzz skeleton (edit s_initialize) |

## Debug — `scripts/debug/`
| file | tool_id | purpose |
|---|---|---|
| default.gdb | gdb | batch backtrace/registers/mappings |
| default.lldb | lldb | batch backtrace/registers |
| syscalls.bt | bpftrace | 10s syscall histogram |

## Requirements
`pymavlink` (MAVLink scripts), `scapy`, `boofuzz` — installed by `env/install-ubuntu.sh`.
`scapy_attack.py` and `boofuzz_session.py` are **templates**: customize the payload /
protocol block for your specific target before relying on results.
