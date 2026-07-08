"""
Function-level configuration schema (OpenXSAM++ §IV-B1).

Every field here is grounded 1:1 in the DefenseWeaver paper's prose
description of the OpenXSAM++ extension (§IV-B1):

  * Software attribute -> operating system, software bill of materials,
    active network services.
  * Hardware attribute -> hardware modules, chips, debugging capabilities.
  * Channel / Interface elements -> technology/protocol, interface,
    transferred data.

The ``src`` tag on each field records that provenance so a UI (or the
OpenXSAM++ exporter) can show where the field comes from and avoid
"rigid hardcoding". Users may also attach free-form custom attributes
(see ``config`` dicts consumed by :mod:`threat_modeler.graph`).

A configuration is a mapping ``{element_guid: {field_key: value, ...}}``
plus an optional ``"__custom"`` list of ``{"k": key, "v": value}`` pairs
per element. Blank values export as ``unspecified`` — never fabricated.
"""

from __future__ import annotations

from typing import Dict, List, TypedDict


class Field(TypedDict):
    key: str
    label: str
    src: str          # provenance tag (which OpenXSAM++ attribute)
    multiline: bool
    hint: str


def _f(key: str, label: str, src: str, multiline: bool = False, hint: str = "") -> Field:
    return {"key": key, "label": label, "src": src, "multiline": multiline, "hint": hint}


# --- Node (component) configuration fields --------------------------------

NODE_FIELDS: List[Dict[str, object]] = [
    {
        "group": "Software  (OpenXSAM++ Software attribute)",
        "fields": [
            _f("sw.os", "Operating system", '"operating system"',
               hint="e.g. NuttX 10.3, Linux 6.1"),
            _f("sw.sbom", "Software bill of materials", '"software bill of materials"',
               multiline=True, hint="one per line, e.g. PX4 1.14 / MAVLink v2"),
            _f("sw.services", "Active network services", '"active network services"',
               multiline=True, hint="one per line, e.g. MAVLink:14550"),
        ],
    },
    {
        "group": "Hardware  (OpenXSAM++ Hardware attribute)",
        "fields": [
            _f("hw.chips", "Chips", '"chips"',
               multiline=True, hint="one per line, e.g. STM32F765 / MPU6000"),
            _f("hw.modules", "Hardware modules", '"hardware modules"',
               multiline=True, hint="one per line, e.g. IMU / GNSS"),
            _f("hw.debug", "Debugging capabilities", '"debugging capabilities"',
               hint="e.g. SWD exposed / none"),
        ],
    },
]

# --- Edge (channel) configuration fields ----------------------------------

EDGE_FIELDS: List[Dict[str, object]] = [
    {
        "group": "Channel  (OpenXSAM++ Channel / Interface)",
        "fields": [
            _f("ch.tech", "Technology / protocol", "Channel",
               hint="e.g. MAVLink, UART, I2C, Wi-Fi"),
            _f("ch.interface", "Interface", "Interface",
               hint="e.g. UART port, RF 2.4GHz"),
            _f("ch.data", "Transferred data", "DataFlow",
               hint="what flows"),
        ],
    },
]
