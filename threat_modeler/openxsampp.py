"""
Deterministic OpenXSAM++ serialization.

IMPORTANT (see README §"Verified facts, 1-2"): DefenseWeaver's paper
describes OpenXSAM++ only in prose (§IV-B1) and does NOT publish a
complete XSD; the DefenseWeaver repository is closed-source under a
commercial license. This serialization is therefore a *documented
reconstruction*:

    skeleton  = the original ASRG/openXSAM XSD shape
                (SystemChunk > Elements > Component; Channel > Endpoints
                 (ComponentRef) + DataFlows (dataflowSource/dataFlowTarget))
    additions = the §IV-B1 extension
                (Software: OS/SBOM/Services; Hardware: Chips/Modules/Debug;
                 Channel Technologies + Interface)

Blank fields are emitted as the literal ``unspecified`` (or an
``<!--unspecified-->`` marker for empty lists). Nothing is fabricated.
"""

from __future__ import annotations

from typing import List
from xml.sax.saxutils import escape

from .dfd import SystemModel
from .graph import Config, normalize_config, _field, _lines, _custom  # reuse config accessors

_TYPE_NAME = {
    "process": "Process",
    "external": "ExternalInteractor",
    "store": "DataStore",
    "element": "Element",
}

U = "  "  # one indent unit


def _esc(s) -> str:
    return escape("" if s is None else str(s), {'"': "&quot;"})


def generate_openxsampp(model: SystemModel, config: Config | None = None) -> str:
    """Return the deterministic OpenXSAM++ XML for a configured model."""
    config = normalize_config(config)
    o: List[str] = []
    o.append('<?xml version="1.0" encoding="utf-8"?>')
    o.append(
        "<!-- Threat Modeler: skeleton=ASRG/openXSAM XSD; "
        "Software/Hardware/Interface=DefenseWeaver Sec. IV-B1; "
        "blank->unspecified -->"
    )
    o.append('<OpenXSAMpp version="0.2-threat_modeler"><SystemChunk name="Components"><Elements>')

    for n in model.nodes:
        g = n.guid
        o.append(
            f'{U}<Component id="{_esc(g)}" name="{_esc(n.label)}" '
            f'type="{_TYPE_NAME.get(n.type, "Element")}">'
        )
        # --- Diagram layout (extension: lets OpenXSAM++ round-trip the DFD) ---
        o.append(
            f'{U}{U}<Diagram left="{n.x:g}" top="{n.y:g}" '
            f'width="{n.w:g}" height="{n.h:g}"/>'
        )

        # --- Software (§IV-B1) ---
        os_v = _field(config, g, "sw.os")
        sbom = _lines(_field(config, g, "sw.sbom"))
        svcs = _lines(_field(config, g, "sw.services"))
        o.append(f"{U}{U}<Software>")
        o.append(f"{U}{U}{U}<OS>{_esc(os_v) if os_v else 'unspecified'}</OS>")
        o.append(f"{U}{U}{U}<SBOM>" + ("" if sbom else "<!--unspecified-->"))
        for x in sbom:
            o.append(f"{U}{U}{U}{U}<Item>{_esc(x)}</Item>")
        o.append(f"{U}{U}{U}</SBOM>")
        o.append(f"{U}{U}{U}<Services>" + ("" if svcs else "<!--unspecified-->"))
        for x in svcs:
            o.append(f"{U}{U}{U}{U}<Service>{_esc(x)}</Service>")
        o.append(f"{U}{U}{U}</Services></Software>")

        # --- Hardware (§IV-B1) ---
        chips = _lines(_field(config, g, "hw.chips"))
        mods = _lines(_field(config, g, "hw.modules"))
        debug = _field(config, g, "hw.debug")
        o.append(f"{U}{U}<Hardware><Chips>" + ("" if chips else "<!--unspecified-->"))
        for x in chips:
            o.append(f"{U}{U}{U}{U}<Chip>{_esc(x)}</Chip>")
        o.append(f"{U}{U}{U}</Chips>")
        o.append(f"{U}{U}{U}<Modules>" + ("" if mods else "<!--unspecified-->"))
        for x in mods:
            o.append(f"{U}{U}{U}{U}<Module>{_esc(x)}</Module>")
        o.append(f"{U}{U}{U}</Modules>")
        o.append(f"{U}{U}{U}<Debug>{_esc(debug) if debug else 'unspecified'}</Debug></Hardware>")

        # --- custom attributes (avoid rigid hardcoding) ---
        cu = _custom(config, g)
        if cu:
            o.append(f"{U}{U}<CustomAttributes>")
            for c in cu:
                o.append(f'{U}{U}{U}<Attr name="{_esc(c["k"])}">{_esc(c["v"])}</Attr>')
            o.append(f"{U}{U}</CustomAttributes>")

        o.append(f"{U}</Component>")

    o.append("</Elements></SystemChunk><SystemChunk name=\"Channels\"><Elements>")

    for e in model.edges:
        tech = _field(config, e.guid, "ch.tech")
        iface = _field(config, e.guid, "ch.interface")
        data = _field(config, e.guid, "ch.data") or e.label
        o.append(
            f'{U}<Channel id="{_esc(e.guid)}" name="{_esc(e.label)}">'
            f'<Endpoints><ComponentRef target="{_esc(e.source)}"/>'
            f'<ComponentRef target="{_esc(e.target)}"/></Endpoints>'
        )
        o.append(
            f"{U}{U}<Technologies><TechnologyRef>"
            f"{_esc(tech) if tech else 'unspecified'}</TechnologyRef></Technologies>"
            f"<Interface>{_esc(iface) if iface else 'unspecified'}</Interface>"
        )
        o.append(
            f'{U}{U}<DataFlows><DataFlow dataflowSource="{_esc(e.source)}" '
            f'dataFlowTarget="{_esc(e.target)}" name="{_esc(data)}"/></DataFlows></Channel>'
        )

    o.append("</Elements></SystemChunk></OpenXSAMpp>")
    return "\n".join(o)


# --- inverse: parse OpenXSAM++ back into (SystemModel, config) --------------

import xml.etree.ElementTree as _ET  # noqa: E402
from typing import Dict, Tuple  # noqa: E402
from .dfd import Node, Edge  # noqa: E402

_TYPE_REVERSE = {
    "Process": "process",
    "ExternalInteractor": "external",
    "DataStore": "store",
    "Element": "element",
}


def _ln(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in (tag or "") else (tag or "")


def _child(el, name: str):
    for c in list(el):
        if _ln(c.tag) == name:
            return c
    return None


def _children(el, name: str):
    return [c for c in list(el) if _ln(c.tag) == name]


def _child_or(el, name: str):
    """Return the named child element, or ``el`` itself when absent.

    A defensive fallback for flat documents that omit the wrapper element.
    Uses an explicit ``is None`` check rather than element truthiness (which
    is deprecated and evaluates empty elements as false)."""
    c = _child(el, name)
    return el if c is None else c


def _text(el) -> str:
    t = (el.text or "").strip() if el is not None else ""
    return "" if t == "unspecified" else t


def _iter(root, name: str):
    for el in root.iter():
        if _ln(el.tag) == name:
            yield el


def parse_openxsampp(xml_str: str) -> Tuple[SystemModel, Config]:
    """Parse an OpenXSAM++ document back into a :class:`SystemModel` (with DFD
    layout) and the ``{guid: {field: value}}`` config it carried.

    Round-trips :func:`generate_openxsampp`. If a ``<Diagram>`` is absent the
    node is auto-placed on a grid so the DFD still renders.
    """
    try:
        root = _ET.fromstring(xml_str)
    except _ET.ParseError as exc:
        raise ValueError(f"Not well-formed OpenXSAM++ XML: {exc}") from exc

    nodes: list = []
    edges: list = []
    config: Config = {}
    missing_layout: list = []

    for comp in _iter(root, "Component"):
        cid = comp.get("id") or ""
        if not cid:
            continue
        label = comp.get("name") or "(unnamed)"
        ntype = _TYPE_REVERSE.get(comp.get("type") or "", "element")

        diag = _child(comp, "Diagram")
        if diag is not None:
            x = float(diag.get("left") or 0)
            y = float(diag.get("top") or 0)
            w = float(diag.get("width") or 150)
            h = float(diag.get("height") or 60)
            has_layout = diag.get("left") is not None
        else:
            x = y = 0.0
            w, h = 150.0, 60.0
            has_layout = False
        node = Node(guid=cid, type=ntype, label=label, x=x, y=y, w=w, h=h)
        nodes.append(node)
        if not has_layout:
            missing_layout.append(node)

        cfg: Dict[str, object] = {}
        sw = _child(comp, "Software")
        if sw is not None:
            os_v = _text(_child(sw, "OS"))
            if os_v:
                cfg["sw.os"] = os_v
            sbom = [_text(x) for x in _children(_child_or(sw, "SBOM"), "Item") if _text(x)]
            if sbom:
                cfg["sw.sbom"] = "\n".join(sbom)
            svcs = [_text(x) for x in _children(_child_or(sw, "Services"), "Service") if _text(x)]
            if svcs:
                cfg["sw.services"] = "\n".join(svcs)
        hw = _child(comp, "Hardware")
        if hw is not None:
            chips = [_text(x) for x in _children(_child_or(hw, "Chips"), "Chip") if _text(x)]
            if chips:
                cfg["hw.chips"] = "\n".join(chips)
            mods = [_text(x) for x in _children(_child_or(hw, "Modules"), "Module") if _text(x)]
            if mods:
                cfg["hw.modules"] = "\n".join(mods)
            debug = _text(_child(hw, "Debug"))
            if debug:
                cfg["hw.debug"] = debug
        ca = _child(comp, "CustomAttributes")
        if ca is not None:
            custom = [
                {"k": a.get("name") or "", "v": _text(a)}
                for a in _children(ca, "Attr") if (a.get("name") and _text(a))
            ]
            if custom:
                cfg["__custom"] = custom
        if cfg:
            config[cid] = cfg

    node_ids = {n.guid for n in nodes}
    for ch in _iter(root, "Channel"):
        chid = ch.get("id") or ""
        if not chid:
            continue
        refs = _children(_child_or(ch, "Endpoints"), "ComponentRef")
        if len(refs) < 2:
            continue
        src = refs[0].get("target") or ""
        tgt = refs[1].get("target") or ""
        if src not in node_ids or tgt not in node_ids:
            continue
        label = ch.get("name") or "(unnamed)"
        edges.append(Edge(guid=chid, label=label, source=src, target=tgt))

        cfg = {}
        techs = _child(ch, "Technologies")
        tech = _text(_child(techs, "TechnologyRef")) if techs is not None else ""
        if tech:
            cfg["ch.tech"] = tech
        iface = _text(_child(ch, "Interface"))
        if iface:
            cfg["ch.interface"] = iface
        df = _child(_child_or(ch, "DataFlows"), "DataFlow")
        data = (df.get("name") if df is not None else "") or ""
        if data and data != label:
            cfg["ch.data"] = data
        if cfg:
            config[chid] = cfg

    if not nodes:
        raise ValueError("No <Component> elements found — is this OpenXSAM++?")

    # auto-layout any node that lacked a <Diagram> (grid, 3 per row)
    for i, node in enumerate(missing_layout):
        node.x = 40 + (i % 3) * 220
        node.y = 40 + (i // 3) * 120

    return SystemModel(nodes=nodes, edges=edges), config

