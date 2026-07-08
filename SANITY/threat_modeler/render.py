"""
Attack-tree layout and SVG rendering.

The tree is the STRICT-JSON shape produced by the Assembler — UNIFORM nodes
(no ``kind``); the root is the final objective and AND/OR describes how a node's
children combine:

    {"summary": str,
     "attack_context"?: str,
     "evidence"?: [ {"id": str, "note": str} ],
     "logic"?: "AND" | "OR",
     "children"?: [ ...nodes ]}

Node styling is derived structurally at render time: the root is drawn as the
objective; every other node shares one style, with an AND/OR gate label on any
node that has children.

IMPORTANT (learned from a prior bug): the layout constants NW/NH/VG that
:func:`render_tree_svg` needs are RETURNED by :func:`layout` and passed
back in, so the two functions share one source of truth. A previous
implementation let ``VG`` fall out of scope during rendering and crashed;
keeping the constants in the returned :class:`Layout` prevents that.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List
from xml.sax.saxutils import escape


@dataclass
class Layout:
    NW: int
    NH: int
    HG: int
    VG: int


def _esc(s) -> str:
    return escape("" if s is None else str(s), {'"': "&quot;"})


def layout(root: Dict[str, Any], NW: int = 170, NH: int = 38, HG: int = 18, VG: int = 76) -> Layout:
    """Assign ``_x``/``_y``/``_d`` to every node in place; return the constants."""
    cursor = [0]

    def place(node: Dict[str, Any], depth: int) -> None:
        node["_d"] = depth
        node["_y"] = depth * VG
        children = node.get("children") or []
        if not children:
            node["_x"] = cursor[0]
            cursor[0] += NW + HG
        else:
            for c in children:
                place(c, depth + 1)
            node["_x"] = (children[0]["_x"] + children[-1]["_x"]) / 2

    place(root, 0)
    return Layout(NW=NW, NH=NH, HG=HG, VG=VG)


def _twrap(label: str, cx: float, cy: float, w: int, max_lines: int = 3) -> str:
    words = str(label or "").split()
    lines: List[str] = []
    max_chars = max(14, w // 6)
    cur = ""
    for wd in words:
        if len((cur + " " + wd).strip()) > max_chars:
            lines.append(cur)
            cur = wd
        else:
            cur = (cur + " " + wd).strip()
    if cur:
        lines.append(cur)
    shown = lines[:max_lines]
    if len(lines) > max_lines and shown:
        shown[-1] = shown[-1][: max_chars - 1] + "…"
    start = cy - (len(shown) - 1) * 6
    return "".join(
        f'<text x="{cx}" y="{start + i * 12}" text-anchor="middle" '
        f'dominant-baseline="middle">{_esc(ln)}</text>'
        for i, ln in enumerate(shown)
    )


_STYLE = """
  .tnode rect{stroke-width:1.5}
  .tnode.k-root rect{fill:#1c1608;stroke:#f0a72a}
  .tnode.k-node rect{fill:#15101f;stroke:#9a7bd6}
  .tnode text{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:10.5px;fill:#c9d4e3}
  .tnode .lg{fill:#33b3c7;font-weight:700}
  .tedge{stroke:#4a5768;stroke-width:1.3;fill:none}
"""


def render_tree_svg(tree: Dict[str, Any]) -> str:
    """Render an attack tree to a standalone SVG string."""
    lay = layout(tree)
    NW, NH, VG = lay.NW, lay.NH, lay.VG

    nodes: List[Dict[str, Any]] = []

    def collect(n: Dict[str, Any]) -> None:
        nodes.append(n)
        for c in n.get("children") or []:
            collect(c)

    collect(tree)

    min_x = min(n["_x"] for n in nodes)
    max_x = max(n["_x"] + NW for n in nodes)
    max_y = max(n["_y"] + NH for n in nodes)
    vb_w = max_x - min_x + 40
    vb_h = max_y + 40

    parts: List[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="{min_x - 20} -20 {vb_w} {vb_h}" '
        f'width="{vb_w}" height="{vb_h}" style="background:#0a0e14">'
    )
    parts.append(f"<style>{_STYLE}</style>")

    def edges(n: Dict[str, Any]) -> None:
        for c in n.get("children") or []:
            x1, y1 = n["_x"] + NW / 2, n["_y"] + NH
            x2, y2 = c["_x"] + NW / 2, c["_y"]
            parts.append(
                f'<path class="tedge" d="M{x1},{y1} '
                f'C{x1},{y1 + VG / 2} {x2},{y2 - VG / 2} {x2},{y2}"/>'
            )
            edges(c)

    edges(tree)

    def draw(n: Dict[str, Any], is_root: bool) -> None:
        children = n.get("children") or []
        cls = "k-root" if is_root else "k-node"
        lg = ""
        if children:  # a node that combines children shows its AND/OR gate
            lg = (
                f'<text class="lg" x="{n["_x"] + NW / 2}" y="{n["_y"] - 3}" '
                f'text-anchor="middle">{_esc(n.get("logic", "AND"))}</text>'
            )
        label = n.get("summary") or n.get("label", "")
        parts.append(
            f'<g class="tnode {cls}">{lg}'
            f'<rect x="{n["_x"]}" y="{n["_y"]}" width="{NW}" height="{NH}" rx="4"/>'
            f'{_twrap(label, n["_x"] + NW / 2, n["_y"] + NH / 2, NW)}</g>'
        )
        for c in children:
            draw(c, False)

    draw(tree, True)
    parts.append("</svg>")
    return "".join(parts)


def svg_to_png(svg: str, out_path: str) -> bool:
    """Best-effort SVG->PNG using cairosvg if available.

    Returns True on success, False if cairosvg is not installed (in which
    case the caller should just keep the SVG).
    """
    try:
        import cairosvg  # noqa: WPS433
    except ImportError:
        return False
    cairosvg.svg2png(bytestring=svg.encode("utf-8"), write_to=out_path, scale=2.0)
    return True
