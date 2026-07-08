"""Attack-tree structural validation for ordered entry-to-endpoint chains."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Sequence


@dataclass
class ValidationIssue:
    code: str
    message: str
    severity: str = "warn"
    path: str = ""

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


def _label(x: Any) -> str:
    if isinstance(x, dict):
        return str(x.get("label") or x.get("name") or x.get("id") or "")
    return str(x or "")


def _labels(xs: Any) -> List[str]:
    if not xs:
        return []
    if isinstance(xs, (str, bytes)):
        return [_label(xs)]
    return [_label(x) for x in xs]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s or "").strip()).lower()


def _contains_label(text: str, label: str) -> bool:
    n = _norm(label)
    if len(n) < 4:
        return False
    return n in _norm(text)


def _path_context(dfd_path: Any) -> Dict[str, List[str]]:
    if isinstance(dfd_path, dict):
        components = _labels(dfd_path.get("components") or dfd_path.get("nodes"))
        channels = _labels(dfd_path.get("channels") or dfd_path.get("edges"))
        known_components = _labels(dfd_path.get("knownComponents")) or components
        known_channels = _labels(dfd_path.get("knownChannels")) or channels
        relay_components = _labels(dfd_path.get("relayComponents"))
        return {
            "components": components,
            "channels": channels,
            "knownComponents": known_components,
            "knownChannels": known_channels,
            "relayComponents": relay_components,
        }
    return {
        "components": _labels(dfd_path),
        "channels": [],
        "knownComponents": _labels(dfd_path),
        "knownChannels": [],
        "relayComponents": [],
    }


def _walk(node: Any, path: str = "$") -> Iterable[tuple[str, Dict[str, Any]]]:
    if not isinstance(node, dict):
        return
    yield path, node
    for i, child in enumerate(node.get("children") or []):
        yield from _walk(child, f"{path}.children[{i}]")


def _has_concrete_cve(text: str) -> bool:
    return bool(re.search(r"\bCVE-\d{4}-\d{4,}\b", text, flags=re.IGNORECASE))


# A concrete evidence id: CVE, CWE, MITRE ATT&CK technique (T####[.###]), or SPARTA (SV-XX-#).
_EVIDENCE_RE = re.compile(
    r"\b(CVE-\d{4}-\d{4,}|CWE-\d+|T\d{4}(?:\.\d{3})?|SV-[A-Z]{2,}-\d+)\b",
    flags=re.IGNORECASE,
)


def _has_evidence_id(text: str) -> bool:
    return bool(_EVIDENCE_RE.search(text or ""))


def _is_leaf(node: Dict[str, Any]) -> bool:
    return not (node.get("children") or [])


def _node_evidence_ids(node: Dict[str, Any]) -> List[str]:
    """Evidence ids carried in a node's structured ``evidence`` array."""
    out: List[str] = []
    for e in (node.get("evidence") or []):
        if isinstance(e, dict) and e.get("id"):
            out.append(str(e["id"]))
        elif isinstance(e, str):
            out.append(e)
    return out


def _node_is_grounded(node: Dict[str, Any], label: str) -> bool:
    """A method leaf is grounded if it cites a real evidence id in its structured
    ``evidence`` field (preferred) or, as a fallback, in its label."""
    if any(_has_evidence_id(x) for x in _node_evidence_ids(node)):
        return True
    return _has_evidence_id(label)


def _looks_speculative_vuln(text: str) -> bool:
    t = _norm(text)
    terms = [
        "cve-class",
        "rce",
        "remote code execution",
        "buffer overflow",
        "heap overflow",
        "stack overflow",
        "memory corruption",
        "parser overflow",
        "parser vulnerability",
        "firmware vulnerability",
    ]
    return any(term in t for term in terms)


def validate_attack_tree(
    tree: Dict[str, Any],
    dfd_path: Any,
    entry: Any,
    endpoint: Any,
) -> List[ValidationIssue]:
    """Validate that an attack tree is one ordered DFD-path chain.

    ``dfd_path`` may be a plain ordered component list or a richer dict:
    {"components": [...], "channels": [...], "knownComponents": [...],
     "knownChannels": [...], "relayComponents": [...]}.
    """
    issues: List[ValidationIssue] = []
    ctx = _path_context(dfd_path)
    allowed_components = {_norm(x) for x in ctx["components"]}
    allowed_channels = {_norm(x) for x in ctx["channels"]}

    if not isinstance(tree, dict):
        return [ValidationIssue("tree_type", "attack tree must be a JSON object", "err", "$")]

    # The tree is UNIFORM nodes (no 'kind'): the root is the final objective,
    # every node carries summary/attack_context/evidence, and AND/OR describes
    # how a node's children combine. Ordering is expressed by parent/child
    # nesting, so there is no SEQ node and no single-child-root requirement.
    for path, node in _walk(tree):
        # 'summary' is the node's text; fall back to legacy 'label'.
        label = str(node.get("summary") or node.get("label") or "")
        meta_comp = node.get("dfd_component")
        meta_ch = node.get("dfd_channel")
        exempt = bool(node.get("out_of_band") or node.get("precondition"))

        if meta_comp and _norm(meta_comp) not in allowed_components and not exempt:
            issues.append(ValidationIssue(
                "outside_component",
                f"node references component outside DFD path: {meta_comp}",
                "err",
                path,
            ))
        if meta_ch and _norm(meta_ch) not in allowed_channels and not exempt:
            issues.append(ValidationIssue(
                "outside_channel",
                f"node references channel outside DFD path: {meta_ch}",
                "err",
                path,
            ))

        for comp in ctx["knownComponents"]:
            if _norm(comp) not in allowed_components and _contains_label(label, comp) and not exempt:
                issues.append(ValidationIssue(
                    "outside_component_label",
                    f"label appears to reference component outside DFD path: {comp}",
                    "err",
                    path,
                ))
        for ch in ctx["knownChannels"]:
            if _norm(ch) not in allowed_channels and _contains_label(label, ch) and not exempt:
                issues.append(ValidationIssue(
                    "outside_channel_label",
                    f"label appears to reference channel outside DFD path: {ch}",
                    "err",
                    path,
                ))

        for relay in ctx["relayComponents"]:
            if _contains_label(label, relay) and "compromise" in _norm(label):
                issues.append(ValidationIssue(
                    "passive_relay_compromise",
                    f"passive relay is labeled as compromised without explicit justification: {relay}",
                    "warn",
                    path,
                ))

        # Every leaf (a node with no children) is a single actionable attack and
        # must be grounded in a concrete evidence id (CVE / CWE / ATT&CK / SPARTA)
        # plus a reasoned attack_context — not just an id in the summary.
        if _is_leaf(node):
            if not _node_is_grounded(node, label):
                issues.append(ValidationIssue(
                    "leaf_without_evidence",
                    "leaf must cite a concrete evidence id (CVE/CWE/ATT&CK/SPARTA) "
                    "in its 'evidence' field",
                    "warn",
                    path,
                ))
            if not str(node.get("attack_context") or "").strip():
                issues.append(ValidationIssue(
                    "leaf_without_context",
                    "leaf must carry an 'attack_context' explaining the reasoned, "
                    "component-specific mechanism",
                    "warn",
                    path,
                ))
        if _looks_speculative_vuln(label) and not _has_concrete_cve(label):
            issues.append(ValidationIssue(
                "speculative_leaf",
                "speculative vulnerability/RCE leaf must cite a concrete CVE",
                "warn",
                path,
            ))

        logic = str(node.get("logic") or "").upper()
        children: Sequence[Any] = node.get("children") or []
        if logic == "OR" and len(children) < 2:
            issues.append(ValidationIssue(
                "weak_or",
                "OR node should contain two or more real alternatives",
                "warn",
                path,
            ))

    entry_labels = _labels(entry)
    endpoint_labels = _labels(endpoint)
    if entry_labels and ctx["components"]:
        if not any(_norm(e) == _norm(ctx["components"][0]) for e in entry_labels):
            issues.append(ValidationIssue(
                "entry_alignment",
                "DFD path does not start with the scenario entry component",
                "err",
                "$",
            ))
    if endpoint_labels and ctx["components"]:
        if not any(_norm(e) == _norm(ctx["components"][-1]) for e in endpoint_labels):
            issues.append(ValidationIssue(
                "endpoint_alignment",
                "DFD path does not end with the scenario endpoint component",
                "err",
                "$",
            ))

    return issues
