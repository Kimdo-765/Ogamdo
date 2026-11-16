"""Portable readers and Markdown segmentation for security case material.

The Ogamdo adapter reads only the exported exploit-library shape.  Neither
this module nor the index imports Ogamdo's API, worker, or model providers.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .sanitize import redact_text
from .vocab import OUTCOMES, PRIMITIVES, canonical, technique_nodes


_SAFE_ID = re.compile(r"^[A-Za-z0-9_-]+$")
_HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*$")
_FENCE = re.compile(r"^\s{0,3}(?:```|~~~)")
_UUIDISH = re.compile(r"^[0-9a-f]{8,}(?:-[0-9a-f]{4,})*(?:\.[^.]+)?$", re.I)
_MAX_META_BYTES = 256_000
# Cases built from an Exploit Library entry. A library sync owns only these, so
# other sources (e.g. writeup digests ingested as JSONL) can share a collection.
EXPLOIT_SOURCE_TYPE = "ctf"
_MAX_REPORT_BYTES = 2_000_000

_META_FIELDS = (
    "module", "chal_name", "chal_filename", "technique_name", "bug_classes",
    "arch", "glibc_version", "mitigations", "tags", "notes", "saved_at",
    "binary_sha256", "source_job_id", "source_child_job_id", "script_filename",
    # Optional richer keys in future libraries; current Ogamdo entries do
    # not generally contain them, but the adapter can use them immediately.
    "primitives", "conditions", "blockers", "outcomes",
)


def chunk_markdown(text: str, max_chars: int = 1800) -> list[dict[str, Any]]:
    """Split Markdown by real headings and then by size, retaining line spans.

    Heading-looking text inside fenced code is treated as code.  Chunks are
    deliberately small enough for models with modest context windows, while
    the original line range remains available for a citation.
    """
    if max_chars < 128:
        raise ValueError("max_chars must be at least 128")
    lines = str(text or "").splitlines(keepends=True)
    groups: list[tuple[str, str, int, list[str]]] = []
    section = "Document"
    path = ""
    stack: list[tuple[int, str]] = []
    first_line = 1
    current: list[str] = []
    fenced = False
    for number, line in enumerate(lines, 1):
        heading = _HEADING.match(line) if not fenced else None
        if heading:
            if current:
                groups.append((section, path, first_line, current))
            section = heading.group(2).strip().rstrip("# ").strip() or "Document"
            level = len(heading.group(1))
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, section))
            path = " > ".join(title for _, title in stack)
            first_line = number
            current = [line]
        else:
            current.append(line)
        if _FENCE.match(line):
            fenced = not fenced
    if current:
        groups.append((section, path, first_line, current))

    chunks: list[dict[str, Any]] = []
    for title, heading_path, start, group_lines in groups:
        pending: list[str] = []
        pending_start = start
        size = 0

        def flush(end_line: int) -> None:
            nonlocal pending, size
            value = "".join(pending).strip()
            if value:
                chunks.append({
                    "section": title,
                    "heading_path": heading_path,
                    "line_start": pending_start,
                    "line_end": end_line,
                    "text": value,
                })
            pending = []
            size = 0

        for offset, line in enumerate(group_lines):
            number = start + offset
            if pending and size + len(line) > max_chars:
                flush(number - 1)
                pending_start = number
            # A single huge line is split, with each part citing that line.
            if len(line) > max_chars:
                for pos in range(0, len(line), max_chars):
                    part = line[pos:pos + max_chars]
                    if pending:
                        flush(number - 1)
                    pending_start = number
                    pending = [part]
                    size = len(part)
                    flush(number)
                pending_start = number + 1
                continue
            if not pending:
                pending_start = number
            pending.append(line)
            size += len(line)
        if pending:
            flush(start + len(group_lines) - 1)
    return chunks


def _read_json(path: Path, max_bytes: int = _MAX_META_BYTES) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
            return {}
        value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _safe_value(value: Any, *, flags: list[str], targets: list[str]) -> Any:
    if isinstance(value, str):
        return redact_text(value, flags=flags, target_urls=targets)
    if isinstance(value, list):
        return [_safe_value(v, flags=flags, targets=targets) for v in value]
    if isinstance(value, dict):
        return {
            str(k): _safe_value(v, flags=flags, targets=targets)
            for k, v in value.items()
        }
    return value if value is None or isinstance(value, (int, float, bool)) else str(value)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if isinstance(v, str) and v.strip()]
    return []


def _title(meta: dict[str, Any], entry_id: str) -> str:
    for key in ("chal_name", "technique_name", "chal_filename"):
        raw = str(meta.get(key) or "").strip()
        if raw and raw not in {"?", "unknown", "none"} and not _UUIDISH.fullmatch(raw):
            return raw[:180]
    return entry_id


def _heading_kind(section: str) -> str | None:
    name = re.sub(r"[_-]+", " ", section.casefold()).strip()
    if re.search(r"\b(root cause|bug class|vulnerability|weakness)\b|취약 원인|취약점|근본 원인", name):
        return "root_cause"
    if re.search(r"\b(primitive|capability)\b|확보한 능력|프리미티브", name):
        return "primitive"
    if re.search(
        r"\b(technique|exploit method|exploit chain|exploit strategy|"
        r"exploitation strategy|solver strategy|solve strategy|solver)\b|"
        r"적용 기법|공격 기법|풀이 기법|공격 전략|공격 절차|솔버",
        name,
    ):
        return "technique"
    if re.search(r"\b(outcome|impact|result)\b|최종 결과|공격 결과", name):
        return "outcome"
    if re.search(r"\b(preconditions?|prerequisites?|requirements?)\b|전제 조건|필요 조건", name):
        return "condition"
    if re.search(r"\b(blocked by|mitigation|constraint|limitation)\b|차단|방어|제약", name):
        return "blocker"
    return None


def _heading_label(chunk: dict[str, Any]) -> str | None:
    title = str(chunk.get("section") or "")
    if ":" in title:
        value = title.split(":", 1)[1].strip()
    elif " — " in title:
        value = title.split(" — ", 1)[1].strip()
    else:
        lines = str(chunk.get("text") or "").splitlines()[1:]
        value = ""
        fenced = False
        for line in lines:
            if _FENCE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            candidate = re.sub(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)", "", line).strip()
            if candidate:
                value = candidate
                break
    value = value.strip(" *`_")
    value = re.split(r"(?<=[.!?])\s+", value, maxsplit=1)[0]
    value = re.sub(r"\s+", " ", value)[:160].strip(" :;,-")
    if not value or "[REDACTED_" in value:
        return None
    return value


def _concise_technique(label: str) -> bool:
    """Avoid promoting a report's first instruction to a technique node.

    Many historical sections are titled "Exploit chain" and open with a
    sentence or numbered step.  That prose is searchable as a chunk; it is
    not a stable technique identity for graph traversal.
    """
    value = label.strip().rstrip(".")
    words = value.split()
    if not value or len(value) > 90 or len(words) > 8:
        return False
    if re.match(r"^(?:the|this|that|we|first|then|next|step|use|run|leak|read|write|call|"
                r"execute|send|derive|recover|build|set|create|check)\b", value, re.I):
        return False
    if re.search(r"[;=]|(?:\s->\s)|(?:\s→\s)", value):
        return False
    if value.endswith((":", ",", "!", "?")):
        return False
    return True


def _short(label: str) -> bool:
    """A name, not a sentence: short enough that another case could share it."""
    value = label.strip()
    return bool(value) and len(value) <= 60 and len(value.split()) <= 6


def _vocabulary_label(kind: str, label: str) -> str | None:
    """The node label for a primitive or outcome, or ``None`` to keep it text-only."""
    vocabulary = PRIMITIVES if kind == "primitive" else OUTCOMES
    return canonical(label, vocabulary) or (label.strip() if _short(label) else None)


def report_digest(raw_report: str) -> str:
    return hashlib.sha256(raw_report.encode("utf-8")).hexdigest()


def _section_at(sections: list[dict[str, Any]], line: int) -> str:
    for chunk in sections:
        if int(chunk["line_start"]) <= line <= int(chunk["line_end"]):
            return str(chunk["section"])
    return "report"


def extracted_dir(library_root: Path) -> Path:
    """Where ``backfill`` keeps its results: a sibling of the library.

    Not inside each entry. Ogamdo writes the library from a container, so on
    a host install its entry directories belong to another user.
    """
    return Path(library_root).resolve().parent / "security-rag-extracted"


def _evidence(section: str, start: int = 0, end: int = 0) -> dict[str, Any]:
    return {"section": section, "line_start": start, "line_end": end}


def _node(kind: str, label: str) -> dict[str, str]:
    return {"kind": kind, "label": label}


def _relations_for_case(
    entry_id: str, metadata: dict[str, Any], sections: list[dict[str, Any]],
    extracted: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Record observed labels and *candidate* transitions between them.

    Merely co-occurring in a report does not establish an exploit chain.
    Causal edges come from two places, both marked ``candidate``: headings
    that explicitly name successive roles, and model extractions (``backfill``) whose
    quoted evidence was located in the report. Consumers must preserve status.
    """
    case_node = _node("case", entry_id)
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    headed: dict[str, tuple[str, dict[str, Any]]] = {}

    def add(source: dict[str, str], kind: str, target: dict[str, str],
            status: str, evidence: dict[str, Any], conditions: list[str] | None = None) -> None:
        key = (source["kind"], source["label"].casefold(), kind,
               target["kind"], target["label"].casefold())
        if key in seen:
            return
        seen.add(key)
        edges.append({"from": source, "type": kind, "to": target,
                      "status": status, "evidence": evidence,
                      "conditions": conditions or []})

    def usable(label: Any) -> str | None:
        return label.strip() if isinstance(label, str) and label.strip() and "[REDACTED_" not in label else None

    bugs = [b for b in (usable(v) for v in _strings(metadata.get("bug_classes"))) if b]
    for bug in bugs:
        add(_node("root_cause", bug), "observed_in_case", case_node, "observed", _evidence("meta.json"))
    # One report names one technique, often as a composite. Its parts and the
    # families inside it are the identities other cases can share.
    techniques = technique_nodes(usable(metadata.get("technique_name")) or "")
    for label in techniques:
        add(_node("technique", label), "observed_in_case", case_node, "observed", _evidence("meta.json"))
    for field, kind in (("primitives", "primitive"), ("outcomes", "outcome")):
        for raw in _strings(metadata.get(field)):
            label = _vocabulary_label(kind, raw) if usable(raw) else None
            if label:
                add(_node(kind, label), "observed_in_case", case_node, "observed", _evidence("meta.json"))
    for field, kind in (("conditions", "condition"), ("blockers", "blocker")):
        for raw in _strings(metadata.get(field)):
            if usable(raw) and _short(raw):
                add(_node(kind, raw.strip()), "observed_in_case", case_node, "observed", _evidence("meta.json"))

    for chunk in sections:
        kind = _heading_kind(str(chunk.get("section") or ""))
        if not kind:
            continue
        # The structured REPORT field is a more stable technique identity
        # than the first sentence under an "Exploit chain" heading.
        if kind == "technique" and techniques:
            label = techniques[0]
        else:
            label = _heading_label(chunk)
        if not label:
            continue
        if kind == "technique" and not techniques and not _concise_technique(label):
            continue
        if kind in {"primitive", "outcome"}:
            label = _vocabulary_label(kind, label)
        elif kind != "technique" and not _short(label):
            # A sentence under "Root cause" is evidence to read, not a node.
            label = None
        if not label:
            continue
        ev = _evidence(str(chunk["section"]), int(chunk["line_start"]),
                       int(chunk["line_end"]))
        headed.setdefault(kind, (label, ev))
        add(_node(kind, label), "observed_in_case", case_node, "observed", ev)

    for source_kind, target_kind, relation_type in (
        ("root_cause", "primitive", "produces"),
        ("primitive", "technique", "enables"),
        ("technique", "outcome", "leads_to"),
    ):
        if source_kind in headed and target_kind in headed:
            source_label, _ = headed[source_kind]
            target_label, target_ev = headed[target_kind]
            add(_node(source_kind, source_label), relation_type,
                _node(target_kind, target_label), "candidate", target_ev)
    if "technique" in headed:
        technique_label, _ = headed["technique"]
        for kind, relation_type in (("condition", "requires"),
                                    ("blocker", "blocked_by")):
            if kind in headed:
                label, ev = headed[kind]
                add(_node("technique", technique_label), relation_type,
                    _node(kind, label), "candidate", ev)

    # Model-extracted links. Each carries the line span where its quote was
    # found in this report; a quote that could not be located was never saved.
    for item in (extracted or {}).get("primitives") or []:
        if not isinstance(item, dict) or item.get("label") not in PRIMITIVES:
            continue
        start, end = int(item.get("line_start") or 0), int(item.get("line_end") or 0)
        ev = _evidence(_section_at(sections, start), start, end)
        primitive = _node("primitive", item["label"])
        add(primitive, "observed_in_case", case_node, "observed", ev)
        if item.get("from_bug") in bugs:
            add(_node("root_cause", item["from_bug"]), "produces", primitive, "candidate", ev)
        for label in techniques:
            add(primitive, "enables", _node("technique", label), "candidate", ev)
    for item in (extracted or {}).get("outcomes") or []:
        if not isinstance(item, dict) or item.get("label") not in OUTCOMES:
            continue
        start, end = int(item.get("line_start") or 0), int(item.get("line_end") or 0)
        ev = _evidence(_section_at(sections, start), start, end)
        outcome = _node("outcome", item["label"])
        add(outcome, "observed_in_case", case_node, "observed", ev)
        for label in techniques:
            add(_node("technique", label), "leads_to", outcome, "candidate", ev)
    return edges


def load_exploit_case(
    entry_dir: Path, *, source_job_root: Path | None = None,
    extracted_root: Path | None = None,
) -> dict[str, Any] | None:
    """Load one ``data/exploits/<id>`` entry into the portable case format.

    An incomplete entry is skipped.  The optional ``source_job_root`` can
    supply structured facts while historical job directories still exist;
    it is never needed to consume an exported exploit library.
    """
    entry_dir = Path(entry_dir)
    if entry_dir.is_symlink() or not entry_dir.is_dir() or not _SAFE_ID.fullmatch(entry_dir.name):
        return None
    report_path = entry_dir / "report.md"
    if report_path.is_symlink() or not report_path.is_file():
        return None
    try:
        if report_path.stat().st_size > _MAX_REPORT_BYTES:
            return None
        raw_report = report_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    raw_meta = _read_json(entry_dir / "meta.json")
    if not raw_meta:
        return None

    flags = _strings(raw_meta.get("flags"))
    targets = _strings(raw_meta.get("target_url"))
    metadata = {
        key: _safe_value(raw_meta[key], flags=flags, targets=targets)
        for key in _META_FIELDS if key in raw_meta
    }
    if source_job_root and raw_meta.get("source_job_id"):
        job_id = str(raw_meta["source_job_id"])
        if _SAFE_ID.fullmatch(job_id):
            job_dir = Path(source_job_root) / job_id
            findings = _read_json(job_dir / "report_findings.json") or _read_json(job_dir / "findings.json")
            if findings:
                vulns = findings.get("vulns") or []
                extra_bugs = [
                    str(v.get("bug_class") or v.get("attack_class"))
                    for v in vulns if isinstance(v, dict) and (v.get("bug_class") or v.get("attack_class"))
                ]
                extra_primitives = [
                    str(v.get("primitive_class")) for v in vulns
                    if isinstance(v, dict) and v.get("primitive_class")
                ]
                facts = findings.get("key_facts") or []
                extra_bugs += [str(v["fact_class"]) for v in facts
                               if isinstance(v, dict) and v.get("fact_class")]
                old_bugs = metadata.get("bug_classes") or []
                metadata["bug_classes"] = list(dict.fromkeys(
                    [str(v) for v in old_bugs if v] + extra_bugs
                ))
                if extra_primitives:
                    metadata["primitives"] = list(dict.fromkeys(extra_primitives))
                technique = ((findings.get("chain") or {}).get("technique_name")
                             or (findings.get("solver_strategy") or {}).get("technique_name"))
                if technique and not metadata.get("technique_name"):
                    metadata["technique_name"] = str(technique)
    # Written by ``security-rag backfill``. It is bound to the report it was
    # extracted from; after an overwrite the stale file is ignored until the
    # backfill runs again.
    if extracted_root is None:
        extracted_root = extracted_dir(entry_dir.parent)
    extracted = _read_json(Path(extracted_root) / f"{entry_dir.name}.json")
    if extracted.get("report_sha256") != report_digest(raw_report):
        extracted = {}
    for field in ("primitives", "outcomes"):
        labels = [str(i["label"]) for i in extracted.get(field) or []
                  if isinstance(i, dict) and i.get("label")]
        if labels:
            metadata[field] = list(dict.fromkeys(_strings(metadata.get(field)) + labels))
    metadata = _safe_value(metadata, flags=flags, targets=targets)
    body = redact_text(raw_report, flags=flags, target_urls=targets)
    sections = chunk_markdown(body)
    title = redact_text(_title(metadata, entry_dir.name), flags=flags, target_urls=targets)
    case = {
        "id": entry_dir.name,
        "title": title,
        "body": body,
        "source_type": EXPLOIT_SOURCE_TYPE,
        "source_uri": f"exploit://{entry_dir.name}/report.md",
        "module": str(metadata.get("module") or "").strip().lower(),
        "metadata": metadata,
        "sections": sections,
        "relations": _relations_for_case(entry_dir.name, metadata, sections, extracted),
    }
    return case
