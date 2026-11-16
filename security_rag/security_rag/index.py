"""SQLite-backed, provider-neutral retrieval and evidence graph.

The database is derived state. Source cases remain authoritative; callers may
rebuild this file at any time. The same API can index Ogamdo's Exploit Library
or cases supplied by another platform such as Strata.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import unicodedata
from contextlib import contextmanager
from functools import lru_cache
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit

from .ingest import EXPLOIT_SOURCE_TYPE, _heading_kind, chunk_markdown, load_exploit_case
from .query import (
    PROTECTION_HEADS, analyze_query, expand_labels, hangul_index_text, is_capability, is_protection,
    required_units, tokens,
)
from .sanitize import redact_text
from .vocab import OUTCOMES, PRIMITIVES, canonical, technique_nodes

SCHEMA_VERSION = 1
INDEXER_VERSION = 3
# Tokenizer and column layout of the derived FTS table. A change drops and
# refills that table only; cases, chunks and edges are untouched.
FTS_LAYOUT = "2:porter-unicode61:title,section,body,labels,ko"
_SENSITIVE_KEYS = {"flag", "flags", "target_url", "password", "secret", "secrets", "token", "api_key", "authorization"}
_KINDS = {"case", "root_cause", "primitive", "technique", "outcome", "condition", "blocker", "artifact", "component"}
_STATUSES = {"verified", "observed", "candidate", "taxonomy"}

# Which section of a matched case to show. Case-level labels sit on every
# chunk and bm25 normalizes by row length, so the case's ranking row is
# usually its shortest one: a Source line, an Outcome or the title. The shown
# passage is chosen again, from the concepts its own text contains and from
# how directly its kind of section answers "how".
_PASSAGE_SKIP = re.compile(
    r"^(?:source|keywords|run|running it|how to run|usage|results?|artifacts?|files"
    r"|verification|validation(?: performed)?|status|실행|검증.*|재현)$"
    # A heading that is only the flag or its capture; a flag checker or a
    # section on decoding the flag describes a method and stays.
    r"|^(?:results?\s*[—–-]\s*)?(?:✅\s*)?(?:the\s+)?flags?"
    r"(?:\s+(?:captured\b.*|content|candidate)|\s*[:=].*)?$"
    r"|redacted_flag|\bcross.references?\b"
    # Notes on why a helper template was not used, not the exploit.
    r"|\bwhy\b.*\bscaffold|scaffold\s+applicability"
    # A heading that states the flag's name or value gives the answer away;
    # one about how a checker compares it describes a method and stays.
    r"|\bflag\s+name\s+is\b|\bflag\s*(?:is|=)\s*[`'\"\[{(<]|플래그\s*(?:명|이름)\s*(?:은|는|:)",
    re.IGNORECASE,
)
_NUMBERING = re.compile(r"^\s*\d+(?:\.\d+)*(?:[.)]|\s*[—–-])?\s+")
_PASSAGE_PRIORITY: tuple[tuple[re.Pattern[str], float], ...] = (
    # A retrospective of a failed attempt mentions the right words but is
    # not the method (checked before "root cause" can claim it).
    (re.compile(r"\b(?:previous|earlier|failed|failure|post.?mortem|retr(?:y|ies)|dead.?ends?|rejected|abandoned"
                r"|what went wrong)\b|실패|이전 시도|기각"), 0.3),
    (re.compile(r"\b(?:pitfalls?|caveats?|gotchas?)\b|주의|함정"), 0.85),
    (re.compile(r"\bvariants?\b|변형"), 0.75),
    (re.compile(r"^(?:summary|tl;dr|overview)$|요약|개요|결론"), 0.5),
    (re.compile(r"^(?:target|target shape|challenge|analysis|background|setup|environment|notes?)\b"), 0.4),
)
_KIND_PRIORITY = {
    "technique": 1.0, "condition": 0.9, "primitive": 0.8, "blocker": 0.7,
    "root_cause": 0.6, "outcome": 0.25,
}
# Free-form library headings that describe a method ("Strategy", "Phase 2 —
# <step>", "<bug> → <primitive>") rank just below Technique.
_METHOD_HEADING = re.compile(
    r"\b(?:strateg(?:y|ies)|approach|attack|exploit(?:ation)?|payload|chain|flow|how it works|solution|solve[rd]?"
    r"|method|bypass|steps?|phase\s*\d+|stage\s*\d+)\b|→|->|공격|풀이|익스플로잇|단계|우회"
)
# A one-unit gain in matched concepts outweighs a small priority gap (Summary
# over Technique) but not a large one (Outcome over Technique).
_PRIORITY_WEIGHT = 1.5
# A digest's method card: the sections that say how, what must hold, what
# blocks it and what goes wrong, in that order.
_CARD_SECTIONS = ("Technique", "Preconditions", "Constraint", "Pitfalls")
_CARD_CHARS = 2800
_CARD_CAPS = {"Preconditions": 450, "Constraint": 450, "Pitfalls": 650}
_LEADING_HEADING = re.compile(r"^#{1,6}[ \t][^\n]*\n?")
_REDACTION_ONLY = re.compile(r"(?:#{1,6}[^\n]*\n)?\W*\[REDACTED_FLAG\]\W*", re.IGNORECASE)


# Negated query concepts. A case that relies on what the asker lacks drops;
# one that worked under the same lack rises. "Relies on" is read from the
# technique a case used and the mitigations it faced, not from its primitives:
# those list what the exploit gained on the way. A lacked capability ("no
# libc leak") never lowers a case, because a case that builds the leak is an
# answer; only a lacked part of the environment (a hook, a mitigation) does.
# Blockers often say "no malloc hooks", which marks the case as an answer.
_CONFLICT_FACTOR = 0.35
_SHARED_LACK_FACTOR = 1.25
_USE_FIELDS = ("technique_name", "tags")
_LACK_FIELDS = ("blockers", "conditions", "mitigations")
_UNKNOWN_STATES = {"", "none", "null", "unknown", "?"}
_OFF_STATES = {"no", "off", "disabled", "false", "0", "absent"}


def _stem(word: str) -> str:
    return word[:-1] if len(word) > 3 and word.endswith("s") and not word.endswith("ss") else word


def _mentions(values: list[str], unit: Any) -> bool:
    """Whether any value names the concept; a plural matches its singular."""
    for value in values:
        raw = unicodedata.normalize("NFKC", value).casefold()
        padded = " " + " ".join(_stem(t) for t in tokens(raw)) + " "
        for alt in unit.alternatives:
            if alt.korean:
                if all(word in raw for word in alt.words):
                    return True
            elif " " + " ".join(_stem(w) for w in alt.words) + " " in padded:
                return True
    return False


def _use_and_lack(meta: dict[str, Any]) -> tuple[list[str], list[tuple[str, ...]]]:
    """What a case says it used, and the lacks it records (as unit-name spans).

    "Used" is the technique and tags, minus what they say the exploit got
    around ("canary-leak", "safe-linking-bypass"). Each blocker, condition or
    mitigation is read with the query parser, so only the words a negation
    covers count as lacked: "PIE on, no leak needed" lacks a leak, not PIE.
    """
    used = [_BYPASSED.sub(" ", v) for key in _USE_FIELDS for v in _strings(meta.get(key))]
    lacked: list[tuple[str, ...]] = []
    for key in _LACK_FIELDS:
        value = meta.get(key)
        if isinstance(value, dict):
            # Library reports: {"canary": false, "pie": true, "relro": null}.
            for name, state in value.items():
                text = str(state).casefold().strip() if state is not None else ""
                if state is None or text in _UNKNOWN_STATES:
                    continue  # not recorded, so neither present nor absent
                if state is False or text in _OFF_STATES:
                    lacked.append((str(name).casefold(),))
            continue
        for item in _strings(value):
            lacked.extend(_read_item(item))
    return used, lacked


_BYPASSED = re.compile(r"[\w.]+[\s_-]+(?:bypass|leak)\b", re.IGNORECASE)


@lru_cache(maxsize=8192)
def _read_item(item: str) -> tuple[tuple[str, ...], ...]:
    """The lacks a metadata phrase states, each as its units' names."""
    return tuple(tuple(u.name for u in span) for span in analyze_query(item).negated)


def _negation_effect(
    meta: dict[str, Any], spans: tuple[tuple[Any, ...], ...], stated: tuple[Any, ...],
) -> tuple[list[str], list[str]]:
    """Negated spans this case relies on, and ones it also went without.

    The effect is kept small on purpose, because reading negation from free
    text is a guess. Only a hook can conflict: "hooks removed" is the one
    case where a technique (hook overwrite) simply stops existing; a lacked
    capability may be built by the case, a lacked protection makes its job
    easier, and other nouns were misread too often. A recorded shared lack
    wins over a conflict, but not for a case that lacks a protection the
    asker says they have ("PIE enabled but no PIE leak").
    """
    used, lacked = _use_and_lack(meta)
    positive = {u.name for u in stated}
    stated_protections = [u for u in stated if is_protection(u)]
    lacks_stated = any(
        any(_mentions([lack[-1]], u) for u in stated_protections) for lack in lacked
    )
    conflicts: list[str] = []
    shared: list[str] = []
    for span in spans:
        head, modifiers = span[-1], span[:-1]
        name = " ".join(u.name for u in span)
        if not lacks_stated and any(_same_lack(lack, span, positive) for lack in lacked):
            shared.append(name)
        elif any(_is_hook(u) and _mentions(used, u) for u in span) and (
            head.name not in positive or any(_mentions(used, m) for m in modifiers)
        ):
            conflicts.append(name)
    return conflicts, shared


def _is_hook(unit: Any) -> bool:
    return any(a.words and a.words[-1] in {"hook", "hooks"} for a in unit.alternatives)


def _is_environment(unit: Any) -> bool:
    """A version number, "glibc" or a protection name: it describes, it does not ask."""
    return unit.name.replace(" ", "").isdigit() or unit.name in {"glibc", "libc6"} or is_protection(unit)


def _same_lack(lack: tuple[str, ...], span: tuple[Any, ...], positive: set[str]) -> bool:
    """Whether a lack a case records is the asker's.

    The heads must agree ("no malloc hooks" and "free hook removed" describe
    the same glibc). A capability or a gadget also needs an agreeing
    modifier when both sides have one: "no heap leak" is shared by a case
    without any leak, not by one that only lacked a libc leak, and "no pop
    rdi gadget" not by one without an argument-setting gadget. So does a head
    the asker also has ("PIE enabled but no PIE leak"). A lack written
    shorter ("no pop" for "no pop rdi gadget") counts when every word of it
    is in the span, unless it is a different protection ("no PIE" is not
    "no PIE leak").
    """
    head, modifiers = span[-1], span[:-1]
    text = " ".join(lack)
    if _mentions([lack[-1]], head):
        strict = is_capability(head) or _is_gadget(head) or head.name in positive
        if strict and modifiers and len(lack) > 1:
            return any(_mentions([text], m) for m in modifiers)
        return True
    words = {_stem(w) for u in span for a in u.alternatives if not a.korean for w in a.words}
    written = [_stem(t) for t in tokens(text)]
    if not written or not all(w in words for w in written):
        return False
    return written[-1] not in {_stem(p) for p in PROTECTION_HEADS}


def _is_gadget(unit: Any) -> bool:
    return any(a.words and a.words[-1] in {"gadget", "gadgets"} for a in unit.alternatives)


def _cut(text: str, size: int) -> str:
    """``text`` within ``size`` chars, ending on a line or sentence when one is near."""
    if len(text) <= size:
        return text
    piece = text[: max(0, size - 1)]
    for mark in ("\n", ". "):
        end = piece.rfind(mark)
        if end > 0.6 * len(piece):
            piece = piece[: end + (1 if mark == ". " else 0)]
            break
    return piece.rstrip() + "…"


def _passage_priority(section: str, title: str) -> float | None:
    """How directly a section answers "how"; None for one never shown by choice.

    Lists of names (Keywords, cross-references, a digest's title chunk with
    its Korean title line) match many query words without saying how; their
    matches still count for the case, but they are not shown by choice.
    """
    name = _NUMBERING.sub("", str(section or "")).strip()
    if str(section or "").strip() == str(title or "").strip():
        return None
    low = name.casefold()
    if _PASSAGE_SKIP.search(low):
        return None
    for pattern, value in _PASSAGE_PRIORITY:
        if pattern.search(low):
            return value
    kind = _heading_kind(name)
    if kind:
        return _KIND_PRIORITY.get(kind, 0.5)
    return 0.95 if _METHOD_HEADING.search(low) else 0.5


def _method_card(title: str, rows: list[sqlite3.Row], budget: int = _CARD_CHARS) -> dict[str, Any] | None:
    """The digest's method sections, each with its text and line span.

    A section split across chunks is joined back together. When the whole
    card is over budget, short sections stay whole and long ones share the rest.
    """
    merged: dict[str, list[Any]] = {}
    for row in rows:
        name = row["section"]
        if name not in _CARD_SECTIONS:
            continue
        text = _LEADING_HEADING.sub("", row["text"], count=1).strip()
        if name in merged:
            merged[name][1] = max(merged[name][1], row["line_end"])
            merged[name][2].append(text)
        else:
            merged[name] = [row["line_start"], row["line_end"], [text]]
    if not merged:
        return None
    parts = [(name, *merged[name]) for name in _CARD_SECTIONS if name in merged]
    bodies = {name: "\n".join(t for t in texts if t) for name, _start, _end, texts in parts}
    room = budget
    # The steps matter most: the other sections get a modest cap first, the
    # Technique gets the rest, and whatever it leaves goes back to them.
    take = {name: min(len(bodies[name]), _CARD_CAPS.get(name, 0)) for name in bodies if name != "Technique"}
    if "Technique" in bodies:
        take["Technique"] = min(len(bodies["Technique"]), max(room - sum(take.values()), room // 3))
    spare = room - sum(take.values())
    for name in ("Pitfalls", "Constraint", "Preconditions"):
        if spare > 0 and name in bodies:
            extra = min(len(bodies[name]) - take[name], spare)
            take[name] += extra
            spare -= extra
    texts = {name: _cut(bodies[name], take[name]) for name in bodies}
    # Characters a cut gave up by ending on a line go back, Technique first.
    for name in ("Technique", "Pitfalls", "Constraint", "Preconditions"):
        spare = room - sum(len(t) for t in texts.values())
        if spare > 0 and name in bodies and len(texts[name]) < len(bodies[name]):
            texts[name] = _cut(bodies[name], len(texts[name]) + spare)
    sections = []
    for name, start, end, _texts in parts:
        body = texts[name]
        sections.append({"section": name, "line_start": start, "line_end": end, "text": body,
                         "truncated": body != bodies[name]})
    return {
        "sections": sections,
        "chars": sum(len(s["text"]) for s in sections),
        "truncated": any(s["truncated"] for s in sections),
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _norm_label(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value)).casefold().strip()
    text = re.sub(r"[_\s]+", "-", text)
    text = re.sub(r"[^\w가-힣+.-]+", "-", text, flags=re.UNICODE)
    text = re.sub(r"-+", "-", text).strip("-.")
    text = {
        "use-after-free": "uaf", "use-after-free-vulnerability": "uaf",
        "arbitrary-read": "aar", "arbitrary-memory-read": "aar",
        "arbitrary-write": "aaw", "arbitrary-memory-write": "aaw",
        "sql-injection": "sqli", "out-of-bounds-read": "oob-read",
        "out-of-bounds-write": "oob-write",
    }.get(text, text)
    return text[:160]


def _node_id(kind: str, label: str) -> str:
    return f"{kind}:{_norm_label(label)}"


def _seed_nodes(con: sqlite3.Connection, query: str) -> list[str]:
    """Node IDs a caller's name for a concept refers to.

    An exact ID or label wins. Otherwise the name is read through the shared
    vocabulary, so ``tcache poisoning`` or ``libc leak`` reach the node the
    index stores them under; a substring match is the last resort.
    """
    norm = _norm_label(query)
    exact = "SELECT node_id FROM nodes WHERE node_id=? OR normalized_label=? ORDER BY node_id"
    seeds = [r["node_id"] for r in con.execute(exact, (query, norm))]
    if seeds:
        return seeds
    names = technique_nodes(query) + [
        label for label in (canonical(query, PRIMITIVES), canonical(query, OUTCOMES)) if label
    ]
    for name in dict.fromkeys(names):
        for row in con.execute(exact, (name, _norm_label(name))):
            if row["node_id"] not in seeds:
                seeds.append(row["node_id"])
    if seeds:
        return seeds
    return [r["node_id"] for r in con.execute(
        "SELECT node_id FROM nodes WHERE normalized_label LIKE ? ORDER BY node_id LIMIT 12", (f"%{norm}%",)
    )]


def _metadata_labels(meta: dict[str, Any]) -> str:
    values: list[str] = []
    for key in (
        "technique_name", "bug_classes", "primitives", "outcomes", "root_causes", "conditions",
        "blockers", "arch", "glibc_version", "mitigations", "tags", "product",
        "component", "affected_versions", "fixed_versions", "cve_ids", "cwe_ids",
    ):
        value = meta.get(key)
        if isinstance(value, dict):
            values.extend(f"{k} {v}" for k, v in value.items())
        elif isinstance(value, (list, tuple)):
            values.extend(str(v) for v in value)
        elif value is not None:
            values.append(str(value))
    text = " ".join(values)[:3000]
    return text + " " + expand_labels(text)


def _safe_metadata(value: Any, *, flags: tuple[str, ...], targets: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        return {
            str(k): _safe_metadata(v, flags=flags, targets=targets)
            for k, v in value.items()
            if str(k).casefold() not in _SENSITIVE_KEYS
        }
    if isinstance(value, list):
        return [_safe_metadata(v, flags=flags, targets=targets) for v in value]
    if isinstance(value, str):
        return redact_text(value, flags=flags, target_urls=targets)
    return value


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, (list, tuple, set)):
        return tuple(str(v) for v in value if v)
    return ()


def _safe_source_uri(value: Any, *, flags: tuple[str, ...], targets: tuple[str, ...], case_id: str) -> str:
    raw = redact_text(str(value or f"case://{case_id}"), flags=flags, target_urls=targets).strip()
    parsed = urlsplit(raw)
    if parsed.scheme in {"http", "https"}:
        # URLs identify evidence, but userinfo/query/fragment often carry tokens.
        host = parsed.hostname or ""
        if not host:
            raise ValueError("source_uri has no host")
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host + (f":{parsed.port}" if parsed.port else "")
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    return raw


class RagIndex:
    """Incremental case index with FTS retrieval and supported graph edges."""

    def __init__(self, db_path: str | Path, *, read_only: bool = False):
        self.db_path = Path(db_path)
        self.read_only = read_only
        self.fts_enabled = False
        if read_only:
            # A serving process must not create, migrate or refill anything:
            # the indexer owns the file. It only checks that the layout is
            # the one this code queries, and says how to fix it if not.
            with self._connection() as con:
                settings = {r["key"]: r["value"] for r in con.execute("SELECT key,value FROM settings")}
                if settings.get("schema_version") != str(SCHEMA_VERSION):
                    raise RuntimeError("index schema version changed; rebuild the derived database")
                tables = {r["name"] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if "chunks_fts" in tables:
                    if settings.get("fts_layout") != FTS_LAYOUT:
                        raise RuntimeError(
                            "index was written by another version; run sync-exploits "
                            "(or restart the watch-exploits service) before serving"
                        )
                    self.fts_enabled = True
            return
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as con:
            self._initialize(con)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if self.read_only:
            con = sqlite3.connect(f"{self.db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=30)
        else:
            con = sqlite3.connect(str(self.db_path), timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=30000")
        if not self.read_only:
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA journal_mode=WAL")
        try:
            yield con
            con.commit()
        except BaseException:
            con.rollback()
            raise
        finally:
            con.close()

    def _initialize(self, con: sqlite3.Connection) -> None:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS cases (
              collection TEXT NOT NULL,
              case_id TEXT NOT NULL,
              title TEXT NOT NULL,
              body TEXT NOT NULL,
              source_type TEXT NOT NULL,
              source_uri TEXT NOT NULL,
              module TEXT NOT NULL,
              metadata_json TEXT NOT NULL,
              content_hash TEXT NOT NULL,
              indexed_at TEXT NOT NULL,
              PRIMARY KEY (collection, case_id)
            );
            CREATE TABLE IF NOT EXISTS chunks (
              chunk_id INTEGER PRIMARY KEY,
              collection TEXT NOT NULL,
              case_id TEXT NOT NULL,
              section TEXT NOT NULL,
              line_start INTEGER NOT NULL,
              line_end INTEGER NOT NULL,
              text TEXT NOT NULL,
              labels TEXT NOT NULL,
              FOREIGN KEY (collection, case_id) REFERENCES cases(collection, case_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS chunks_case_idx ON chunks(collection, case_id);
            CREATE TABLE IF NOT EXISTS nodes (
              node_id TEXT PRIMARY KEY,
              kind TEXT NOT NULL,
              label TEXT NOT NULL,
              normalized_label TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS nodes_label_idx ON nodes(normalized_label);
            CREATE TABLE IF NOT EXISTS edges (
              edge_id INTEGER PRIMARY KEY,
              collection TEXT NOT NULL,
              case_id TEXT NOT NULL,
              source_node TEXT NOT NULL,
              relation_type TEXT NOT NULL,
              target_node TEXT NOT NULL,
              status TEXT NOT NULL,
              conditions_json TEXT NOT NULL,
              section TEXT NOT NULL,
              line_start INTEGER NOT NULL,
              line_end INTEGER NOT NULL,
              FOREIGN KEY (collection, case_id) REFERENCES cases(collection, case_id) ON DELETE CASCADE,
              FOREIGN KEY (source_node) REFERENCES nodes(node_id),
              FOREIGN KEY (target_node) REFERENCES nodes(node_id),
              UNIQUE(collection, case_id, source_node, relation_type, target_node, section, line_start, line_end)
            );
            CREATE INDEX IF NOT EXISTS edges_source_idx ON edges(source_node);
            CREATE INDEX IF NOT EXISTS edges_target_idx ON edges(target_node);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        if "heading_path" not in {r["name"] for r in con.execute("PRAGMA table_info(chunks)")}:
            con.execute("ALTER TABLE chunks ADD COLUMN heading_path TEXT NOT NULL DEFAULT ''")
        row = con.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()
        if row and int(row["value"]) != SCHEMA_VERSION:
            raise RuntimeError("index schema version changed; rebuild the derived database")
        con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))
        try:
            layout = con.execute("SELECT value FROM settings WHERE key='fts_layout'").fetchone()
            if not layout or layout["value"] != FTS_LAYOUT:
                con.execute("DROP TABLE IF EXISTS chunks_fts")
            con.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts
                           USING fts5(title, section, body, labels, ko,
                                      tokenize='porter unicode61 remove_diacritics 2')""")
            self.fts_enabled = True
            have = con.execute("SELECT count(*) AS n FROM chunks_fts").fetchone()["n"]
            want = con.execute("SELECT count(*) AS n FROM chunks").fetchone()["n"]
            if have != want:
                con.execute("DELETE FROM chunks_fts")
                rows = con.execute("""SELECT k.chunk_id,c.title,k.section,k.heading_path,k.text,k.labels
                                      FROM chunks k JOIN cases c ON c.collection=k.collection AND c.case_id=k.case_id""").fetchall()
                for r in rows:
                    self._fts_insert(con, r["chunk_id"], r["title"], r["section"], r["heading_path"], r["text"], r["labels"])
            con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('fts_layout',?)", (FTS_LAYOUT,))
        except sqlite3.OperationalError as exc:
            if "fts5" not in str(exc).lower() and "no such module" not in str(exc).lower():
                raise
            self.fts_enabled = False

    @staticmethod
    def _fts_insert(con: sqlite3.Connection, chunk_id: int, title: str, section: str,
                    heading_path: str, text: str, labels: str) -> None:
        # The heading path, not the bare heading, is what gets searched: a
        # chunk titled "Step 2" is found through the "Exploit chain" above it.
        heading = heading_path or section
        con.execute("INSERT INTO chunks_fts(rowid,title,section,body,labels,ko) VALUES(?,?,?,?,?,?)",
                    (chunk_id, title, heading, text, labels,
                     hangul_index_text(" ".join((title, heading, text)))))

    def _prepare_case(self, case: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(case, dict):
            raise TypeError("case must be a JSON object")
        case_id = str(case.get("id") or "").strip()
        if not case_id or len(case_id) > 200:
            raise ValueError("case.id must be 1-200 characters")
        flags = _strings(case.get("redact_flags"))
        targets = _strings(case.get("redact_target_urls"))
        def clean(value: Any) -> str:
            return redact_text(str(value or ""), flags=flags, target_urls=targets)
        title = clean(case.get("title") or case_id).strip()[:500]
        body = clean(case.get("body") or "")
        source_type = clean(case.get("source_type") or "research").strip()[:80]
        source_uri = _safe_source_uri(case.get("source_uri"), flags=flags, targets=targets, case_id=case_id)
        module = clean(case.get("module") or "").strip().casefold()[:80]
        metadata = _safe_metadata(case.get("metadata") or {}, flags=flags, targets=targets)
        if not isinstance(metadata, dict):
            raise ValueError("case.metadata must be an object")
        raw_sections = case.get("sections") or chunk_markdown(body)
        sections: list[dict[str, Any]] = []
        for raw in raw_sections:
            if not isinstance(raw, dict):
                continue
            text = clean(raw.get("text") or "").strip()
            if not text:
                continue
            sections.append({
                "section": clean(raw.get("section") or "report").strip()[:160],
                "heading_path": clean(raw.get("heading_path") or "").strip()[:400],
                "line_start": max(1, int(raw.get("line_start") or 1)),
                "line_end": max(1, int(raw.get("line_end") or raw.get("line_start") or 1)),
                "text": text,
            })
        if not sections and body.strip():
            sections = [{"section": "report", "heading_path": "", "line_start": 1, "line_end": len(body.splitlines()), "text": body}]
        relations: list[dict[str, Any]] = []
        for raw in case.get("relations") or []:
            if not isinstance(raw, dict):
                continue
            source = raw.get("from") or {}
            target = raw.get("to") or {}
            if not isinstance(source, dict) or not isinstance(target, dict):
                continue
            source_kind = clean(source.get("kind") or "").strip().casefold()
            target_kind = clean(target.get("kind") or "").strip().casefold()
            source_label = clean(source.get("label") or "").strip()[:160]
            target_label = clean(target.get("label") or "").strip()[:160]
            relation_type = clean(raw.get("type") or "").strip().casefold()[:80]
            status = clean(raw.get("status") or "candidate").strip().casefold()
            if not source_kind or not target_kind or not source_label or not target_label or not relation_type:
                continue
            if status not in _STATUSES:
                status = "candidate"
            evidence = raw.get("evidence") or {}
            if not isinstance(evidence, dict):
                evidence = {}
            conditions = [clean(x).strip() for x in _strings(raw.get("conditions")) if clean(x).strip()]
            relations.append({
                "from": {"kind": source_kind, "label": source_label},
                "type": relation_type,
                "to": {"kind": target_kind, "label": target_label},
                "status": status,
                "evidence": {
                    "section": clean(evidence.get("section") or "report").strip()[:160],
                    "line_start": max(0, int(evidence.get("line_start") or 0)),
                    "line_end": max(0, int(evidence.get("line_end") or 0)),
                },
                "conditions": conditions,
            })
        return {
            "id": case_id, "title": title, "body": body, "source_type": source_type,
            "source_uri": source_uri, "module": module, "metadata": metadata,
            "sections": sections, "relations": relations,
        }

    def has_case(self, case_id: str, *, collection: str = "default") -> bool:
        with self._connection() as con:
            return con.execute("SELECT 1 FROM cases WHERE collection=? AND case_id=?", (collection, case_id)).fetchone() is not None

    def upsert_case(self, case: dict[str, Any], *, collection: str = "default") -> bool:
        """Insert or replace one case atomically; return False when unchanged."""
        collection = str(collection).strip()
        if not collection or len(collection) > 100:
            raise ValueError("collection must be 1-100 characters")
        prepared = self._prepare_case(case)
        case_id = prepared["id"]
        digest = hashlib.sha256(f"{INDEXER_VERSION}\n{_json(prepared)}".encode("utf-8")).hexdigest()
        meta = prepared["metadata"]
        labels = _metadata_labels(meta)
        with self._connection() as con:
            old = con.execute("SELECT content_hash FROM cases WHERE collection=? AND case_id=?", (collection, case_id)).fetchone()
            if old and old["content_hash"] == digest:
                return False
            old_chunk_ids = [r["chunk_id"] for r in con.execute(
                "SELECT chunk_id FROM chunks WHERE collection=? AND case_id=?", (collection, case_id)
            )]
            if self.fts_enabled:
                con.executemany("DELETE FROM chunks_fts WHERE rowid=?", [(i,) for i in old_chunk_ids])
            con.execute("DELETE FROM edges WHERE collection=? AND case_id=?", (collection, case_id))
            con.execute("DELETE FROM chunks WHERE collection=? AND case_id=?", (collection, case_id))
            con.execute("""INSERT INTO cases(collection,case_id,title,body,source_type,source_uri,module,metadata_json,content_hash,indexed_at)
                           VALUES(?,?,?,?,?,?,?,?,?,?)
                           ON CONFLICT(collection,case_id) DO UPDATE SET
                           title=excluded.title,body=excluded.body,source_type=excluded.source_type,
                           source_uri=excluded.source_uri,module=excluded.module,metadata_json=excluded.metadata_json,
                           content_hash=excluded.content_hash,indexed_at=excluded.indexed_at""",
                        (collection, case_id, prepared["title"], prepared["body"], prepared["source_type"],
                         prepared["source_uri"], prepared["module"], _json(meta), digest, _now()))
            for section in prepared["sections"]:
                cursor = con.execute("""INSERT INTO chunks(collection,case_id,section,heading_path,line_start,line_end,text,labels)
                                        VALUES(?,?,?,?,?,?,?,?)""",
                                     (collection, case_id, section["section"], section["heading_path"],
                                      section["line_start"], section["line_end"], section["text"], labels))
                if self.fts_enabled:
                    self._fts_insert(con, cursor.lastrowid, prepared["title"], section["section"],
                                     section["heading_path"], section["text"], labels)
            for relation in prepared["relations"]:
                source = relation["from"]
                target = relation["to"]
                source_id = _node_id(source["kind"], source["label"])
                target_id = _node_id(target["kind"], target["label"])
                for node_id, node in ((source_id, source), (target_id, target)):
                    con.execute("INSERT OR IGNORE INTO nodes(node_id,kind,label,normalized_label) VALUES(?,?,?,?)",
                                (node_id, node["kind"], node["label"], _norm_label(node["label"])))
                evidence = relation["evidence"]
                con.execute("""INSERT OR IGNORE INTO edges(collection,case_id,source_node,relation_type,target_node,status,
                               conditions_json,section,line_start,line_end) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                            (collection, case_id, source_id, relation["type"], target_id, relation["status"],
                             _json(relation["conditions"]), evidence["section"], evidence["line_start"], evidence["line_end"]))
            con.execute("DELETE FROM nodes WHERE node_id NOT IN (SELECT source_node FROM edges UNION SELECT target_node FROM edges)")
        return True

    def delete_case(self, case_id: str, *, collection: str = "default") -> bool:
        with self._connection() as con:
            chunk_ids = [r["chunk_id"] for r in con.execute(
                "SELECT chunk_id FROM chunks WHERE collection=? AND case_id=?", (collection, case_id)
            )]
            if not chunk_ids and not con.execute("SELECT 1 FROM cases WHERE collection=? AND case_id=?", (collection, case_id)).fetchone():
                return False
            if self.fts_enabled:
                con.executemany("DELETE FROM chunks_fts WHERE rowid=?", [(i,) for i in chunk_ids])
            con.execute("DELETE FROM cases WHERE collection=? AND case_id=?", (collection, case_id))
            con.execute("DELETE FROM nodes WHERE node_id NOT IN (SELECT source_node FROM edges UNION SELECT target_node FROM edges)")
        return True

    def sync_exploit_library(
        self, library_root: str | Path, *, collection: str = "ogamdo",
        source_job_root: str | Path | None = None,
        extracted_root: str | Path | None = None,
    ) -> dict[str, int]:
        """Reconcile one collection against an Exploit Library directory."""
        root = Path(library_root)
        if not root.is_dir():
            raise FileNotFoundError(root)
        counts = {"added": 0, "updated": 0, "unchanged": 0, "deleted": 0, "skipped": 0}
        seen: set[str] = set()
        for entry in sorted(root.iterdir()):
            if entry.is_symlink() or not entry.is_dir():
                continue
            # A directory may temporarily lack a complete report during an
            # overwrite. Preserve its previous index until a later scan.
            seen.add(entry.name)
            case = load_exploit_case(
                entry, source_job_root=Path(source_job_root) if source_job_root else None,
                extracted_root=Path(extracted_root) if extracted_root else None,
            )
            if case is None:
                counts["skipped"] += 1
                continue
            case_id = case["id"]
            was_present = self.has_case(case_id, collection=collection)
            changed = self.upsert_case(case, collection=collection)
            counts["added" if changed and not was_present else "updated" if changed else "unchanged"] += 1
        with self._connection() as con:
            # Only library-built cases are reconciled here; cases from other
            # sources in the same collection belong to their own ingester.
            stale = [r["case_id"] for r in con.execute(
                "SELECT case_id FROM cases WHERE collection=? AND source_type=?",
                (collection, EXPLOIT_SOURCE_TYPE),
            ) if r["case_id"] not in seen]
        for case_id in stale:
            if self.delete_case(case_id, collection=collection):
                counts["deleted"] += 1
        return counts

    def ingest_jsonl(self, path: str | Path, *, collection: str = "default", replace_missing: bool = False) -> dict[str, int]:
        """Ingest platform-neutral case JSONL; optionally reconcile deletions."""
        counts = {"added": 0, "updated": 0, "unchanged": 0, "deleted": 0}
        seen: set[str] = set()
        cases: list[dict[str, Any]] = []
        with Path(path).open(encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    case = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSON at line {line_no}") from exc
                if not isinstance(case, dict):
                    raise ValueError(f"case at line {line_no} is not an object")
                case_id = str(case.get("id") or "").strip()
                if case_id in seen:
                    raise ValueError(f"duplicate case id at line {line_no}: {case_id}")
                seen.add(case_id)
                cases.append(case)
        # Parse and validate the whole file before mutating the index. A bad
        # final line must not leave a half-imported Strata collection behind.
        for case in cases:
            self._prepare_case(case)
        for case in cases:
            case_id = str(case["id"]).strip()
            was_present = self.has_case(case_id, collection=collection)
            changed = self.upsert_case(case, collection=collection)
            counts["added" if changed and not was_present else "updated" if changed else "unchanged"] += 1
        if replace_missing:
            # A JSONL snapshot replaces only cases of the source types it
            # carries, so it cannot delete library cases sharing the collection.
            owned = sorted({self._prepare_case(case)["source_type"] for case in cases})
            marks = ",".join("?" for _ in owned)
            with self._connection() as con:
                stale = [r["case_id"] for r in con.execute(
                    f"SELECT case_id FROM cases WHERE collection=? AND source_type IN ({marks})",
                    (collection, *owned),
                ) if r["case_id"] not in seen] if owned else []
            for case_id in stale:
                if self.delete_case(case_id, collection=collection):
                    counts["deleted"] += 1
        return counts

    def stats(self) -> dict[str, Any]:
        with self._connection() as con:
            cases = con.execute("SELECT count(*) AS n FROM cases").fetchone()["n"]
            chunks = con.execute("SELECT count(*) AS n FROM chunks").fetchone()["n"]
            edges = con.execute("SELECT count(*) AS n FROM edges").fetchone()["n"]
            collections = {r["collection"]: r["n"] for r in con.execute("SELECT collection,count(*) AS n FROM cases GROUP BY collection")}
        return {"cases": cases, "chunks": chunks, "edges": edges, "collections": collections, "fts_enabled": self.fts_enabled}

    def search(
        self, query: str, *, module: str | None = None, collection: str | None = None,
        limit: int = 5, module_hint: str | None = None,
        exclude_case_ids: tuple[str, ...] = (), cards: int = 3,
    ) -> list[dict[str, Any]]:
        """Return one best cited section per case, ordered by relevance.

        ``module`` is an exact filter; ``module_hint`` is a soft boost that
        still permits cross-domain technique discovery.

        Cases are ranked on whole rows, case labels included. The section shown
        for a case is then chosen from that case's own text (see
        ``_attach_passages``), and each hit says which concepts the shown
        passage contains (``excerpt_terms``), which the case contains anywhere
        (``case_terms``), how much of the query it covers (``coverage``) and,
        for the first ``cards`` writeup digests, its ``method_card``.
        """
        plan = analyze_query(query)
        units = list(plan.units)
        if not units and plan.negated:
            # Only lacks were named ("no RELRO", "릭 없이"): look for them,
            # and let the lack decide the order below.
            units = list({u.name: u for span in plan.negated for u in span}.values())[:12]
        if not units:
            return []
        # Optional concepts ("filter" for "quotes filtered") only help a
        # passage clear the gate; they neither rank nor are required.
        names = {u.name for u in units}
        searched = units + [u for u in plan.optional if u.name not in names]
        # Lacked concepts still rank: the cases that name the asker's lack
        # ("no pop rdi gadget", "hooks removed") are often the answers. They
        # are never required, so a misread negation costs at most a demotion.
        lacked = [u for u in {u.name: u for span in plan.negated for u in span}.values() if u.name not in names]
        ranked = units + lacked
        # A lacked concept a passage names also counts toward the gate, as an
        # optional one does: when the lack is the topic ("external entities
        # disabled"), the answers name it.
        searched = searched + [u for u in lacked if u.name not in {x.name for x in searched}]
        rankable = {u.name for u in ranked}
        # A version number, "glibc" or a protection name only describes the
        # environment; such words alone never make a passage relevant.
        content = {u.name for u in units if not _is_environment(u)}
        need = required_units(len(units))
        limit = max(1, min(int(limit), 50))
        # (row, raw relevance, names of the query concepts this passage has)
        candidates: list[tuple[sqlite3.Row, float, list[str]]] = []
        where = []
        params: list[Any] = []
        if collection:
            where.append("c.collection=?")
            params.append(collection)
        if module:
            where.append("c.module=?")
            params.append(module.casefold())
        columns = """c.collection,c.case_id,c.title,c.source_type,c.source_uri,c.module,c.metadata_json,
                     k.section,k.heading_path,k.line_start,k.line_end,k.text"""
        # How many passages hold each concept, for coverage weights and for
        # naming concepts the index has never seen.
        frequency: dict[str, int] = {}
        with self._connection() as con:
            if self.fts_enabled:
                # One pass per concept says which passages contain it; the
                # ranked pass below cannot, because bm25 only returns a sum.
                having = [
                    {r[0] for r in con.execute("SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH ?", (u.fts(),))}
                    for u in searched
                ]
                frequency = {u.name: len(ids) for u, ids in zip(searched, having)}
                # A Korean word with no English spelling that no passage
                # contains is a gap in the vocabulary, not a missing concept:
                # it does not count toward how many concepts must match, as
                # long as the question also names a concept the index knows
                # in English. A question about nothing in the index (a recipe)
                # still needs its full share and comes back empty.
                unknown = sum(1 for u in units if not frequency[u.name] and all(a.korean for a in u.alternatives))
                anchored = any(frequency[u.name] and any(not a.korean for a in u.alternatives) for u in units)
                if unknown and anchored:
                    need = required_units(max(1, len(units) - unknown))
                content = {name for name in content if frequency[name]}
                sql = f"""SELECT chunks_fts.rowid AS fts_rowid,{columns},
                                  bm25(chunks_fts,0.25,0.5,1.0,3.0,1.0) AS bm_rank
                           FROM chunks_fts
                           JOIN chunks k ON k.chunk_id=chunks_fts.rowid
                           JOIN cases c ON c.collection=k.collection AND c.case_id=k.case_id
                           WHERE {' AND '.join(['chunks_fts MATCH ?'] + where)}
                           ORDER BY bm_rank ASC"""
                match = " OR ".join(f"({u.fts()})" for u in ranked)
                for row in con.execute(sql, [match] + params):
                    matched = [u.name for u, ids in zip(searched, having) if row["fts_rowid"] in ids]
                    if len(matched) >= need and (not content or content & set(matched)):
                        candidates.append((row, -float(row["bm_rank"]), matched))
            else:
                frequency = {u.name: 0 for u in searched}
                sql = f"""SELECT {columns},k.labels
                           FROM chunks k JOIN cases c ON c.collection=k.collection AND c.case_id=k.case_id
                           WHERE {' AND '.join(['1=1'] + where)}"""
                for row in con.execute(sql, params):
                    raw = " ".join([row["title"], row["heading_path"] or row["section"], row["text"], row["labels"]])
                    padded = " " + " ".join(tokens(raw)) + " "
                    matched = [u.name for u in searched if u.in_text(padded, raw)]
                    for name in matched:
                        frequency[name] += 1
                    if len(matched) >= need and (not content or content & set(matched)):
                        candidates.append((row, float(len(matched)), matched))
            excluded = set(exclude_case_ids)
            best: dict[tuple[str, str], dict[str, Any]] = {}
            for row, score, matched in candidates:
                if row["case_id"] in excluded:
                    continue
                # Among passages that clear the floor, prefer the fuller answer;
                # naming the asker's lack counts as part of the answer.
                score *= 0.5 + 0.5 * len([n for n in matched if n in rankable]) / len(ranked)
                matched = [n for n in matched if n in names]
                if module_hint and row["module"] == module_hint.casefold():
                    score *= 1.1
                key = (row["collection"], row["case_id"])
                hit = {
                    "case_id": row["case_id"], "collection": row["collection"],
                    "title": row["title"], "source_type": row["source_type"],
                    "source_uri": row["source_uri"], "module": row["module"],
                    "section": row["section"], "heading_path": row["heading_path"],
                    "line_start": row["line_start"],
                    "line_end": row["line_end"], "excerpt": row["text"],
                    "score": round(score, 8), "matched_terms": matched,
                    "metadata": json.loads(row["metadata_json"]),
                    "conflict_terms": [], "constraint_terms": [],
                }
                if key not in best or hit["score"] > best[key]["score"]:
                    best[key] = hit
            if plan.negated:
                for hit in best.values():
                    conflicts, shared = _negation_effect(hit["metadata"], plan.negated, plan.units)
                    if conflicts:
                        hit["score"] = round(hit["score"] * _CONFLICT_FACTOR, 8)
                    elif shared:
                        hit["score"] = round(hit["score"] * _SHARED_LACK_FACTOR, 8)
                    hit["conflict_terms"], hit["constraint_terms"] = conflicts, shared
            hits = sorted(best.values(), key=lambda h: (-h["score"], h["collection"], h["case_id"]))[:limit]
            self._attach_passages(con, hits, units, frequency, cards=cards, negated=plan.negated)
        return hits

    def _attach_passages(
        self, con: sqlite3.Connection, hits: list[dict[str, Any]], units: list[Any],
        frequency: dict[str, int], *, cards: int, negated: tuple[tuple[Any, ...], ...] = (),
    ) -> None:
        """Choose each hit's shown section and say what it and its case cover.

        The passage is the case's chunk with the highest sum of the query
        concepts in its own text, plus ``_PRIORITY_WEIGHT`` times its section
        priority. A concept the case title or labels already name counts
        half (it says which case, not which section), and a version number
        or protection name counts 0.3 (it echoes the asker's environment).
        A subsection takes its parent heading's priority when that is
        higher, and a chunk with almost no body counts less. Ties go to the
        higher priority, then the longer body, then the earlier chunk.
        Source, Keywords, run logs and empty chunks are shown only when a case
        has nothing else. Concepts found in the title, the metadata labels or
        any chunk (Keywords included) count for the case.
        """
        if not hits:
            return
        total = con.execute("SELECT count(*) AS n FROM chunks").fetchone()["n"] or 1
        weight = {u.name: math.log(1.0 + total / (1.0 + frequency.get(u.name, 0))) for u in units}
        order = [u.name for u in units]
        rows_of: dict[tuple[str, str], list[sqlite3.Row]] = {}
        for hit in hits:
            key = (hit["collection"], hit["case_id"])
            rows_of[key] = con.execute(
                """SELECT chunk_id,section,heading_path,line_start,line_end,text,labels
                   FROM chunks WHERE collection=? AND case_id=? ORDER BY line_start,chunk_id""",
                key,
            ).fetchall()
        # Body and title/label matches use the same tokenizer as ranking, so
        # an inflected form counts here exactly when it counted there. A
        # Korean spelling is checked against the passage's own text instead:
        # the ``ko`` column also carries the case title's syllables.
        in_body: dict[str, set[int]] = {}
        in_meta: dict[str, set[int]] = {}
        if self.fts_enabled:
            # Whole-table matches intersected here: FTS5 evaluates a MATCH
            # once per value of a ``rowid IN (...)`` list, which cost ~10 ms
            # per concept.
            ids = {r["chunk_id"] for rows in rows_of.values() for r in rows}
            sql = "SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH ?"
            for u in units:
                english = " OR ".join(a.fts() for a in u.alternatives if not a.korean)
                if not english:
                    in_body[u.name] = in_meta[u.name] = set()
                    continue
                in_body[u.name] = {r[0] for r in con.execute(sql, (f"body : ({english})",))} & ids
                in_meta[u.name] = {r[0] for r in con.execute(sql, (f"{{title labels}} : ({english})",))} & ids

        def has(u: Any, chunk_id: int, raw: str, found: dict[str, set[int]], path: tuple[str, str] | None = None) -> bool:
            """``raw`` is NFKC-casefolded text; ``path`` its parent headings (padded tokens, raw)."""
            if path and u.in_text(*path):
                # A subsection is found through its parent headings, as in
                # ranking; the heading words are few, so tokens suffice.
                return True
            if not self.fts_enabled:
                return u.in_text(" " + " ".join(tokens(raw)) + " ", raw)
            if chunk_id in found[u.name]:
                return True
            return any(a.korean and a.in_text("", raw) for a in u.alternatives)

        def folded(text: str) -> str:
            return unicodedata.normalize("NFKC", str(text or "")).casefold()

        shown = 0
        for hit in hits:
            hit.update(excerpt_terms=[], case_terms=[], coverage=None, method_card=None)
            rows = rows_of[(hit["collection"], hit["case_id"])]
            if not rows:
                continue
            title = hit["title"]
            # The document's top heading names the whole case, like the
            # title: it is neither a parent section nor a passage of its own.
            heads = {str(r["heading_path"] or "").split(" > ")[0].strip() for r in rows}
            root = heads.pop() if len(heads) == 1 else None
            case_terms: set[str] = set()
            meta_text = folded(title + " " + rows[0]["labels"])
            for u in units:
                if has(u, rows[0]["chunk_id"], meta_text, in_meta):
                    case_terms.add(u.name)
            protections = any(is_protection(u) for u in units)
            environment = {
                u.name for u in units
                if _is_environment(u) or (protections and u.name in {"full", "partial"})
            }
            term_weight = {
                u.name: 0.0 if u.name in environment else 0.5 if u.name in case_terms else 1.0
                for u in units
            }
            scored = []
            for row in rows:
                # Parent headings count for the passage; the case title, the
                # first element of every path, does not.
                path = [p for p in str(row["heading_path"] or "").split(" > ") if p]
                if path and path[0].strip() in (title.strip(), root):
                    path = path[1:]
                parents = folded(" ".join(path[:-1]))
                parent_words = (" " + " ".join(tokens(parents)) + " ", parents) if parents else None
                raw = folded(row["text"])
                present = {u.name for u in units if has(u, row["chunk_id"], raw, in_body, parent_words)}
                case_terms |= present
                priority = _passage_priority(row["section"], title)
                if root and str(row["section"]).strip() == root and not path:
                    priority = None
                body = len(_LEADING_HEADING.sub("", row["text"], count=1).strip())
                if priority is not None:
                    inherited = [v for v in (_passage_priority(p, title) for p in path[:-1]) if v is not None]
                    priority = max([priority, *inherited])
                    if body < 40 or _REDACTION_ONLY.fullmatch(row["text"].strip()):
                        priority = None  # a heading with nothing under it
                    elif body < 150:
                        priority *= 0.6
                scored.append((row, present, priority, body))
            eligible = [s for s in scored if s[2] is not None] or [(r, p, 0.0, b) for r, p, _, b in scored]
            row, present, _priority, _body = max(
                eligible,
                key=lambda s: (
                    # Environment words (version, glibc, protections) echo the
                    # question; together they count at most 0.3.
                    round(sum(term_weight[n] for n in s[1]) + (0.3 if environment & s[1] else 0.0)
                          + _PRIORITY_WEIGHT * s[2], 6),
                    s[2], min(s[3], 1500), -s[0]["line_start"],
                ),
            )
            hit.update(
                section=row["section"], heading_path=row["heading_path"],
                line_start=row["line_start"], line_end=row["line_end"], excerpt=row["text"],
            )
            gated = set(hit["matched_terms"])
            hit["excerpt_terms"] = [n for n in order if n in present]
            hit["case_terms"] = [n for n in order if n in case_terms]
            hit["matched_terms"] = [n for n in order if n in case_terms or n in gated]
            covered = case_terms | gated
            total_weight = sum(weight.values()) or 1.0
            hit["coverage"] = {
                "terms": len(order),
                "case": sum(1 for n in order if n in covered),
                "excerpt": len(present),
                "weighted": round(sum(weight[n] for n in order if n in covered) / total_weight, 3),
                "missing": [n for n in order if n not in covered],
                "absent_from_corpus": [n for n in order if frequency.get(n, 0) == 0],
                "negated": [" ".join(u.name for u in span) for span in negated],
            }
            card = None
            if hit["source_type"] == "writeup_digest" and shown < cards:
                card = _method_card(title, rows)
                shown += card is not None
            hit["method_card"] = card
        # A one-syllable Korean word never matches the ``ko`` pair index but
        # can occur in a passage; a concept some hit contains is not absent.
        found = {n for hit in hits for n in hit["case_terms"]}
        for hit in hits:
            if hit["coverage"]:
                hit["coverage"]["absent_from_corpus"] = [
                    n for n in hit["coverage"]["absent_from_corpus"] if n not in found
                ]

    def explore(
        self, node: str, *, depth: int = 2, collection: str | None = None,
        include_cases: bool = False,
    ) -> dict[str, Any]:
        """Follow supported relationships from a concept or node ID.

        Edges are aggregated by relation and status. Each support identifies
        the originating case and source span, so inferred links cannot appear
        as validated findings merely because they share terms.

        ``observed_in_case`` edges are left out unless ``include_cases`` is
        set: every concept of a case hangs off its case node, so following
        them turns a walk of the causal graph into a list of cohabitants.
        """
        depth = max(1, min(int(depth), 4))
        query = str(node).strip()
        if not query:
            return {"query": node, "nodes": [], "edges": []}
        with self._connection() as con:
            seeds = _seed_nodes(con, query)
            if not seeds:
                return {"query": node, "nodes": [], "edges": []}
            seen = set(seeds)
            frontier = set(seeds)
            edge_map: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
            for _ in range(depth):
                if not frontier or len(edge_map) >= 200:
                    break
                placeholders = ",".join("?" for _ in frontier)
                where = f"(e.source_node IN ({placeholders}) OR e.target_node IN ({placeholders}))"
                params: list[Any] = list(frontier) + list(frontier)
                if collection:
                    where += " AND e.collection=?"
                    params.append(collection)
                if not include_cases:
                    where += " AND e.relation_type!='observed_in_case'"
                # Ordered, so a truncated walk is the same walk every time.
                sql = f"""SELECT e.source_node,e.relation_type,e.target_node,e.status,e.conditions_json,
                                  e.section,e.line_start,e.line_end,e.case_id,e.collection,c.source_uri
                           FROM edges e JOIN cases c ON c.collection=e.collection AND c.case_id=e.case_id
                           WHERE {where} ORDER BY e.edge_id LIMIT 1000"""
                next_frontier: set[str] = set()
                for row in con.execute(sql, params):
                    key = (row["source_node"], row["relation_type"], row["target_node"], row["status"], row["conditions_json"])
                    record = edge_map.setdefault(key, {
                        "source": row["source_node"], "type": row["relation_type"],
                        "target": row["target_node"], "status": row["status"],
                        "conditions": json.loads(row["conditions_json"]), "supports": [],
                    })
                    record["supports"].append({
                        "case_id": row["case_id"], "collection": row["collection"],
                        "source_uri": row["source_uri"], "section": row["section"],
                        "line_start": row["line_start"], "line_end": row["line_end"],
                    })
                    for candidate in (row["source_node"], row["target_node"]):
                        if candidate not in seen:
                            next_frontier.add(candidate)
                    if len(edge_map) >= 200:
                        break
                seen.update(next_frontier)
                frontier = next_frontier
            node_rows = []
            if seen:
                placeholders = ",".join("?" for _ in seen)
                node_rows = list(con.execute(
                    f"SELECT node_id,kind,label FROM nodes WHERE node_id IN ({placeholders}) ORDER BY node_id",
                    list(seen),
                ))
        nodes = [{"id": r["node_id"], "kind": r["kind"], "label": r["label"]} for r in node_rows]
        edges = sorted(edge_map.values(), key=lambda e: (e["source"], e["type"], e["target"], e["status"]))
        return {"query": node, "nodes": nodes, "edges": edges}

    def related(
        self, node: str, *, kind: str | None = None,
        collection: str | None = None, limit: int = 10,
    ) -> dict[str, Any]:
        """Find direct links and cross-case associations for one concept.

        Co-observation means two concepts appear in the same documented case;
        it is deliberately not an exploit-enabling causal claim.
        """
        query = str(node).strip()
        if not query:
            return {"query": node, "related": []}
        limit = max(1, min(int(limit), 50))
        with self._connection() as con:
            seeds = _seed_nodes(con, query)
            if not seeds:
                return {"query": node, "related": []}
            marks = ",".join("?" for _ in seeds)
            direct_where = f"(e.source_node IN ({marks}) OR e.target_node IN ({marks})) AND e.relation_type!='observed_in_case'"
            direct_params: list[Any] = list(seeds) + list(seeds)
            if collection:
                direct_where += " AND e.collection=?"
                direct_params.append(collection)
            direct_sql = f"""SELECT e.*,c.source_uri,
                                   ns.kind AS source_kind,ns.label AS source_label,
                                   nt.kind AS target_kind,nt.label AS target_label
                            FROM edges e JOIN cases c ON c.collection=e.collection AND c.case_id=e.case_id
                            JOIN nodes ns ON ns.node_id=e.source_node JOIN nodes nt ON nt.node_id=e.target_node
                            WHERE {direct_where}"""
            records: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
            for row in con.execute(direct_sql, direct_params):
                outgoing = row["source_node"] in seeds
                other_id = row["target_node"] if outgoing else row["source_node"]
                other_kind = row["target_kind"] if outgoing else row["source_kind"]
                other_label = row["target_label"] if outgoing else row["source_label"]
                if kind and other_kind != kind:
                    continue
                direction = "outgoing" if outgoing else "incoming"
                key = (other_id, row["relation_type"], direction, row["status"], row["conditions_json"])
                record = records.setdefault(key, {
                    "node": {"id": other_id, "kind": other_kind, "label": other_label},
                    "relation": row["relation_type"], "direction": direction,
                    "status": row["status"], "conditions": json.loads(row["conditions_json"]),
                    "support_count": 0, "supports": [],
                })
                record["supports"].append({
                    "case_id": row["case_id"], "collection": row["collection"],
                    "source_uri": row["source_uri"], "section": row["section"],
                    "line_start": row["line_start"], "line_end": row["line_end"],
                })
            co_where = f"e1.source_node IN ({marks}) AND e1.relation_type='observed_in_case' AND e2.relation_type='observed_in_case'"
            co_params: list[Any] = list(seeds)
            if collection:
                co_where += " AND e1.collection=?"
                co_params.append(collection)
            if kind:
                co_where += " AND n.kind=?"
                co_params.append(kind)
            co_sql = f"""SELECT e2.source_node,n.kind,n.label,e2.case_id,e2.collection,c.source_uri,
                               e2.section,e2.line_start,e2.line_end
                        FROM edges e1 JOIN edges e2 ON e1.collection=e2.collection AND e1.case_id=e2.case_id
                        JOIN cases c ON c.collection=e2.collection AND c.case_id=e2.case_id
                        JOIN nodes n ON n.node_id=e2.source_node
                        WHERE {co_where}"""
            co_records: dict[str, dict[str, Any]] = {}
            co_seen: set[tuple[str, str, str]] = set()
            for row in con.execute(co_sql, co_params):
                other_id = row["source_node"]
                if other_id in seeds:
                    continue
                support_key = (other_id, row["collection"], row["case_id"])
                if support_key in co_seen:
                    continue
                co_seen.add(support_key)
                record = co_records.setdefault(other_id, {
                    "node": {"id": other_id, "kind": row["kind"], "label": row["label"]},
                    "relation": "co_observed", "direction": "undirected",
                    "status": "observed_in_cases", "conditions": [],
                    "support_count": 0, "supports": [],
                })
                record["supports"].append({
                    "case_id": row["case_id"], "collection": row["collection"],
                    "source_uri": row["source_uri"], "section": row["section"],
                    "line_start": row["line_start"], "line_end": row["line_end"],
                })
            # How many cases mention each co-observed neighbor at all. A label
            # on a third of the library ("logic", "constant") shares cases with
            # everything; sharing most of a rare label's cases is the signal.
            frequency: dict[str, int] = {}
            if co_records:
                ids = list(co_records)
                freq_where = f"source_node IN ({','.join('?' for _ in ids)}) AND relation_type='observed_in_case'"
                freq_params: list[Any] = ids
                if collection:
                    freq_where += " AND collection=?"
                    freq_params = ids + [collection]
                frequency = {r["source_node"]: r["n"] for r in con.execute(
                    f"SELECT source_node,count(DISTINCT collection||'/'||case_id) AS n FROM edges WHERE {freq_where} GROUP BY source_node",
                    freq_params,
                )}
        result = list(records.values()) + list(co_records.values())
        for record in result:
            record["support_count"] = len(record["supports"])
            if record["relation"] == "co_observed":
                record["case_frequency"] = frequency.get(record["node"]["id"], record["support_count"])
                record["_rank"] = record["support_count"] / (record["case_frequency"] + 5)
            else:
                record["_rank"] = float(record["support_count"])
            record["supports"] = sorted(
                record["supports"], key=lambda s: (s["collection"], s["case_id"], s["line_start"])
            )[:20]
        priority = {"verified": 0, "observed": 1, "candidate": 2, "taxonomy": 3, "observed_in_cases": 4}
        result.sort(key=lambda r: (priority.get(r["status"], 5), -r["_rank"], r["node"]["id"]))
        for record in result:
            del record["_rank"]
        return {"query": node, "related": result[:limit]}
