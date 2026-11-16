"""SQLite-backed, provider-neutral retrieval and evidence graph.

The database is derived state. Source cases remain authoritative; callers may
rebuild this file at any time. The same API can index Ogamdo's Exploit Library
or cases supplied by another platform such as Strata.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit

from .ingest import EXPLOIT_SOURCE_TYPE, chunk_markdown, load_exploit_case
from .query import expand_labels, hangul_index_text, parse_query, required_units, tokens
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
        exclude_case_ids: tuple[str, ...] = (),
    ) -> list[dict[str, Any]]:
        """Return one best cited section per case, ordered by relevance.

        ``module`` is an exact filter; ``module_hint`` is a soft boost that
        still permits cross-domain technique discovery.
        """
        units = parse_query(query)
        if not units:
            return []
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
        with self._connection() as con:
            if self.fts_enabled:
                # One pass per concept says which passages contain it; the
                # ranked pass below cannot, because bm25 only returns a sum.
                having = [
                    {r[0] for r in con.execute("SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH ?", (u.fts(),))}
                    for u in units
                ]
                sql = f"""SELECT chunks_fts.rowid AS fts_rowid,{columns},
                                  bm25(chunks_fts,0.25,0.5,1.0,3.0,1.0) AS bm_rank
                           FROM chunks_fts
                           JOIN chunks k ON k.chunk_id=chunks_fts.rowid
                           JOIN cases c ON c.collection=k.collection AND c.case_id=k.case_id
                           WHERE {' AND '.join(['chunks_fts MATCH ?'] + where)}
                           ORDER BY bm_rank ASC"""
                match = " OR ".join(f"({u.fts()})" for u in units)
                for row in con.execute(sql, [match] + params):
                    matched = [u.name for u, ids in zip(units, having) if row["fts_rowid"] in ids]
                    if len(matched) >= need:
                        candidates.append((row, -float(row["bm_rank"]), matched))
            else:
                sql = f"""SELECT {columns},k.labels
                           FROM chunks k JOIN cases c ON c.collection=k.collection AND c.case_id=k.case_id
                           WHERE {' AND '.join(['1=1'] + where)}"""
                for row in con.execute(sql, params):
                    raw = " ".join([row["title"], row["heading_path"] or row["section"], row["text"], row["labels"]])
                    padded = " " + " ".join(tokens(raw)) + " "
                    matched = [u.name for u in units if u.in_text(padded, raw)]
                    if len(matched) >= need:
                        candidates.append((row, float(len(matched)), matched))
        excluded = set(exclude_case_ids)
        best: dict[tuple[str, str], dict[str, Any]] = {}
        for row, score, matched in candidates:
            if row["case_id"] in excluded:
                continue
            # Among passages that clear the floor, prefer the fuller answer.
            score *= 0.5 + 0.5 * len(matched) / len(units)
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
            }
            if key not in best or hit["score"] > best[key]["score"]:
                best[key] = hit
        return sorted(best.values(), key=lambda h: (-h["score"], h["collection"], h["case_id"]))[:limit]

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
