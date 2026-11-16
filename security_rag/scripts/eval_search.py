"""Measure search quality against an existing index, using metadata as labels.

A hit counts as relevant when the case's own ``bug_classes`` or
``technique_name`` contains one of the expected substrings. Those fields were
written by the report phase, not by a reviewer, so the numbers are a
regression signal for ranking changes rather than an absolute score.

    python3 scripts/eval_search.py --db ../data/security-rag.sqlite

The index is copied to a temporary file first; the source is opened read-only.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security_rag import RagIndex  # noqa: E402

# (query, expected substrings in bug_classes/technique_name; () = expect no hits)
QUERIES: list[tuple[str, tuple[str, ...]]] = [
    # abbreviations and their long forms
    ("uaf", ("uaf",)),
    ("use after free", ("uaf",)),
    ("use-after-free tcache", ("uaf", "tcache")),
    ("rce", ("rce", "command-injection")),
    ("sqli", ("sqli", "sql")),
    ("ssrf", ("ssrf",)),
    ("xss", ("xss",)),
    ("fsop", ("fsop",)),
    # plain technique and weakness names
    ("heap overflow", ("heap-overflow",)),
    ("format string", ("fmt-string",)),
    ("double free", ("double-free",)),
    ("prototype pollution", ("prototype-pollution",)),
    ("race condition", ("race",)),
    ("path traversal", ("path-traversal", "lfi")),
    ("type confusion", ("type-confusion", "typer")),
    ("house of einherjar", ("einherjar",)),
    ("tcache poisoning", ("tcache",)),
    ("integer overflow", ("int-overflow",)),
    # inflected forms
    ("heap overflows", ("heap-overflow",)),
    ("format strings", ("fmt-string",)),
    ("race conditions", ("race",)),
    ("out of bounds writes", ("oob-write",)),
    # Korean and mixed
    ("힙 오버플로우", ("heap-overflow",)),
    ("포맷 스트링", ("fmt-string",)),
    ("경쟁 상태", ("race",)),
    ("프로토타입 오염", ("prototype-pollution",)),
    ("힙 UAF", ("uaf",)),
    ("임의 주소 쓰기", ("oob-write", "aaw", "uaf", "heap-overflow")),
    ("명령어 삽입", ("command-injection",)),
    # unrelated: the right answer is nothing
    ("kubernetes ingress annotation helm chart", ()),
    ("quarterly revenue forecast spreadsheet", ()),
    ("레시피 김치찌개 끓이는 법", ()),
]


def _relevant(hit: dict, expected: tuple[str, ...]) -> bool:
    meta = hit.get("metadata") or {}
    haystack = " ".join(
        [str(x) for x in (meta.get("bug_classes") or [])]
        + [str(meta.get("technique_name") or "")]
        + [str(x) for x in (meta.get("primitives") or [])]
    ).casefold().replace("_", "-")
    return any(e in haystack for e in expected)


def evaluate(index: RagIndex, collection: str, limit: int = 5) -> dict:
    rows = []
    for query, expected in QUERIES:
        hits = index.search(query, collection=collection, limit=limit)
        if not expected:
            rows.append({"query": query, "kind": "negative", "hits": len(hits),
                         "ok": not hits})
            continue
        flags = [_relevant(h, expected) for h in hits]
        first = next((i for i, f in enumerate(flags) if f), None)
        rows.append({
            "query": query, "kind": "positive", "hits": len(hits),
            "p_at_k": round(sum(flags) / limit, 3),
            "rr": round(1 / (first + 1), 3) if first is not None else 0.0,
        })
    pos = [r for r in rows if r["kind"] == "positive"]
    neg = [r for r in rows if r["kind"] == "negative"]
    return {
        "positive_queries": len(pos),
        "mean_p_at_5": round(sum(r["p_at_k"] for r in pos) / len(pos), 3),
        "mrr": round(sum(r["rr"] for r in pos) / len(pos), 3),
        "zero_hit_positives": [r["query"] for r in pos if not r["hits"]],
        "missed_positives": [r["query"] for r in pos if r["hits"] and not r["rr"]],
        "negatives_correctly_empty": f"{sum(r['ok'] for r in neg)}/{len(neg)}",
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", required=True)
    parser.add_argument("--collection", default="ogamdo")
    parser.add_argument("--rows", action="store_true", help="include per-query rows")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / "index.sqlite"
        src = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
        dst = sqlite3.connect(copy)
        src.backup(dst)
        dst.close()
        src.close()
        result = evaluate(RagIndex(copy), args.collection)
    if not args.rows:
        result.pop("rows")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
