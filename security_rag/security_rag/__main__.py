"""JSON CLI for portable indexing, exploration, and optional model answers."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from .backfill import backfill_library
from .chat import answer_with_context
from .context import render_context
from .index import RagIndex
from .ingest import extracted_dir, load_exploit_case
from .server import RagHTTPServer


def _print_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def _search_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", required=True, help="derived SQLite index path")
    parser.add_argument("--query", required=True)
    parser.add_argument("--module", default=None, help="exact module filter")
    parser.add_argument("--collection", default=None)
    parser.add_argument("--limit", type=int, default=5)


def _snapshot(root: Path) -> tuple[tuple[str, int, int, int, int, int], ...]:
    rows = []
    for entry in root.iterdir():
        if not entry.is_dir():
            continue
        meta = entry / "meta.json"
        report = entry / "report.md"
        try:
            a = meta.stat()
            b = report.stat()
            try:
                extracted = (extracted_dir(root) / f"{entry.name}.json").stat().st_mtime_ns
            except OSError:
                extracted = 0
            rows.append((entry.name, a.st_mtime_ns, a.st_size, b.st_mtime_ns, b.st_size, extracted))
        except OSError:
            rows.append((entry.name, 0, 0, 0, 0, 0))
    return tuple(sorted(rows))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="security-rag")
    sub = parser.add_subparsers(dest="command", required=True)
    sync = sub.add_parser("sync-exploits", help="reconcile an Ogamdo-style Exploit Library")
    sync.add_argument("--library", required=True)
    sync.add_argument("--db", required=True)
    sync.add_argument("--collection", default="ogamdo")
    sync.add_argument("--source-jobs", default=None, help="optional job root for structured findings")
    watch = sub.add_parser("watch-exploits", help="keep a library index current as entries change")
    watch.add_argument("--library", required=True)
    watch.add_argument("--db", required=True)
    watch.add_argument("--collection", default="ogamdo")
    watch.add_argument("--source-jobs", default=None, help="optional job root for structured findings")
    watch.add_argument("--interval", type=float, default=15.0, help="poll seconds; default 15")
    single = sub.add_parser("upsert-exploit", help="index one saved exploit entry after a save")
    single.add_argument("--entry", required=True)
    single.add_argument("--db", required=True)
    single.add_argument("--collection", default="ogamdo")
    single.add_argument("--source-jobs", default=None, help="optional job root for structured findings")
    delete = sub.add_parser("delete-case", help="remove one indexed case")
    delete.add_argument("--id", required=True)
    delete.add_argument("--db", required=True)
    delete.add_argument("--collection", default="ogamdo")
    ingest = sub.add_parser("ingest-jsonl", help="ingest portable case JSONL")
    ingest.add_argument("--file", required=True)
    ingest.add_argument("--db", required=True)
    ingest.add_argument("--collection", default="strata")
    ingest.add_argument("--replace-missing", action="store_true", help="remove cases absent from this JSONL collection")
    search = sub.add_parser("search", help="return cited search hits as JSON")
    _search_args(search)
    explore = sub.add_parser("explore", help="follow evidence-backed concept relations")
    explore.add_argument("--db", required=True)
    explore.add_argument("--node", required=True)
    explore.add_argument("--depth", type=int, default=2)
    explore.add_argument("--collection", default=None)
    explore.add_argument("--include-cases", action="store_true", help="also follow observed_in_case edges")
    related = sub.add_parser("related", help="rank directly supported and co-observed concept links")
    related.add_argument("--db", required=True)
    related.add_argument("--node", required=True)
    related.add_argument("--kind", default=None, help="neighbor kind, e.g. technique")
    related.add_argument("--collection", default=None)
    related.add_argument("--limit", type=int, default=10)
    context = sub.add_parser("context", help="render search hits as model-neutral text")
    _search_args(context)
    context.add_argument("--max-chars", type=int, default=6000)
    context.add_argument("--node", default=None, help="include related concepts for this node")
    context.add_argument("--kind", default=None, help="related neighbor kind")
    context.add_argument("--related-limit", type=int, default=5)
    answer = sub.add_parser("answer", help="search, then call an OpenAI-compatible chat endpoint")
    _search_args(answer)
    answer.add_argument("--base-url", required=True)
    answer.add_argument("--model", required=True)
    answer.add_argument("--timeout", type=float, default=120.0)
    answer.add_argument("--max-chars", type=int, default=6000)
    answer.add_argument("--node", default=None, help="include related concepts for this node")
    answer.add_argument("--kind", default=None, help="related neighbor kind")
    answer.add_argument("--related-limit", type=int, default=5)
    fill = sub.add_parser("backfill", help="extract primitives and outcomes from saved reports with a chat model")
    fill.add_argument("--library", required=True)
    fill.add_argument("--base-url", required=True, help="OpenAI-compatible endpoint, ending in /v1")
    fill.add_argument("--model", required=True)
    fill.add_argument("--api-key-file", default=None, help="file holding the endpoint key; else SECURITY_RAG_API_KEY")
    fill.add_argument("--force", action="store_true", help="re-extract entries that already have a current result")
    fill.add_argument("--limit", type=int, default=None)
    fill.add_argument("--out", default=None, help="result directory; default <library>/../security-rag-extracted")
    fill.add_argument("--workers", type=int, default=2)
    fill.add_argument("--no-reasoning", action="store_true", help="ask the server to skip the model's thinking phase")
    stats = sub.add_parser("stats", help="show index counts")
    stats.add_argument("--db", required=True)
    serve = sub.add_parser("serve", help="serve authenticated read-only retrieval over HTTP")
    serve.add_argument("--db", required=True)
    serve.add_argument("--host", default="127.0.0.1", help="loopback bind address; default 127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--collections", default="ogamdo", help="comma-separated allowed collections")

    args = parser.parse_args(argv)
    try:
        if args.command == "serve":
            if args.host not in {"127.0.0.1", "localhost"}:
                raise ValueError("serve binds to loopback only; use an HTTPS proxy or tunnel for remote access")
            if not 1 <= args.port <= 65535:
                raise ValueError("port must be from 1 to 65535")
            collections = tuple(dict.fromkeys(x.strip() for x in args.collections.split(",") if x.strip()))
            token = os.environ.get("SECURITY_RAG_SERVER_TOKEN", "")
            with RagHTTPServer((args.host, args.port), args.db, token=token, collections=collections) as server:
                print(f"security-rag listening on http://{args.host}:{args.port}", flush=True)
                server.serve_forever(poll_interval=0.5)
            return 0
        if args.command == "backfill":
            key = os.environ.get("SECURITY_RAG_API_KEY")
            if args.api_key_file:
                key = Path(args.api_key_file).expanduser().read_text(encoding="utf-8").strip()
            _print_json(backfill_library(
                args.library, base_url=args.base_url, model=args.model, api_key=key,
                force=args.force, limit=args.limit, workers=args.workers,
                reasoning=not args.no_reasoning, out_dir=args.out,
            ))
            return 0
        index = RagIndex(args.db)
        if args.command == "sync-exploits":
            _print_json(index.sync_exploit_library(
                args.library, collection=args.collection, source_job_root=args.source_jobs
            ))
        elif args.command == "watch-exploits":
            root = Path(args.library)
            if not root.is_dir():
                raise FileNotFoundError(root)
            if args.interval < 1:
                raise ValueError("interval must be at least one second")
            previous = None
            cycles = 0
            while True:
                current = _snapshot(root)
                if current != previous or cycles % 24 == 0:
                    counts = index.sync_exploit_library(
                        root, collection=args.collection, source_job_root=args.source_jobs
                    )
                    print(json.dumps(counts, ensure_ascii=False), flush=True)
                    previous = current
                cycles += 1
                time.sleep(args.interval)
        elif args.command == "upsert-exploit":
            case = load_exploit_case(
                Path(args.entry), source_job_root=Path(args.source_jobs) if args.source_jobs else None
            )
            if case is None:
                raise ValueError("entry has no valid meta.json and report.md")
            _print_json({"case_id": case["id"], "changed": index.upsert_case(case, collection=args.collection)})
        elif args.command == "delete-case":
            _print_json({"case_id": args.id, "deleted": index.delete_case(args.id, collection=args.collection)})
        elif args.command == "ingest-jsonl":
            _print_json(index.ingest_jsonl(args.file, collection=args.collection, replace_missing=args.replace_missing))
        elif args.command == "search":
            _print_json(index.search(args.query, module=args.module, collection=args.collection, limit=args.limit))
        elif args.command == "explore":
            _print_json(index.explore(
                args.node, depth=args.depth, collection=args.collection, include_cases=args.include_cases
            ))
        elif args.command == "related":
            _print_json(index.related(args.node, kind=args.kind, collection=args.collection, limit=args.limit))
        elif args.command == "context":
            hits = index.search(args.query, module=args.module, collection=args.collection, limit=args.limit)
            links = index.related(args.node, kind=args.kind, collection=args.collection,
                                  limit=args.related_limit) if args.node else None
            print(render_context(hits, links=links, max_chars=args.max_chars))
        elif args.command == "answer":
            hits = index.search(args.query, module=args.module, collection=args.collection, limit=args.limit)
            links = index.related(args.node, kind=args.kind, collection=args.collection,
                                  limit=args.related_limit) if args.node else None
            _print_json(answer_with_context(
                args.query, hits, base_url=args.base_url, model=args.model,
                api_key=os.environ.get("SECURITY_RAG_API_KEY"), timeout=args.timeout,
                max_context_chars=args.max_chars,
                links=links,
            ))
        elif args.command == "stats":
            _print_json(index.stats())
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"security-rag: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
