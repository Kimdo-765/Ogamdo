"""Small, dependency-free client for the authenticated Security RAG API."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def request_rag(
    route: str, payload: dict, *, base_url: str | None = None,
    token: str | None = None, token_file: str | None = None,
) -> dict:
    if route not in {"search", "related", "explore", "context"}:
        raise ValueError("unsupported RAG route")
    base_url = (base_url or os.environ.get("SECURITY_RAG_URL") or "").rstrip("/")
    token = token or os.environ.get("SECURITY_RAG_SERVER_TOKEN") or ""
    if not token and token_file:
        saved = Path(token_file).read_text(encoding="utf-8").strip()
        prefix = "SECURITY_RAG_SERVER_TOKEN="
        token = saved[len(prefix):] if saved.startswith(prefix) else saved
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    ):
        raise ValueError("SECURITY_RAG_URL must be HTTPS for remote access")
    if not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username:
        raise ValueError("SECURITY_RAG_URL must be a plain origin, such as https://rag.example.com")
    if not token:
        raise ValueError("SECURITY_RAG_SERVER_TOKEN is required")
    req = Request(
        base_url + "/v1/" + route,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    with urlopen(req, timeout=20) as response:
        return json.load(response)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Query cited Security RAG evidence")
    commands = parser.add_subparsers(dest="route", required=True)
    for route in ("search", "related", "explore", "context"):
        cmd = commands.add_parser(route)
        cmd.add_argument("--base-url", help="RAG origin; defaults to SECURITY_RAG_URL")
        cmd.add_argument("--token-file", help="local token file when no environment token is set")
        cmd.add_argument("--collection", default="ogamdo")
        if route in {"search", "context"}:
            cmd.add_argument("--query", required=True)
            cmd.add_argument("--module")
            cmd.add_argument("--limit", type=int, default=5)
        if route in {"related", "explore"}:
            cmd.add_argument("--node", required=True)
        elif route == "context":
            cmd.add_argument("--node")
        if route in {"related", "context"}:
            cmd.add_argument("--kind")
        if route == "related":
            cmd.add_argument("--limit", type=int, default=10)
        if route == "explore":
            cmd.add_argument("--depth", type=int, default=2)
            cmd.add_argument("--include-cases", action="store_true", default=None,
                             help="also follow the links from each concept to its cases")
        if route == "context":
            cmd.add_argument("--max-chars", type=int, default=6000)
            cmd.add_argument("--related-limit", type=int, default=5)
    args = parser.parse_args(argv)
    payload = {key: value for key, value in vars(args).items()
               if key not in {"route", "base_url", "token_file"} and value is not None}
    try:
        result = request_rag(args.route, payload, base_url=args.base_url, token_file=args.token_file)
    except HTTPError as exc:
        print(f"RAG request failed with HTTP {exc.code}", file=sys.stderr)
        return 1
    except (URLError, ValueError, OSError) as exc:
        print(f"RAG request failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
