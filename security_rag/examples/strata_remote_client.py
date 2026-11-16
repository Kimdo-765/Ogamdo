"""Copy this dependency-free client into Strata to retrieve cited RAG context.

Set SECURITY_RAG_URL to the RAG server's HTTPS origin and
SECURITY_RAG_SERVER_TOKEN to the distinct RAG access token. The returned
context can be passed to any model; this example does not call a model.
"""

from __future__ import annotations

import argparse
import json
import os
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def fetch_context(
    query: str, *, node: str | None = None, kind: str | None = None,
    collection: str = "ogamdo", limit: int = 5,
    base_url: str | None = None, token: str | None = None,
) -> dict:
    """Return context, cited hits, and qualified links from the RAG server."""
    base_url = (base_url or os.environ.get("SECURITY_RAG_URL") or "").rstrip("/")
    token = token or os.environ.get("SECURITY_RAG_SERVER_TOKEN") or ""
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    ):
        raise ValueError("SECURITY_RAG_URL must use HTTPS for a remote server")
    if not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("SECURITY_RAG_URL must be an origin, such as https://rag.example.com")
    if not token:
        raise ValueError("SECURITY_RAG_SERVER_TOKEN is required")
    payload = {"query": query, "collection": collection, "limit": limit}
    if node:
        payload["node"] = node
    if kind:
        payload["kind"] = kind
    request = Request(
        base_url + "/v1/context",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=20) as response:
        return json.load(response)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch cited RAG context for Strata")
    parser.add_argument("--query", required=True)
    parser.add_argument("--node")
    parser.add_argument("--kind")
    parser.add_argument("--collection", default="ogamdo")
    args = parser.parse_args()
    result = fetch_context(args.query, node=args.node, kind=args.kind, collection=args.collection)
    print(json.dumps(result, ensure_ascii=False, indent=2))
