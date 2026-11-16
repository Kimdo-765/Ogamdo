"""Authenticated, read-only HTTP retrieval for remote model runtimes."""

from __future__ import annotations

import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .context import render_context
from .index import RagIndex

MAX_REQUEST_BYTES = 8192
MAX_RESPONSE_BYTES = 262144


def _string(data: dict[str, Any], key: str, *, required: bool = False, max_length: int = 1000) -> str | None:
    value = data.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ValueError(f"{key} must be a nonempty string of at most {max_length} characters")
    return value.strip()


def _integer(data: dict[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{key} must be an integer from {minimum} to {maximum}")
    return value


class RagHTTPServer(ThreadingHTTPServer):
    """One index instance shared by short, independent read requests."""

    daemon_threads = True
    block_on_close = False
    request_queue_size = 16

    def __init__(
        self, address: tuple[str, int], db_path: str | Path, *,
        token: str, collections: tuple[str, ...] = ("ogamdo",),
    ) -> None:
        if not token or len(token) < 24:
            raise ValueError("SECURITY_RAG_SERVER_TOKEN must contain at least 24 characters")
        if not collections or any(not name or len(name) > 80 for name in collections):
            raise ValueError("at least one valid collection is required")
        db = Path(db_path)
        if not db.is_file():
            raise FileNotFoundError(f"RAG index does not exist: {db}")
        self.index = RagIndex(db, read_only=True)
        # Index calls run one at a time. Concurrent SQLite/FTS work from many
        # threads of one process contends badly: measured on the live index,
        # 8 parallel searches cost ~1.2 s CPU each (6 s p50) instead of ~25 ms,
        # and bursts timed out. Serialized, 8 waiters see ~0.2 s at worst.
        self.index_lock = threading.Lock()
        self.token = token
        self.collections = frozenset(collections)
        self.default_collection = collections[0]
        self._slots = threading.BoundedSemaphore(16)
        super().__init__(address, RagRequestHandler)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(10)
        return request, client_address

    def process_request(self, request, client_address):
        self._slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class RagRequestHandler(BaseHTTPRequestHandler):
    server: RagHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        # Queries and credentials belong in request bodies/headers, never logs.
        return

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_RESPONSE_BYTES:
            status = 413
            body = b'{"error":"response_too_large"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _authorized(self) -> bool:
        auth = self.headers.get("Authorization", "")
        prefix = "Bearer "
        supplied = auth[len(prefix):] if auth.startswith(prefix) else ""
        if len(auth) > 256 or not hmac.compare_digest(
            supplied.encode("utf-8"), self.server.token.encode("utf-8")
        ):
            self._send(401, {"error": "unauthorized"})
            return False
        return True

    def _collection(self, data: dict[str, Any]) -> str:
        name = _string(data, "collection", max_length=80) or self.server.default_collection
        if name not in self.server.collections:
            raise PermissionError("collection is not available")
        return name

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path not in {"/v1/search", "/v1/related", "/v1/explore", "/v1/context"}:
            self._send(404, {"error": "not_found"})
            return
        if not self._authorized():
            return
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._send(415, {"error": "content_type_must_be_application_json"})
            return
        try:
            size = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            size = -1
        if size < 0 or size > MAX_REQUEST_BYTES:
            self._send(413, {"error": "request_size_invalid"})
            self.close_connection = True
            return
        try:
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object")
            with self.server.index_lock:
                result = self._dispatch(data)
            self._send(200, result)
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            self._send(400, {"error": str(exc)[:200]})
        except PermissionError:
            self._send(403, {"error": "collection_forbidden"})
        except Exception:
            # Never disclose database paths, SQL, or indexed content in errors.
            self._send(500, {"error": "internal_error"})

    def _dispatch(self, data: dict[str, Any]) -> dict[str, Any]:
        collection = self._collection(data)
        if self.path in {"/v1/search", "/v1/context"}:
            query = _string(data, "query", required=True)
            assert query is not None
            module = _string(data, "module", max_length=80)
            limit = _integer(data, "limit", 5, 1, 20)
            hits = self.server.index.search(query, module=module, collection=collection, limit=limit)
            if self.path == "/v1/search":
                return {"hits": hits}
            node = _string(data, "node", max_length=160)
            kind = _string(data, "kind", max_length=40)
            if kind and not node:
                raise ValueError("kind requires node")
            related_limit = _integer(data, "related_limit", 5, 1, 10)
            max_chars = _integer(data, "max_chars", 6000, 200, 12000)
            links = (
                self.server.index.related(node, kind=kind, collection=collection, limit=related_limit)
                if node else None
            )
            return {
                "context": render_context(hits, links=links, max_chars=max_chars),
                "hits": hits,
                "links": links,
            }
        node = _string(data, "node", required=True, max_length=160)
        assert node is not None
        if self.path == "/v1/related":
            kind = _string(data, "kind", max_length=40)
            limit = _integer(data, "limit", 10, 1, 20)
            return self.server.index.related(node, kind=kind, collection=collection, limit=limit)
        depth = _integer(data, "depth", 2, 1, 2)
        include_cases = data.get("include_cases", False)
        if not isinstance(include_cases, bool):
            raise ValueError("include_cases must be a boolean")
        return self.server.index.explore(node, depth=depth, collection=collection, include_cases=include_cases)
