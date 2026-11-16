"""HTTP contract and access-control checks for remote retrieval."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT / "examples"))

from security_rag.index import RagIndex  # noqa: E402
from security_rag.server import RagHTTPServer  # noqa: E402
from strata_remote_client import fetch_context  # noqa: E402

TOKEN = "fixture-" + "qwerty0123456789abcdef"


class RagServerTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory(prefix="rag-http-test-")
        self.addCleanup(temp.cleanup)
        db = Path(temp.name) / "index.sqlite"
        index = RagIndex(db)
        index.upsert_case({
            "id": "case-one",
            "title": "Allocator study",
            "body": "## Root Cause\nA stale pointer causes use after free in the allocator.\n",
            "source_type": "research_note",
            "source_uri": "https://example.invalid/research/one",
            "module": "pwn",
            "metadata": {"bug_classes": ["uaf"]},
            "relations": [{
                "from": {"kind": "root_cause", "label": "use after free"},
                "type": "produces",
                "to": {"kind": "primitive", "label": "arbitrary read"},
                "status": "observed",
                "conditions": ["stale object remains reachable"],
                "evidence": {"section": "Root Cause", "line_start": 1, "line_end": 2},
            }],
        }, collection="ogamdo")
        index.upsert_case({
            "id": "private-case", "title": "Private study", "body": "secret_other_collection_marker",
            "source_type": "research_note", "source_uri": "case://private-case", "module": "web",
        }, collection="private")
        self.server = RagHTTPServer(("127.0.0.1", 0), db, token=TOKEN, collections=("ogamdo",))
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (self.server.shutdown(), thread.join(timeout=2)))
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def request(self, path: str, body: dict | None = None, *, token: str | None = TOKEN):
        headers = {"Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        req = Request(
            self.base + path,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            headers=headers,
        )
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as exc:
            return exc.code, json.load(exc)

    def test_health_and_authentication(self) -> None:
        self.assertEqual((200, {"status": "ok"}), self.request("/healthz", token=None))
        self.assertEqual(401, self.request("/v1/search", {"query": "uaf"}, token=None)[0])
        self.assertEqual(401, self.request("/v1/search", {"query": "uaf"}, token="wrong")[0])
        self.assertEqual(404, self.request("/v1/upsert", {"query": "uaf"})[0])

    def test_search_context_and_relations(self) -> None:
        status, data = self.request("/v1/search", {"query": "stale pointer", "module": "pwn"})
        self.assertEqual(200, status)
        self.assertEqual("case-one", data["hits"][0]["case_id"])
        self.assertEqual("https://example.invalid/research/one", data["hits"][0]["source_uri"])
        self.assertGreaterEqual(data["hits"][0]["line_start"], 1)

        status, data = self.request("/v1/related", {"node": "use after free", "kind": "primitive"})
        self.assertEqual(200, status)
        self.assertEqual("arbitrary read", data["related"][0]["node"]["label"])
        self.assertEqual("observed", data["related"][0]["status"])

        status, data = self.request("/v1/explore", {"node": "use after free", "depth": 1})
        self.assertEqual(200, status)
        self.assertTrue(any(e["type"] == "produces" for e in data["edges"]))

        status, data = self.request("/v1/context", {
            "query": "stale pointer", "node": "use after free", "kind": "primitive",
            "max_chars": 1200,
        })
        self.assertEqual(200, status)
        self.assertIn("case-one", data["context"])
        self.assertIn("arbitrary read", data["context"])

    def test_collection_scope_and_request_limits(self) -> None:
        self.assertEqual(403, self.request("/v1/search", {
            "query": "secret_other_collection_marker", "collection": "private",
        })[0])
        self.assertEqual([], self.request("/v1/search", {
            "query": "secret_other_collection_marker",
        })[1]["hits"])
        self.assertEqual(400, self.request("/v1/search", {"query": "uaf", "limit": 1000})[0])
        self.assertEqual(400, self.request("/v1/explore", {"node": "uaf", "depth": 4})[0])
        self.assertEqual(413, self.request("/v1/search", {"query": "x" * 9000})[0])

    def test_concurrent_requests_never_overlap_index_calls(self) -> None:
        # Concurrent SQLite work from many server threads collapsed under load,
        # so index calls must be serialized while requests still all succeed.
        state = {"active": 0, "peak": 0}
        guard = threading.Lock()
        original = self.server.index.search

        def tracked(*args, **kwargs):
            with guard:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            try:
                threading.Event().wait(0.02)
                return original(*args, **kwargs)
            finally:
                with guard:
                    state["active"] -= 1

        self.server.index.search = tracked
        statuses: list[int] = []
        workers = [threading.Thread(target=lambda: statuses.append(
            self.request("/v1/search", {"query": "stale pointer"})[0])) for _ in range(8)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)
        self.assertEqual([200] * 8, statuses)
        self.assertEqual(1, state["peak"])

    def test_server_requires_existing_index_and_separate_token(self) -> None:
        with self.assertRaises(ValueError):
            RagHTTPServer(("127.0.0.1", 0), self.server.index.db_path, token="short")
        with self.assertRaises(FileNotFoundError):
            RagHTTPServer(("127.0.0.1", 0), self.server.index.db_path.parent / "missing", token=TOKEN)

    def test_standalone_strata_client_uses_same_context_contract(self) -> None:
        result = fetch_context("stale pointer", node="use after free", kind="primitive",
                               base_url=self.base, token=TOKEN)
        self.assertIn("case-one", result["context"])
        self.assertEqual("observed", result["links"]["related"][0]["status"])
        with self.assertRaises(ValueError):
            fetch_context("stale pointer", base_url="http://remote.example.invalid", token=TOKEN)


if __name__ == "__main__":
    unittest.main()
