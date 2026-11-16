"""Behavioral tests for the standalone security research RAG package.

Run from the repository root with::

    python3 -m unittest discover -s security_rag/tests -v

The fixtures intentionally use the on-disk format exported by Ogamdo, while
the custom cases exercise the platform-neutral API Strata can also call.
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from security_rag import RagIndex, redact_text, render_context  # noqa: E402


def write_exploit(root: Path, case_id: str, report: str, **metadata: object) -> Path:
    entry = root / case_id
    entry.mkdir(parents=True, exist_ok=True)
    meta = {
        "id": case_id,
        "module": "pwn",
        "chal_name": "sample target",
        "source_job_id": case_id.split("-", 1)[-1],
        "technique_name": "tcache_poison",
        "bug_classes": ["uaf"],
        "saved_at": "2026-11-01T00:00:00+00:00",
        **metadata,
    }
    (entry / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (entry / "report.md").write_text(report, encoding="utf-8")
    return entry


class PortableRagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="portable-rag-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.library = self.root / "exploits"
        self.library.mkdir()
        self.index = RagIndex(self.root / "rag.sqlite")

    def test_incremental_sync_updates_and_deletes_only_changed_entries(self) -> None:
        case_id = "pwn-aabbccddeeff"
        entry = write_exploit(
            self.library,
            case_id,
            "# Sample\n\n## Root Cause: stale heap pointer\nA stale heap pointer is reused.\n\n"
            "## Primitive: arbitrary read\nThe stale pointer enables arbitrary read.\n\n"
            "## Technique: tcache poisoning\nThe report describes the technique.\n",
            flags=["DH{secret_flag_123}"],
            target_url="https://internal.example.invalid:8443",
        )
        first = self.index.sync_exploit_library(self.library)
        self.assertIsInstance(first, dict)
        initial_hits = self.index.search("stale heap pointer", limit=10)
        self.assertIn(case_id, json.dumps(initial_hits))
        graph = self.index.explore("stale heap pointer", depth=1, collection="ogamdo")
        inferred = [edge for edge in graph["edges"] if edge["type"] == "produces"]
        self.assertEqual(1, len(inferred), graph)
        self.assertEqual("candidate", inferred[0]["status"])
        self.assertEqual("Primitive: arbitrary read", inferred[0]["supports"][0]["section"])

        second = self.index.sync_exploit_library(self.library)
        self.assertIsInstance(second, dict)
        # A second scan must not create duplicate search results.
        self.assertEqual(
            len(initial_hits),
            len(self.index.search("stale heap pointer", limit=10)),
        )

        (entry / "report.md").write_text(
            "# Sample\n\n## Root Cause\nA refcount race enables use after free.\n\n"
            "## Primitive\nArbitrary read.\n\n## Technique\nTcache poisoning.\n",
            encoding="utf-8",
        )
        self.index.sync_exploit_library(self.library)
        self.assertNotIn(case_id, json.dumps(self.index.search("stale heap pointer")))
        self.assertIn(case_id, json.dumps(self.index.search("refcount race")))

        for child in entry.iterdir():
            child.unlink()
        entry.rmdir()
        self.index.sync_exploit_library(self.library)
        self.assertNotIn(case_id, json.dumps(self.index.search("refcount race")))

    def test_search_is_collection_scoped_and_persists_after_reopen(self) -> None:
        case = {
            "id": "case-1",
            "title": "Allocator regression",
            "body": "## Root Cause\nA refcount race in the allocator.\n",
            "source_type": "research_note",
            "source_uri": "https://example.invalid/research/case-1",
            "module": "pwn",
            "metadata": {"arch": "x86_64"},
            "relations": [],
        }
        self.assertTrue(self.index.upsert_case(case, collection="strata"))
        self.assertFalse(self.index.upsert_case(case, collection="strata"))
        self.assertIn("case-1", json.dumps(self.index.search("refcount race", collection="strata")))
        self.assertNotIn("case-1", json.dumps(self.index.search("refcount race", collection="ogamdo")))

        reopened = RagIndex(self.root / "rag.sqlite")
        hits = reopened.search("refcount race", collection="strata")
        self.assertIn("case-1", json.dumps(hits))
        self.assertEqual("https://example.invalid/research/case-1", hits[0]["source_uri"])
        self.assertGreaterEqual(hits[0]["line_start"], 1)
        self.assertIn("refcount race", hits[0]["excerpt"])

    def test_strata_jsonl_reconciliation_does_not_touch_other_collections(self) -> None:
        write_exploit(self.library, "pwn-aabbccddeeff", "## Technique\nTcache poisoning.\n")
        self.index.sync_exploit_library(self.library)
        path = self.root / "strata.jsonl"
        cases = [{
            "id": case_id,
            "title": title,
            "body": f"## Technique\n{title} is relevant to a test component.\n",
            "source_type": "research_note",
            "source_uri": f"https://example.invalid/{case_id}",
            "module": "web",
            "metadata": {},
            "relations": [],
        } for case_id, title in (("strata-one", "cache invalidation"),
                                ("strata-two", "session fixation"))]
        path.write_text("\n".join(json.dumps(case) for case in cases) + "\n", encoding="utf-8")
        self.assertEqual(2, self.index.ingest_jsonl(path, collection="strata")["added"])
        self.assertEqual(2, self.index.ingest_jsonl(path, collection="strata")["unchanged"])
        self.assertIn("strata-two", json.dumps(self.index.search("session fixation", collection="strata")))

        path.write_text(json.dumps(cases[0]) + "\n", encoding="utf-8")
        self.assertEqual(
            1,
            self.index.ingest_jsonl(path, collection="strata", replace_missing=True)["deleted"],
        )
        self.assertNotIn("strata-two", json.dumps(self.index.search("session fixation", collection="strata")))
        self.assertIn("pwn-aabbccddeeff", json.dumps(self.index.search("tcache", collection="ogamdo")))

    def test_incomplete_overwrite_keeps_previous_index_until_entry_is_complete(self) -> None:
        case_id = "pwn-abcdef123456"
        entry = write_exploit(
            self.library, case_id,
            "## Root Cause\nA stale pointer is reachable from the allocator.\n",
        )
        self.index.sync_exploit_library(self.library)
        self.assertIn(case_id, json.dumps(self.index.search("stale pointer")))

        report = entry / "report.md"
        saved_report = report.read_text(encoding="utf-8")
        report.unlink()  # an import or overwrite may be between file writes
        self.index.sync_exploit_library(self.library)
        self.assertIn(case_id, json.dumps(self.index.search("stale pointer")))

        report.write_text(saved_report, encoding="utf-8")
        meta = entry / "meta.json"
        saved_meta = meta.read_text(encoding="utf-8")
        meta.unlink()
        self.index.sync_exploit_library(self.library)
        self.assertIn(case_id, json.dumps(self.index.search("stale pointer")))

        meta.write_text(saved_meta, encoding="utf-8")
        report.write_text("## Root Cause\nA new allocator refcount bug is reachable.\n", encoding="utf-8")
        self.index.sync_exploit_library(self.library)
        self.assertNotIn(case_id, json.dumps(self.index.search("stale pointer")))
        self.assertIn(case_id, json.dumps(self.index.search("refcount bug")))

    def test_generic_source_uri_does_not_expose_credentials_or_query(self) -> None:
        source = "https://alice:password123@example.invalid/research/case?token=hidden123#private"
        self.index.upsert_case({
            "id": "case-uri",
            "title": "Relevant allocator note",
            "body": "## Root Cause\nA lifetime bug in the allocator.\n",
            "source_type": "research_note",
            "source_uri": source,
            "module": "pwn",
            "metadata": {},
            "relations": [],
        }, collection="strata")
        hits = self.index.search("lifetime bug", collection="strata")
        self.assertEqual("https://example.invalid/research/case", hits[0]["source_uri"])
        payload = json.dumps(hits) + render_context(hits)
        for value in ("alice", "password123", "hidden123", "private"):
            self.assertNotIn(value, payload)

    def test_shared_relation_keeps_other_case_evidence_after_delete(self) -> None:
        relation = {
            "from": {"kind": "root_cause", "label": "use after free"},
            "type": "produces",
            "to": {"kind": "primitive", "label": "arbitrary read"},
            "status": "verified",
            "evidence": {"section": "Root Cause", "line_start": 3, "line_end": 5},
            "conditions": ["stale object is reachable"],
        }
        for case_id in ("case-one", "case-two"):
            self.assertTrue(self.index.upsert_case({
                "id": case_id,
                "title": f"{case_id} research",
                "body": "## Root Cause\nA reachable stale object creates arbitrary read.\n",
                "source_type": "research_note",
                "source_uri": f"https://example.invalid/{case_id}",
                "module": "pwn",
                "metadata": {},
                "relations": [relation],
            }, collection="strata"))

        def supports() -> set[str]:
            graph = self.index.explore("use after free", depth=1, collection="strata")
            edges = [e for e in graph["edges"] if e["type"] == "produces"]
            self.assertEqual(1, len(edges), graph)
            self.assertEqual("verified", edges[0]["status"])
            self.assertEqual(["stale object is reachable"], edges[0]["conditions"])
            self.assertTrue(
                {"source_uri", "section", "line_start", "line_end"}
                <= edges[0]["supports"][0].keys()
            )
            return {support["case_id"] for support in edges[0]["supports"]}

        self.assertEqual({"case-one", "case-two"}, supports())
        self.assertTrue(self.index.delete_case("case-one", collection="strata"))
        self.assertEqual({"case-two"}, supports())
        self.assertTrue(self.index.delete_case("case-two", collection="strata"))
        self.assertFalse(self.index.explore("use after free", depth=1, collection="strata")["edges"])

    def test_related_distinguishes_co_observation_from_verified_link(self) -> None:
        left = {"kind": "technique", "label": "tcache poisoning"}
        right = {"kind": "technique", "label": "FSOP variant"}

        def observation(case_id: str, technique: dict[str, str]) -> dict:
            return {
                "from": technique,
                "type": "observed_in_case",
                "to": {"kind": "case", "label": case_id},
                "status": "observed",
                "evidence": {"section": "Technique", "line_start": 3, "line_end": 5},
                "conditions": [],
            }

        for case_id in ("case-alpha", "case-beta"):
            self.index.upsert_case({
                "id": case_id,
                "title": case_id,
                "body": "## Technique\nTwo techniques were discussed in this case.\n",
                "source_type": "research_note",
                "source_uri": f"https://example.invalid/{case_id}",
                "module": "pwn",
                "metadata": {},
                "relations": [observation(case_id, left), observation(case_id, right)],
            }, collection="strata")

        self.index.upsert_case({
            "id": "case-reviewed",
            "title": "Reviewed technique relationship",
            "body": "## Technique\nA reviewer identified an alternative technique.\n",
            "source_type": "research_note",
            "source_uri": "https://example.invalid/case-reviewed",
            "module": "pwn",
            "metadata": {},
            "relations": [{
                "from": left,
                "type": "alternative_to",
                "to": right,
                "status": "verified",
                "evidence": {"section": "Technique", "line_start": 2, "line_end": 2},
                "conditions": ["reviewed in this case"],
            }],
        }, collection="strata")

        related = self.index.related("tcache poisoning", kind="technique", collection="strata")
        co_observed = [item for item in related["related"] if item["relation"] == "co_observed"]
        self.assertEqual(1, len(co_observed), related)
        self.assertEqual("FSOP variant", co_observed[0]["node"]["label"])
        self.assertEqual("observed_in_cases", co_observed[0]["status"])
        self.assertEqual("undirected", co_observed[0]["direction"])
        self.assertEqual(
            {"case-alpha", "case-beta"},
            {support["case_id"] for support in co_observed[0]["supports"]},
        )

        verified = [item for item in related["related"] if item["relation"] == "alternative_to"]
        self.assertEqual(1, len(verified), related)
        self.assertEqual("verified", verified[0]["status"])
        self.assertEqual("outgoing", verified[0]["direction"])
        self.assertEqual("case-reviewed", verified[0]["supports"][0]["case_id"])

    def test_redaction_survives_retrieval_and_context_rendering(self) -> None:
        case_id = "pwn-112233445566"
        secret = "DH{private_flag_987}"
        target = "https://internal.example.invalid:8443"
        report = (
            "# Real report\n\n## Root Cause\nAn out of bounds write reaches a heap object.\n\n"
            f"The captured flag was {secret}.\nTarget: {target}\n"
        )
        write_exploit(self.library, case_id, report, flags=[secret], target_url=target)
        self.index.sync_exploit_library(self.library)
        hits = self.index.search("out of bounds heap")
        self.assertTrue(hits)
        payload = json.dumps(hits, ensure_ascii=False)
        self.assertNotIn(secret, payload)
        self.assertNotIn(target, payload)
        self.assertIn(case_id, payload)

        context = render_context(hits, max_chars=1200)
        self.assertIn(case_id, context)
        self.assertNotIn(secret, context)
        self.assertNotIn(target, context)
        self.assertLessEqual(len(context), 1200)
        self.assertNotIn(secret, redact_text(report, flags=[secret], target_urls=[target]))

    def test_openai_compatible_adapter_accepts_the_same_evidence(self) -> None:
        from security_rag.chat import answer_with_context

        received: list[dict] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append({
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "payload": json.loads(body),
                })
                response = json.dumps({
                    "choices": [{"message": {"role": "assistant", "content": "Evidence supports the link."}}],
                    "model": "local-test",
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *_args: object) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        hits = [{
            "case_id": "case-1",
            "collection": "strata",
            "title": "A refcount race",
            "source_type": "research_note",
            "source_uri": "https://example.invalid/research/case-1",
            "module": "pwn",
            "section": "Root Cause",
            "line_start": 3,
            "line_end": 5,
            "excerpt": "A stale object creates an arbitrary read.",
            "score": 1.0,
            "metadata": {},
        }]
        result = answer_with_context(
            "Which primitive follows the refcount race?",
            hits,
            base_url=f"http://127.0.0.1:{server.server_port}/v1",
            model="local-test",
            api_key="unit-test-key",
        )
        self.assertEqual("Evidence supports the link.", result["answer"])
        self.assertEqual("local-test", result["model"])
        self.assertIn("case-1", json.dumps(result["evidence"]))
        self.assertEqual("/v1/chat/completions", received[0]["path"])
        self.assertEqual("Bearer unit-test-key", received[0]["authorization"])
        request_text = json.dumps(received[0]["payload"])
        self.assertIn("case-1", request_text)
        self.assertIn("Which primitive follows", request_text)

    def test_relation_status_and_sources_reach_context_and_model(self) -> None:
        from security_rag.chat import answer_with_context

        hits = [{
            "case_id": "case-alpha", "collection": "strata", "title": "Technique note",
            "source_type": "research_note", "source_uri": "https://example.invalid/case-alpha",
            "module": "pwn", "section": "Technique", "line_start": 3, "line_end": 5,
            "excerpt": "The case discusses a capability and a technique.",
            "score": 1.0, "metadata": {},
        }]
        links = {
            "query": "tcache poisoning",
            "related": [{
                "node": {"id": "technique:fsop-variant", "kind": "technique", "label": "FSOP variant"},
                "relation": "co_observed", "direction": "undirected",
                "status": "observed_in_cases", "conditions": [], "support_count": 2,
                "supports": [
                    {"case_id": "case-alpha", "collection": "strata",
                     "source_uri": "https://example.invalid/case-alpha", "section": "Technique",
                     "line_start": 3, "line_end": 5},
                    {"case_id": "case-beta", "collection": "strata",
                     "source_uri": "https://example.invalid/case-beta", "section": "Technique",
                     "line_start": 4, "line_end": 7},
                ],
            }, {
                "node": {"id": "technique:rop", "kind": "technique", "label": "ROP"},
                "relation": "alternative_to", "direction": "outgoing",
                "status": "verified", "conditions": ["reviewed for this case"],
                "support_count": 1,
                "supports": [{"case_id": "case-reviewed", "collection": "strata",
                              "source_uri": "https://example.invalid/case-reviewed",
                              "section": "Technique", "line_start": 2, "line_end": 2}],
            }],
        }
        context = render_context(hits, links=links, max_chars=3000)
        for value in ("observed_in_cases", "verified", "co_observed", "alternative_to",
                      "case-alpha", "case-beta", "case-reviewed", "L3-L5", "L2-L2"):
            self.assertIn(value, context)

        received: list[dict] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append(json.loads(body))
                response = json.dumps({
                    "choices": [{"message": {"role": "assistant", "content": "Cited relation answer."}}],
                    "model": "local-test",
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *_args: object) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        result = answer_with_context(
            "Which links are actually verified?", hits,
            base_url=f"http://127.0.0.1:{server.server_port}/v1",
            model="local-test", links=links,
        )
        self.assertEqual("Cited relation answer.", result["answer"])
        sent = json.dumps(received[0])
        for value in ("observed_in_cases", "verified", "case-alpha", "case-reviewed"):
            self.assertIn(value, sent)


if __name__ == "__main__":
    unittest.main()
