"""Regressions for the defects found reviewing the first Security RAG build.

Each test names the observed failure on the real 289-case index.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from security_rag import RagIndex, redact_text, render_context  # noqa: E402
from security_rag.backfill import backfill_entry, locate_quote, verify  # noqa: E402
from security_rag.ingest import chunk_markdown, load_exploit_case, report_digest  # noqa: E402
from security_rag.query import parse_query  # noqa: E402
from security_rag.vocab import PRIMITIVES, canonical, technique_nodes  # noqa: E402


class RedactionTests(unittest.TestCase):
    def test_bare_host_is_masked_when_target_has_a_port(self) -> None:
        # 24 indexed cases kept `nc <host> <port>` because only host:port was masked.
        for target in ("host3.example.games:12345", "http://host3.example.games:12345/"):
            out = redact_text("nc host3.example.games 12345", target_urls=[target])
            self.assertNotIn("host3.example.games", out)

    def test_flag_prefix_is_learned_from_the_case(self) -> None:
        out = redact_text(
            "real eventctf2024{kt88h_qpz_2h} decoy eventctf2024{h2t_vht_mzp6}",
            flags=["eventctf2024{kt88h_qpz_2h}"],
        )
        self.assertNotIn("h2t_vht_mzp6", out)
        self.assertEqual(out.count("[REDACTED_FLAG]"), 2)

    def test_code_about_flags_and_credentials_stays_readable(self) -> None:
        code = 'struct flag{ int a; }; printf("flag{%s}", buf); f"FLAG{i}_x"; password = request.form["pw"]'
        self.assertEqual(redact_text(code), code)

    def test_literal_credentials_and_truncated_flags_are_still_masked(self) -> None:
        out = redact_text('password = "hunter2hunter2"; api_key=abcd1234efgh; saw DH{abcdef0123456789')
        self.assertNotIn("hunter2hunter2", out)
        self.assertNotIn("abcd1234efgh", out)
        self.assertNotIn("abcdef0123456789", out)


class IndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="rag-review-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index = RagIndex(self.root / "rag.sqlite")

    def add(self, case_id: str, body: str, **extra: object) -> None:
        self.index.upsert_case({"id": case_id, "title": case_id, "body": body, **extra}, collection="t")

    def test_incoming_relation_is_rendered_in_its_own_direction(self) -> None:
        # Was rendered "tcache poisoning --enables--> use after free".
        self.add("c1", "# A\nstale pointer then tcache poisoning\n", relations=[{
            "from": {"kind": "primitive", "label": "use after free"}, "type": "enables",
            "to": {"kind": "technique", "label": "tcache poisoning"}, "status": "observed",
            "evidence": {"section": "A", "line_start": 1, "line_end": 2},
        }])
        links = self.index.related("tcache poisoning", collection="t")
        context = render_context(self.index.search("tcache", collection="t"), links=links)
        self.assertIn("use after free --enables--> tcache poisoning", context)
        self.assertNotIn("tcache poisoning --enables-->", context)

    def test_unrelated_question_returns_nothing(self) -> None:
        # One shared common word used to surface a UAF case for a Kubernetes question.
        self.add("c1", "# Vulnerability\nA stale pointer survives free; see the annotation in the chart.\n")
        self.assertEqual(self.index.search("kubernetes ingress annotation helm chart", collection="t"), [])
        hits = self.index.search("stale pointer", collection="t")
        self.assertEqual([h["case_id"] for h in hits], ["c1"])
        self.assertEqual(hits[0]["matched_terms"], ["stale", "pointer"])

    def test_inflected_and_abbreviated_queries_find_the_same_case(self) -> None:
        self.add("c1", "# Bug\nThe note buffer has a heap overflow.\n", metadata={"bug_classes": ["heap-overflow"]})
        self.add("c2", "# Bug\nFreed chunk is reused.\n", metadata={"bug_classes": ["uaf"]})
        self.assertEqual(self.index.search("heap overflows", collection="t")[0]["case_id"], "c1")
        self.assertEqual(self.index.search("use after free", collection="t")[0]["case_id"], "c2")
        # "uaf" must not degrade into the common words use / after / free.
        self.add("c3", "# Notes\nAfter login you are free to use the form.\n")
        self.assertEqual([h["case_id"] for h in self.index.search("uaf", collection="t")], ["c2"])

    def test_korean_query_matches_particles_and_english_metadata(self) -> None:
        # "힙 오버플로우" returned 0 hits against 335 Hangul chunks.
        self.add("c1", "# 분석\n이 취약점을 이용해 관리자 권한을 얻는다.\n")
        self.add("c2", "# Bug\nnote buffer\n", metadata={"bug_classes": ["heap-overflow"]})
        self.assertEqual(self.index.search("취약점", collection="t")[0]["case_id"], "c1")
        self.assertEqual(self.index.search("힙 오버플로우", collection="t")[0]["case_id"], "c2")

    def test_subsection_is_found_through_its_parent_heading(self) -> None:
        chunks = chunk_markdown("# Report\n## Exploit chain\n### Step 2\noverwrite the hook\n")
        self.assertEqual(chunks[-1]["heading_path"], "Report > Exploit chain > Step 2")
        self.add("c1", "# Report\n## Exploit chain\n### Step 2\noverwrite the hook\n")
        hit = self.index.search("exploit chain hook", collection="t")[0]
        self.assertEqual(hit["section"], "Step 2")

    def test_existing_index_is_migrated_in_place(self) -> None:
        self.add("c1", "# Bug\nheap overflow\n")
        with self.index._connection() as con:
            con.execute("DELETE FROM settings WHERE key='fts_layout'")
        reopened = RagIndex(self.root / "rag.sqlite")
        self.assertEqual(len(reopened.search("heap overflows", collection="t")), 1)


    def test_serving_index_cannot_write_and_refuses_a_stale_layout(self) -> None:
        self.add("c1", "# Bug\nheap overflow\n")
        reader = RagIndex(self.root / "rag.sqlite", read_only=True)
        self.assertEqual(len(reader.search("heap overflow", collection="t")), 1)
        with self.assertRaises(Exception):
            reader.upsert_case({"id": "c2", "title": "x", "body": "y"}, collection="t")
        with self.index._connection() as con:
            con.execute("UPDATE settings SET value='old' WHERE key='fts_layout'")
        with self.assertRaisesRegex(RuntimeError, "another version"):
            RagIndex(self.root / "rag.sqlite", read_only=True)


class GraphTests(unittest.TestCase):
    def test_technique_spellings_share_nodes(self) -> None:
        # One family spelled three ways (house_of_apple2, house_of_apple_2, inside a chain name) was three nodes.
        self.assertEqual(technique_nodes("house_of_apple_2"), ["house-of-apple2"])
        nodes = technique_nodes("tcache_poison into house_of_apple2 on an fsop target + heap grooming")
        for shared in ("house-of-apple2", "fsop", "tcache-poison", "heap-groom"):
            self.assertIn(shared, nodes)
        long_name = "pointer-free heap leak via groomed overlapping chunks with counterfeit size fields"
        self.assertTrue(all(len(n.split("-")) <= 5 for n in technique_nodes(long_name)))

    def test_primitive_labels_map_to_the_vocabulary(self) -> None:
        self.assertEqual(canonical("AAW", PRIMITIVES), "aaw")
        self.assertEqual(canonical("an arbitrary address write into libc", PRIMITIVES), "aaw")
        self.assertIsNone(canonical("the buffer was padded twice before the second request", PRIMITIVES))

    def write_entry(self, root: Path, report: str, **meta: object) -> Path:
        entry = root / "exploits" / "pwn-0123456789ab"
        entry.mkdir(parents=True)
        (entry / "meta.json").write_text(json.dumps({
            "id": entry.name, "module": "pwn", "bug_classes": ["uaf"],
            "technique_name": "tcache_poison then fsop", **meta,
        }), encoding="utf-8")
        (entry / "report.md").write_text(report, encoding="utf-8")
        return entry

    def test_backfill_keeps_only_quoted_vocabulary_labels(self) -> None:
        report = "# R\n## Primitive\nThe stale chunk gives an **arbitrary write** into `__free_hook`.\n\n## Result\nWe pop a shell.\n"
        answer = {"primitives": [
            {"label": "aaw", "from_bug": "uaf", "quote": "gives an arbitrary write into __free_hook"},
            {"label": "aar", "from_bug": "uaf", "quote": "this sentence is not in the report at all"},
            {"label": "teleportation", "quote": "The stale chunk gives an arbitrary write"},
        ], "outcomes": [{"label": "code-execution", "quote": "We pop a shell."}]}
        result = verify(answer, report, ["uaf"])
        self.assertEqual([p["label"] for p in result["primitives"]], ["aaw"])
        self.assertEqual(result["primitives"][0]["line_start"], 3)
        self.assertEqual(result["rejected"], 2)
        self.assertEqual(locate_quote(report, "We pop a shell."), (6, 6))

    def test_backfilled_links_enter_the_graph_as_candidates(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rag-backfill-") as tmp:
            report = "# R\n## Primitive\nThe stale chunk gives an arbitrary write into the hook.\n\n## Result\nWe pop a shell on the box.\n"
            entry = self.write_entry(Path(tmp), report)
            reply = json.dumps({
                "primitives": [{"label": "aaw", "from_bug": "uaf", "quote": "gives an arbitrary write into the hook"}],
                "outcomes": [{"label": "code-execution", "quote": "We pop a shell on the box."}],
            })
            self.assertEqual(backfill_entry(entry, ask=lambda _p: "```json\n" + reply + "\n```", model="m"), "done")
            self.assertEqual(backfill_entry(entry, ask=lambda _p: self.fail("asked twice"), model="m"), "current")
            # Beside the library, not inside the entry a container owns.
            self.assertEqual(sorted(p.name for p in entry.iterdir()), ["meta.json", "report.md"])
            saved = json.loads((Path(tmp) / "security-rag-extracted" / f"{entry.name}.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["report_sha256"], report_digest(report))
            self.assertNotIn("quote", json.dumps(saved))

            index = RagIndex(Path(tmp) / "rag.sqlite")
            index.upsert_case(load_exploit_case(entry), collection="t")
            links = index.related("aaw", collection="t")["related"]
            got = {(r["node"]["id"], r["relation"], r["direction"], r["status"]) for r in links}
            self.assertIn(("root_cause:uaf", "produces", "incoming", "candidate"), got)
            self.assertIn(("technique:tcache-poison", "enables", "outgoing", "candidate"), got)
            reached = index.related("code-execution", kind="technique", collection="t")["related"]
            self.assertIn("leads_to", {r["relation"] for r in reached})

            # An overwritten report invalidates the extraction until it is redone.
            (entry / "report.md").write_text(report + "\nedited\n", encoding="utf-8")
            case = load_exploit_case(entry)
            self.assertNotIn("primitives", case["metadata"])

    def test_generic_neighbors_do_not_outrank_specific_ones(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rag-rank-") as tmp:
            index = RagIndex(Path(tmp) / "rag.sqlite")

            def case(case_id: str, *labels: tuple[str, str]) -> None:
                index.upsert_case({"id": case_id, "title": case_id, "body": "# x\ny\n", "relations": [
                    {"from": {"kind": kind, "label": label}, "type": "observed_in_case",
                     "to": {"kind": "case", "label": case_id}, "status": "observed"}
                    for kind, label in labels
                ]}, collection="t")

            for i in range(12):
                case(f"g{i}", ("root_cause", "logic"))
            case("a", ("root_cause", "uaf"), ("root_cause", "logic"), ("technique", "tcache-poison"))
            case("b", ("root_cause", "uaf"), ("root_cause", "logic"), ("technique", "tcache-poison"))
            ranked = [r["node"]["id"] for r in index.related("uaf", collection="t")["related"]]
            self.assertLess(ranked.index("technique:tcache-poison"), ranked.index("root_cause:logic"))


class QueryTests(unittest.TestCase):
    def test_phrase_aliases_are_one_concept(self) -> None:
        self.assertEqual([u.name for u in parse_query("use after free tcache")], ["use after free", "tcache"])
        self.assertEqual([u.name for u in parse_query("힙 UAF")], ["힙", "uaf"])
        self.assertEqual(parse_query("the of and"), [])


if __name__ == "__main__":
    unittest.main()


def test_node_lookup_reads_names_through_the_vocabulary():
    import sqlite3

    from security_rag.index import _seed_nodes

    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.execute("CREATE TABLE nodes (node_id TEXT, kind TEXT, label TEXT, normalized_label TEXT)")
    for kind, label in (("technique", "tcache-poison"), ("primitive", "info-leak"), ("root_cause", "heap-overflow")):
        con.execute("INSERT INTO nodes VALUES (?,?,?,?)", (f"{kind}:{label}", kind, label, label))
    assert _seed_nodes(con, "tcache poisoning") == ["technique:tcache-poison"]
    assert _seed_nodes(con, "libc leak") == ["primitive:info-leak"]
    assert _seed_nodes(con, "heap overflow") == ["root_cause:heap-overflow"]
    assert _seed_nodes(con, "kubernetes") == []
