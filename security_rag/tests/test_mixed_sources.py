"""A collection may hold Exploit Library cases and JSONL digests side by side.

Each reconciler may delete only the cases of the source it owns: a library sync
must keep writeup digests, and a digest snapshot must keep library cases.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from security_rag import RagIndex  # noqa: E402


def write_exploit(root: Path, case_id: str, report: str) -> None:
    entry = root / case_id
    entry.mkdir(parents=True, exist_ok=True)
    meta = {"id": case_id, "module": "pwn", "technique_name": "tcache_poison", "bug_classes": ["uaf"]}
    (entry / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (entry / "report.md").write_text(report, encoding="utf-8")


def digest(case_id: str, text: str) -> dict:
    return {
        "id": case_id, "title": text, "body": f"## Technique\n{text}\n",
        "source_type": "writeup_digest", "source_uri": f"https://example.invalid/{case_id}",
        "module": "pwn", "metadata": {"bug_classes": ["bof"]}, "relations": [],
    }


class MixedSourceReconcileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="mixed-rag-test-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.library = root / "exploits"
        self.library.mkdir()
        self.jsonl = root / "digests.jsonl"
        self.index = RagIndex(root / "rag.sqlite")
        write_exploit(self.library, "pwn-aabbccddeeff", "## Technique\nTcache poisoning of a stale chunk.\n")
        self.index.sync_exploit_library(self.library, collection="ogamdo")

    def write_digests(self, *cases: dict) -> None:
        self.jsonl.write_text("".join(json.dumps(c) + "\n" for c in cases), encoding="utf-8")

    def test_library_sync_keeps_digests_in_the_same_collection(self) -> None:
        self.write_digests(digest("digest-a", "format string leak of a stack canary"))
        self.index.ingest_jsonl(self.jsonl, collection="ogamdo")
        counts = self.index.sync_exploit_library(self.library, collection="ogamdo")
        self.assertEqual(0, counts["deleted"])
        self.assertIn("digest-a", json.dumps(self.index.search("canary leak format string", collection="ogamdo")))

    def test_library_sync_still_removes_deleted_library_entries(self) -> None:
        self.write_digests(digest("digest-a", "format string leak of a stack canary"))
        self.index.ingest_jsonl(self.jsonl, collection="ogamdo")
        entry = self.library / "pwn-aabbccddeeff"
        for child in entry.iterdir():
            child.unlink()
        entry.rmdir()
        counts = self.index.sync_exploit_library(self.library, collection="ogamdo")
        self.assertEqual(1, counts["deleted"])
        self.assertFalse(self.index.has_case("pwn-aabbccddeeff", collection="ogamdo"))
        self.assertTrue(self.index.has_case("digest-a", collection="ogamdo"))

    def test_digest_snapshot_replaces_only_digests(self) -> None:
        self.write_digests(digest("digest-one", "first digest"), digest("digest-two", "second digest"))
        self.index.ingest_jsonl(self.jsonl, collection="ogamdo")
        self.write_digests(digest("digest-one", "first digest"))
        counts = self.index.ingest_jsonl(self.jsonl, collection="ogamdo", replace_missing=True)
        self.assertEqual(1, counts["deleted"])
        self.assertFalse(self.index.has_case("digest-two", collection="ogamdo"))
        self.assertTrue(self.index.has_case("pwn-aabbccddeeff", collection="ogamdo"))


if __name__ == "__main__":
    unittest.main()
