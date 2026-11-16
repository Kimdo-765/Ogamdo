"""Passage choice, method cards, coverage and negation in search.

The fixtures are invented; they only have the shape of a writeup digest
(Summary, Technique, Preconditions, Constraint, Pitfalls, Keywords, Source).
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from security_rag import RagIndex, render_context  # noqa: E402
from security_rag.index import _passage_priority  # noqa: E402
from security_rag.query import analyze_query, parse_query, required_units  # noqa: E402

EXIT_TITLE = "Stale note pointer -> tcache poison -> exit handler slot overwrite"
EXIT_BODY = f"""# {EXIT_TITLE}
(오래된 포인터로 exit handler 덮어쓰기)

## Summary
A made-up note service frees an entry and keeps its pointer.

## Technique
1. Free the note twice through the stale pointer.
2. Point the freed entry at the exit handler slot and write the target there.

## Preconditions
- The stale pointer stays readable after free.

## Constraint
- glibc 2.39: no malloc hooks, safe-linking on.

## Pitfalls
- The forged size field must match the bin it is taken from.

## Keywords
uaf tcache exit handler arbitrary write stale pointer

## Source
- invented fixture
"""
EXIT_META = {
    "technique_name": "tcache-poison + exit-handler-overwrite",
    "primitives": ["uaf", "aaw"],
    "blockers": ["no malloc hooks", "safe-linking"],
    "mitigations": ["safe-linking", "no malloc hooks", "full relro"],
}

HOOK_TITLE = "Arbitrary write -> free hook overwrite -> system"
HOOK_BODY = f"""# {HOOK_TITLE}

## Summary
An invented service gives one arbitrary write after a libc leak.

## Technique
1. Use the arbitrary write on the free hook.
2. Free a chunk that holds the shell command.

## Preconditions
- An old glibc that still calls the free hook.

## Keywords
arbitrary write free hook libc leak

## Source
- invented fixture
"""
HOOK_META = {"technique_name": "hook-overwrite", "primitives": ["info-leak", "aaw", "control-flow-hijack"]}


class PassageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="rag-passages-")
        self.addCleanup(self.temp.cleanup)
        self.index = RagIndex(Path(self.temp.name) / "rag.sqlite")
        self.digest("exit", EXIT_TITLE, EXIT_BODY, EXIT_META)
        self.digest("hook", HOOK_TITLE, HOOK_BODY, HOOK_META)

    def digest(self, case_id: str, title: str, body: str, meta: dict) -> None:
        self.index.upsert_case(
            {"id": case_id, "title": title, "body": body, "source_type": "writeup_digest", "metadata": meta},
            collection="t",
        )

    def test_shown_section_says_how_not_where_it_came_from(self) -> None:
        # Labels sit on every chunk, so the case's ranking row was its
        # shortest one (the Source line); the passage is chosen again.
        hit = self.index.search("uaf exit handler", collection="t")[0]
        self.assertEqual(hit["case_id"], "exit")
        self.assertEqual(hit["section"], "Technique")
        self.assertIn("exit handler slot", hit["excerpt"])

    def test_excerpt_terms_are_what_the_passage_itself_says(self) -> None:
        hit = self.index.search("uaf exit handler", collection="t")[0]
        self.assertEqual(hit["excerpt_terms"], ["exit", "handler"])
        self.assertIn("uaf", hit["case_terms"])
        self.assertEqual(hit["matched_terms"], ["uaf", "exit", "handler"])

    def test_method_card_cites_each_method_section(self) -> None:
        hit = self.index.search("uaf exit handler", collection="t")[0]
        card = hit["method_card"]
        self.assertEqual([s["section"] for s in card["sections"]],
                         ["Technique", "Preconditions", "Constraint", "Pitfalls"])
        for section in card["sections"]:
            self.assertFalse(section["text"].startswith("#"))
            self.assertLessEqual(section["line_start"], section["line_end"])
        self.assertIn("no malloc hooks", card["sections"][2]["text"])

    def test_a_section_split_across_chunks_is_one_card_section(self) -> None:
        steps = "\n".join(f"{n}. Step {n} of the invented chain moves the fake chunk once more." for n in range(1, 40))
        body = f"# Long chain\n\n## Technique\n{steps}\n\n## Pitfalls\n- The last step needs alignment.\n"
        self.digest("long", "Long chain", body, {"technique_name": "long-chain"})
        hit = self.index.search("invented chain fake chunk", collection="t")[0]
        technique = hit["method_card"]["sections"][0]
        self.assertEqual(technique["section"], "Technique")
        self.assertEqual((technique["line_start"], technique["line_end"]), (3, 43))
        self.assertIn("Step 39", technique["text"])
        self.assertFalse(technique["truncated"])

    def test_only_the_first_digests_get_a_card(self) -> None:
        self.index.upsert_case({"id": "lib", "title": "lib", "body": "# Report\n## Exploit chain\narbitrary write then free hook\n"},
                               collection="t")
        hits = self.index.search("arbitrary write free hook", collection="t", cards=1)
        cards = [h for h in hits if h["method_card"]]
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["source_type"], "writeup_digest")
        self.assertIsNone(next(h for h in hits if h["case_id"] == "lib")["method_card"])

    def test_a_concept_the_index_never_saw_is_named(self) -> None:
        hit = self.index.search("uaf exit zzqvxlocator", collection="t")[0]
        self.assertEqual(hit["coverage"]["absent_from_corpus"], ["zzqvxlocator"])
        self.assertEqual(hit["coverage"]["missing"], ["zzqvxlocator"])
        self.assertEqual((hit["coverage"]["terms"], hit["coverage"]["case"]), (3, 2))

    def test_case_that_needs_the_lacked_concept_drops(self) -> None:
        hits = self.index.search("hooks removed, have arbitrary write", collection="t")
        self.assertEqual([h["case_id"] for h in hits], ["exit", "hook"])
        self.assertEqual(hits[0]["constraint_terms"], ["hooks"])
        self.assertEqual(hits[1]["conflict_terms"], ["hooks"])
        self.assertEqual(hits[0]["coverage"]["negated"], ["hooks"])

    def test_a_primitive_the_case_built_is_not_a_conflict(self) -> None:
        # "no libc leak": a case that builds its own leak is still an answer.
        hit = next(h for h in self.index.search("arbitrary write free hook no libc leak", collection="t")
                   if h["case_id"] == "hook")
        self.assertEqual(hit["conflict_terms"], [])

    def test_context_adds_the_card_and_still_shows_later_cases(self) -> None:
        hits = self.index.search("arbitrary write", collection="t")
        context = render_context(hits, max_chars=2400)
        self.assertLessEqual(len(context), 2400)
        self.assertIn("[Preconditions L", context)
        for hit in hits:
            self.assertIn(f"[{hit['case_id']} | ", context)

    def test_a_query_of_only_lacks_still_searches(self) -> None:
        hits = self.index.search("hooks removed", collection="t")
        self.assertEqual([h["case_id"] for h in hits], ["exit", "hook"])
        self.assertEqual(hits[0]["constraint_terms"], ["hooks"])
        self.assertEqual(hits[1]["conflict_terms"], ["hooks"])

    def test_a_lacked_capability_never_lowers_a_case(self) -> None:
        self.digest("leaky", "Unsorted bin leak -> tcache poison", "# Unsorted bin leak -> tcache poison\n\n"
                    "## Technique\nLeak libc from the unsorted bin, then poison tcache.\n",
                    {"technique_name": "unsorted-bin-leak + tcache-poison"})
        hit = next(h for h in self.index.search("tcache poison without libc leak", collection="t")
                   if h["case_id"] == "leaky")
        self.assertEqual(hit["conflict_terms"], [])

    def test_a_shared_lack_needs_the_same_modifier(self) -> None:
        self.digest("noleak", "Tcache poison with no libc leak", "# Tcache poison with no libc leak\n\n"
                    "## Technique\nPartial overwrite instead of a tcache leak.\n",
                    {"technique_name": "tcache-poison", "blockers": ["no libc leak"]})
        def shared(query: str) -> list[str]:
            return next(h for h in self.index.search(query, collection="t") if h["case_id"] == "noleak")["constraint_terms"]
        self.assertEqual(shared("tcache poison without libc leak"), ["libc leak"])
        self.assertEqual(shared("tcache poison without heap leak"), [])

    def test_an_unrecorded_mitigation_is_not_a_lack(self) -> None:
        self.index.upsert_case({"id": "lib", "title": "lib", "body": "# Report\n## Exploit chain\nstack overflow to ret2win\n",
                                "metadata": {"technique_name": "ret2win", "mitigations": {"relro": None, "canary": False}}},
                               collection="t")
        def shared(query: str) -> list[str]:
            return next(h for h in self.index.search(query, collection="t") if h["case_id"] == "lib")["constraint_terms"]
        self.assertEqual(shared("stack overflow, no relro"), [])
        self.assertEqual(shared("stack overflow, no canary"), ["canary"])

    def test_a_lacked_protection_never_lowers_a_case(self) -> None:
        self.index.upsert_case({"id": "nx", "title": "nx", "body": "# Report\n## Exploit chain\nstack overflow then rop\n",
                                "metadata": {"technique_name": "rop", "mitigations": {"nx": True, "canary": False}}},
                               collection="t")
        hit = next(h for h in self.index.search("NX disabled, stack overflow to shellcode", collection="t")
                   if h["case_id"] == "nx")
        self.assertEqual(hit["conflict_terms"], [])

    def test_a_recorded_lack_wins_over_a_conflict(self) -> None:
        self.digest("both", "Hook overwrite without malloc hooks", "# Hook overwrite without malloc hooks\n\n"
                    "## Technique\nArbitrary write onto a function pointer table.\n",
                    {"technique_name": "hook-overwrite", "blockers": ["no malloc hooks"]})
        hit = next(h for h in self.index.search("hooks removed, have arbitrary write", collection="t") if h["case_id"] == "both")
        self.assertEqual((hit["conflict_terms"], hit["constraint_terms"]), ([], ["hooks"]))

    def test_a_shared_lack_compares_heads(self) -> None:
        # "no malloc/free hooks" lacks hooks, not free().
        self.digest("nofree", "Heap with only malloc", "# Heap with only malloc\n\n## Technique\nHeap overflow into the top chunk.\n",
                    {"technique_name": "top-chunk", "blockers": ["no malloc/free hooks"]})
        hit = next(h for h in self.index.search("heap overflow top chunk without free", collection="t")
                   if h["case_id"] == "nofree")
        self.assertEqual(hit["constraint_terms"], [])

    def test_no_pie_is_not_no_pie_leak(self) -> None:
        self.index.upsert_case({"id": "nopie", "title": "nopie", "body": "# Report\n## Exploit chain\nbuffer overflow ret2win\n",
                                "metadata": {"technique_name": "ret2win", "mitigations": {"pie": False}}}, collection="t")
        hit = next(h for h in self.index.search("PIE enabled but no PIE leak, buffer overflow", collection="t")
                   if h["case_id"] == "nopie")
        self.assertEqual(hit["constraint_terms"], [])

    def test_a_blocked_thing_lets_a_filter_bypass_case_through(self) -> None:
        self.index.upsert_case({"id": "waf", "title": "waf", "body": "# Report\n## Exploit chain\nsql injection with a filter bypass\n"},
                               collection="t")
        self.assertIn("waf", [h["case_id"] for h in self.index.search("sql injection with quotes filtered", collection="t")])

    def test_only_a_hook_can_conflict(self) -> None:
        self.digest("dup", "Fastbin dup into a fake chunk", "# Fastbin dup into a fake chunk\n\n## Technique\nDouble free a fastbin chunk.\n",
                    {"technique_name": "fastbin-dup"})
        hit = next(h for h in self.index.search("fastbin dup no longer works, double free fake chunk", collection="t")
                   if h["case_id"] == "dup")
        self.assertEqual(hit["conflict_terms"], [])

    def test_card_skips_the_part_the_excerpt_shows(self) -> None:
        self.index.upsert_case({"id": "xxe", "title": "xxe", "body": "# Report\n## Exploit chain\nxxe when external entities are off: "
                                "use a local dtd to reach them anyway\n"}, collection="t")
        hits = self.index.search("XXE but external entities are disabled in the parser", collection="t")
        self.assertEqual([h["case_id"] for h in hits], ["xxe"])

    def test_no_boost_for_a_case_without_the_protection_the_asker_has(self) -> None:
        self.index.upsert_case({"id": "nopie2", "title": "nopie2", "body": "# Report\n## Exploit chain\nbuffer overflow ret2win\n",
                                "metadata": {"technique_name": "ret2win", "mitigations": {"pie": False}, "blockers": ["no leak"]}},
                               collection="t")
        hit = next(h for h in self.index.search("PIE enabled but no PIE leak, buffer overflow", collection="t")
                   if h["case_id"] == "nopie2")
        self.assertEqual(hit["constraint_terms"], [])

    def test_environment_words_alone_do_not_make_a_passage_relevant(self) -> None:
        self.index.upsert_case({"id": "ver", "title": "ver", "body": "# Report\n## Notes\nglibc 2.34 is the version in the docker image\n"},
                               collection="t")
        hits = self.index.search("hooks removed in glibc 2.34, have arbitrary write", collection="t")
        self.assertNotIn("ver", [h["case_id"] for h in hits])

    def test_hostile_queries_never_raise(self) -> None:
        for query in ("check house of ,,, * leak", "house of , no 제거됨 ^", "neither " + "a" * 300, '"', "{ } : ^ *",
                      ",", "", "\x00", "no", "없음", "house of"):
            self.index.search(query, collection="t")

    def test_without_fts_the_same_fields_come_back(self) -> None:
        fts = self.index.search("uaf exit handler", collection="t")[0]
        self.index.fts_enabled = False
        plain = self.index.search("uaf exit handler", collection="t")[0]
        self.assertEqual(set(plain), set(fts))
        self.assertEqual(plain["section"], fts["section"])
        self.assertEqual(plain["excerpt_terms"], fts["excerpt_terms"])


class CardTests(unittest.TestCase):
    def test_the_technique_gets_most_of_the_card_and_ends_on_a_line(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rag-card-") as temp:
            index = RagIndex(Path(temp) / "rag.sqlite")
            steps = "\n".join(f"{n}. Invented step {n} moves the fake chunk somewhere new." for n in range(1, 70))
            notes = "\n".join(f"- Invented note {n} about alignment." for n in range(1, 60))
            body = (f"# Long card\n\n## Technique\n{steps}\n\n## Preconditions\n{notes}\n\n"
                    f"## Constraint\n{notes}\n\n## Pitfalls\n{notes}\n")
            index.upsert_case({"id": "c", "title": "Long card", "body": body, "source_type": "writeup_digest",
                               "metadata": {"technique_name": "fake-chunk"}}, collection="t")
            card = index.search("fake chunk invented step", collection="t")[0]["method_card"]
            sizes = {s["section"]: len(s["text"]) for s in card["sections"]}
            self.assertEqual(max(sizes, key=sizes.get), "Technique")
            self.assertLessEqual(card["chars"], 2800)
            technique = card["sections"][0]["text"]
            self.assertTrue(technique.endswith("new.…"), technique[-40:])


class SectionTests(unittest.TestCase):
    def test_scaffold_and_flag_name_headings(self) -> None:
        self.assertIsNone(_passage_priority("Why the helper scaffold is skipped here", "t"))
        self.assertIsNotNone(_passage_priority("Exploit chain built on a scaffold", "t"))
        self.assertIsNone(_passage_priority("Hint (the flag name is placeholder)", "t"))
        for heading in ("How the checker compares the flag", "Flag check routine", "Where the flag is compared"):
            self.assertIsNotNone(_passage_priority(heading, "t"), heading)

    def test_the_document_heading_is_not_a_parent(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rag-h1-") as temp:
            index = RagIndex(Path(temp) / "rag.sqlite")
            body = ("# Strategy report for the invented heap\n## Notes\nThe invented heap overflow reaches the next chunk size.\n"
                    "## Primitive\nThe invented heap overflow reaches the next chunk size field.\n")
            index.upsert_case({"id": "case-1", "title": "case-1", "body": body}, collection="t")
            self.assertEqual(index.search("invented heap overflow next chunk size", collection="t")[0]["section"], "Primitive")

    def test_library_headings_that_describe_a_method_rank_high(self) -> None:
        for heading in ("Strategy", "Phase 3 — invented step", "4.1 invented bug → file read",
                        "Exploit flow (script)", "2. invented filter bypass"):
            self.assertEqual(_passage_priority(heading, "t"), 0.95, heading)
        self.assertEqual(_passage_priority("3. Target shape", "t"), 0.4)
        self.assertEqual(_passage_priority("Root cause of an earlier failed attempt", "t"), 0.3)

    def test_a_subsection_takes_its_parents_priority_and_a_stub_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rag-sub-") as temp:
            index = RagIndex(Path(temp) / "rag.sqlite")
            step = "Overwrite the saved return address with the invented gadget chain. " * 4
            body = (f"# Report\n## Summary\nThe invented gadget chain overwrites the return address.\n"
                    f"## Exploit chain\n### Step 1\n{step}\n")
            index.upsert_case({"id": "r", "title": "Report", "body": body}, collection="t")
            self.assertEqual(index.search("invented gadget chain return address", collection="t")[0]["section"], "Step 1")

    def test_only_a_bare_flag_heading_is_skipped(self) -> None:
        for heading in ("Flag", "FLAG", "Flags", "Flag: `[REDACTED_FLAG]`", "`[REDACTED_FLAG]`", "7 — Flag",
                        "Result — flag captured", "✅ Flag captured", "Flag candidate"):
            self.assertIsNone(_passage_priority(heading, "t"), heading)
        for heading in ("Flag checker internals", "Decoding the flag from a document",
                        "Turning the write into a flag read", "Flag recovery", "flag 복원"):
            self.assertIsNotNone(_passage_priority(heading, "t"), heading)


class ContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="rag-context-")
        self.addCleanup(self.temp.cleanup)
        self.index = RagIndex(Path(self.temp.name) / "rag.sqlite")
        for n in range(6):
            steps = "\n".join(f"{k}. Invented step {k} for case {n} writes the target." for k in range(1, 12))
            body = (f"# Case {n} arbitrary write\n\n## Technique\n{steps}\n\n## Preconditions\n- Needs a write.\n\n"
                    f"## Constraint\n- None recorded.\n\n## Pitfalls\n- Alignment matters for case {n}.\n")
            self.index.upsert_case({"id": f"c{n}", "title": f"Case {n} arbitrary write", "body": body,
                                    "source_type": "writeup_digest", "metadata": {"technique_name": "aaw"}},
                                   collection="t")

    def test_cards_never_push_a_case_out(self) -> None:
        hits = self.index.search("arbitrary write target", collection="t", limit=6, cards=6)
        plain = [dict(h, method_card=None) for h in hits]
        for budget in (200, 400, 900, 1500, 3000, 6000):
            with_cards, without = render_context(hits, max_chars=budget), render_context(plain, max_chars=budget)
            self.assertLessEqual(len(with_cards), budget)
            shown = [h["case_id"] for h in hits if f"[{h['case_id']} | " in without]
            self.assertEqual([h["case_id"] for h in hits if f"[{h['case_id']} | " in with_cards], shown, budget)

    def test_a_card_continues_after_an_excerpt_that_is_its_first_chunk(self) -> None:
        hit = {"case_id": "x", "section": "Technique", "line_start": 10, "line_end": 20,
               "excerpt": "## Technique\nstep one and step two",
               "method_card": {"sections": [{"section": "Technique", "line_start": 10, "line_end": 30,
                                             "text": "step one and step two\nstep three"}]}}
        context = render_context([hit], max_chars=1000)
        self.assertIn("[Technique cont. L10-L30] step three", context)
        self.assertEqual(context.count("step one"), 1)

    def test_card_budget_goes_only_to_hits_with_a_card(self) -> None:
        card = {"sections": [{"section": "Pitfalls", "line_start": 1, "line_end": 9, "text": "pitfall text " * 200}]}
        hits = [{"case_id": "a", "section": "Technique", "line_start": 1, "line_end": 2, "excerpt": "short", "method_card": card},
                {"case_id": "b", "section": "Technique", "line_start": 1, "line_end": 2, "excerpt": "short"},
                {"case_id": "c", "section": "Technique", "line_start": 1, "line_end": 2, "excerpt": "short"}]
        context = render_context(hits, max_chars=3000)
        self.assertGreater(len(context), 2800)
        self.assertLessEqual(len(context), 3000)

    def test_an_excerpt_from_the_tail_of_a_section_still_gets_its_start(self) -> None:
        hit = {"case_id": "x", "section": "Technique", "line_start": 20, "line_end": 30, "excerpt": "tail of the steps",
               "method_card": {"sections": [{"section": "Technique", "line_start": 10, "line_end": 30,
                                             "text": "step one through step ten"}]}}
        self.assertIn("[Technique L10-L30] step one", render_context([hit], max_chars=1000))
        hit["line_start"] = 10
        self.assertNotIn("[Technique L10-L30]", render_context([hit], max_chars=1000))


class QueryReadingTests(unittest.TestCase):
    def names(self, query: str) -> tuple[list[str], list[tuple[str, ...]]]:
        plan = analyze_query(query)
        return [u.name for u in plan.units], [tuple(u.name for u in span) for span in plan.negated]

    def test_lacked_concepts_leave_the_required_set(self) -> None:
        self.assertEqual(self.names("hooks removed, have arbitrary write"), (["arbitrary write"], [("hooks",)]))
        self.assertEqual(self.names("no canary no PIE stack overflow"),
                         (["stack", "overflow"], [("canary",), ("pie",)]))
        self.assertEqual(self.names("tcache poisoning without heap leak"),
                         (["tcache", "poisoning"], [("heap", "leak")]))

    def test_a_head_noun_takes_every_modifier_before_it(self) -> None:
        units, negated = self.names("free hook and malloc hook removed")
        self.assertEqual(units, [])
        self.assertEqual(sorted(negated), [("free", "hook"), ("malloc", "hook")])

    def test_a_concept_also_asked_for_stays_required(self) -> None:
        units, negated = self.names("libc leak but no heap leak")
        self.assertEqual(units, ["libc", "leak"])
        self.assertEqual(negated, [("heap", "leak")])

    def test_korean_negation_also_when_written_onto_the_noun(self) -> None:
        self.assertEqual(self.names("릭 없이 rop"), (["rop"], [("릭",)]))
        self.assertEqual(self.names("릭없이 rop"), (["rop"], [("릭",)]))

    def test_what_a_filter_blocks_is_still_searched(self) -> None:
        self.assertEqual(self.names("seccomp로 execve 막힘"), (["seccomp", "execve"], []))
        self.assertEqual(self.names("underscore blocked ssti"), (["underscore", "ssti"], []))

    def test_korean_request_words_and_verb_forms_are_not_concepts(self) -> None:
        self.assertEqual(self.names("스택 버퍼 오버플로우인데 카나리 때문에 리턴 주소를 못 덮어요")[0],
                         ["스택", "버퍼 오버플로우", "카나리", "리턴 주소"])
        self.assertEqual(self.names("seccomp blocks execve so I cant pop a shell")[0],
                         ["seccomp", "execve", "pop", "shell"])

    def test_english_request_words_are_not_concepts(self) -> None:
        self.assertEqual([u.name for u in parse_query("I only have arbitrary read, how do I find the stack address")],
                         ["arbitrary read", "stack", "address"])

    def test_negation_stops_at_a_statement_boundary(self) -> None:
        self.assertEqual(self.names("have libc leak but heap leak missing"), (["libc", "leak"], [("heap", "leak")]))
        self.assertEqual(self.names("need stack pivot but gadgets are missing"), (["stack", "pivot"], [("gadgets",)]))
        self.assertEqual(self.names("libc 릭은 있고 힙 릭은 없음"), (["libc", "릭"], [("힙", "릭")]))
        self.assertEqual(self.names("스택 피벗 해야 하는데 가젯이 없어요"), (["스택 피벗"], [("가젯",)]))

    def test_a_leading_negation_covers_the_noun_run(self) -> None:
        self.assertEqual(self.names("no stack canary, buffer overflow"), (["buffer overflow"], [("stack", "canary")]))
        self.assertEqual(self.names("no libc base leak"), ([], [("libc", "base", "leak")]))
        self.assertEqual(self.names("no free or malloc hooks"), ([], [("free", "malloc", "hooks")]))
        self.assertEqual(self.names("no canary no PIE stack overflow"),
                         (["stack", "overflow"], [("canary",), ("pie",)]))

    def test_verb_negations_are_read(self) -> None:
        self.assertEqual(self.names("I don't have a libc leak"), ([], [("libc", "leak")]))
        self.assertEqual(self.names("PIE is not enabled"), ([], [("pie",)]))
        self.assertEqual(self.names("PIE가 꺼져 있어요"), ([], [("pie",)]))
        self.assertEqual(self.names("원가젯이 안 돼요"), (["원가젯"], []))

    def test_pwn_words_stay_concepts(self) -> None:
        self.assertEqual(self.names("GOT overwrite")[0], ["got", "overwrite"])
        self.assertEqual(self.names("write what where")[0], ["write", "where"])
        self.assertEqual(self.names("heap off by one"), (["heap", "off by one"], []))

    def test_a_korean_term_is_one_concept_whatever_its_particle(self) -> None:
        self.assertEqual(self.names("힙 오버플로우, 힙 릭은 있는데 libc 릭이 없어"),
                         (["힙 오버플로우", "힙", "릭"], [("libc", "릭")]))

    def test_cant_leak_lacks_the_leak(self) -> None:
        self.assertEqual(self.names("I can't leak anything"), ([], [("leak",)]))
        self.assertEqual(self.names("cannot leak the canary"), ([], [("canary", "leak")]))
        self.assertEqual(self.names("can't leak libc, ret2dlresolve"), (["ret2dlresolve"], [("libc", "leak")]))

    def test_a_protection_before_a_capability_is_its_modifier(self) -> None:
        self.assertEqual(self.names("no PIE leak"), ([], [("pie", "leak")]))
        self.assertEqual(self.names("without canary leak"), ([], [("canary", "leak")]))

    def test_blocked_meanings_keep_the_concept(self) -> None:
        for query, concept in (("execve is not allowed by seccomp, read flag file with rop", "execve"),
                               ("execve disabled by seccomp, orw shellcode", "execve"),
                               ("command injection without spaces", "spaces"),
                               ("command injection with no spaces allowed", "spaces")):
            plan = analyze_query(query)
            self.assertIn(concept, [u.name for u in plan.units], query)
            self.assertEqual(plan.negated, (), query)
            self.assertEqual([u.name for u in plan.optional], ["filter"], query)

    def test_a_list_before_a_trailing_negation_is_all_lacked(self) -> None:
        units, negated = self.names("canary, PIE and NX are all disabled, how to exploit overflow")
        self.assertEqual((units, sorted(negated)), (["exploit", "overflow"], [("canary",), ("nx",), ("pie",)]))
        units, negated = self.names("__malloc_hook, __free_hook removed in 2.34, have libc leak and arbitrary write")
        self.assertEqual(sorted(negated), [("free", "hook"), ("malloc", "hook")])
        self.assertNotIn("malloc", units)

    def test_more_english_negations(self) -> None:
        self.assertEqual(self.names("binary is not PIE and has partial RELRO, format string")[1], [("pie",)])
        self.assertEqual(self.names("neither canary nor PIE, stack overflow"), (["stack", "overflow"], [("canary",), ("pie",)]))
        self.assertEqual(self.names("lack of libc leak, have stack overflow"), (["stack", "overflow"], [("libc", "leak")]))
        self.assertEqual(self.names("w/o heap leak, tcache poisoning"), (["tcache", "poisoning"], [("heap", "leak")]))
        self.assertEqual(self.names("malloc hook no longer exists, have aaw"), (["aaw"], [("malloc", "hook")]))
        self.assertNotIn("wo", self.names("one_gadget won't work")[0])
        self.assertNotIn("ca", self.names("can't overwrite GOT because of full RELRO")[0])

    def test_multiword_techniques_are_one_concept(self) -> None:
        self.assertIn("double free", self.names("no double free because of tcache key check, have uaf")[0])
        self.assertEqual(self.names("tcache poisoning without safe linking")[1], [("safe linking",)])
        self.assertEqual(self.names("house of apple 2")[0], ["house of apple2"])
        self.assertEqual(self.names("house of orange unsorted bin")[0], ["house of orange", "unsorted", "bin"])

    def test_korean_lists_and_quantifiers(self) -> None:
        for query in ("카나리 PIE 둘 다 없음", "카나리랑 PIE 없음", "카나리도 PIE도 없음", "PIE와 카나리 없음",
                      "카나리나 PIE 없음", "카나리 및 PIE 없음"):
            units, negated = self.names(query)
            self.assertEqual((units, sorted(negated)), ([], [("pie",), ("카나리",)]), query)

    def test_korean_note_style_statements(self) -> None:
        self.assertEqual(self.names("libc 릭 있음 힙 릭 없음"), (["libc", "릭"], [("힙", "릭")]))
        self.assertEqual(self.names("카나리 켜짐 PIE 꺼짐"), (["카나리"], [("pie",)]))
        self.assertEqual(self.names("스택 릭 됐고 libc 릭 없음"), (["스택", "릭"], [("libc", "릭")]))

    def test_korean_negation_by_stem_and_attached(self) -> None:
        for query, lacked in (("원샷 가젯 없었음", ("원샷 가젯",)), ("RELRO 제거되었어요", ("relro",)),
                              ("가젯없어서 막힘", ("가젯",)), ("훅제거됨", ("훅",)), ("카나리꺼져서", ("카나리",))):
            self.assertEqual(self.names(query)[1], [lacked], query)
        self.assertEqual(self.names("execve 차단되어"), (["execve"], []))

    def test_korean_cannot_use(self) -> None:
        self.assertEqual(self.names("free hook을 쓸 수 없어요 임의 쓰기는 있음"), (["임의 쓰기"], [("free", "hook")]))
        self.assertEqual(self.names("원샷 가젯 못 써요"), ([], [("원샷 가젯",)]))
        self.assertEqual(self.names("hook 사용할 수 없음"), ([], [("hook",)]))

    def test_korean_only_x_is_not_a_lack(self) -> None:
        self.assertEqual(self.names("syscall 가젯밖에 없어요"), (["syscall", "가젯"], []))

    def test_korean_terms_written_without_spaces(self) -> None:
        self.assertEqual(self.names("스택피벗 방법")[0], ["스택 피벗"])
        self.assertEqual(self.names("원샷가젯 조건")[0], ["원샷 가젯", "조건"])

    def test_korean_predicate_pieces_are_not_concepts(self) -> None:
        self.assertEqual(self.names("pop rdi 가젯 없음 ret2csu 써야 하나"), (["ret2csu"], [("pop", "rdi", "가젯")]))

    def test_state_words_close_a_statement(self) -> None:
        self.assertEqual(self.names("NX enabled, canary disabled, stack overflow"), (["nx", "stack", "overflow"], [("canary",)]))
        self.assertEqual(self.names("PIE on, canary off"), (["pie"], [("canary",)]))
        self.assertEqual(self.names("Full RELRO, hooks removed, have arbitrary write")[1], [("hooks",)])
        self.assertEqual(self.names("Full RELRO, PIE 꺼짐"), (["full", "relro"], [("pie",)]))

    def test_because_of_is_blocked_only_for_a_check_or_filter(self) -> None:
        self.assertEqual(self.names("no free hook because of glibc 2.34, have arbitrary write")[1], [("free", "hook")])
        self.assertEqual(self.names("no double free because of tcache key check, have uaf")[1], [])

    def test_impossible_and_noun_runs(self) -> None:
        self.assertEqual(self.names("canary leak is impossible because the buffer is null-terminated")[1], [("canary", "leak")])
        self.assertEqual(self.names("hook overwrite no longer possible on glibc 2.34")[1], [("hook", "overwrite")])
        self.assertEqual(self.names("no output function, ret2dlresolve"), (["ret2dlresolve"], [("output", "function")]))

    def test_korean_delete_as_a_verb_is_not_a_lack(self) -> None:
        self.assertEqual(self.names("노트 삭제 후 출력하면 libc 주소 릭됨")[1], [])
        self.assertEqual(self.names("셸코드에서 널 바이트 제거해야 함")[1], [])
        self.assertEqual(self.names("hook 삭제됨")[1], [("hook",)])

    def test_korean_one_syllable_nouns_drop_their_particle(self) -> None:
        self.assertEqual(self.names("free hook 덮을 수가 없어요, 임의 쓰기 있음"), (["임의 쓰기"], [("free", "hook")]))
        self.assertEqual(self.names("카나리 값이 매번 바뀜")[0], ["카나리"])

    def test_a_long_question_needs_at_most_four_concepts(self) -> None:
        self.assertEqual([required_units(n) for n in (1, 2, 3, 4, 5, 7, 9, 12)], [1, 2, 2, 2, 3, 4, 4, 4])


class KoreanTermTests(unittest.TestCase):
    def test_korean_exploitation_term_reaches_english_text(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rag-ko-") as temp:
            index = RagIndex(Path(temp) / "rag.sqlite")
            index.upsert_case({"id": "rng", "title": "rng", "body": "# Report\n## Solve\nThe PRNG state is recovered from 624 outputs.\n"},
                              collection="t")
            hit = index.search("난수 상태 복구", collection="t")[0]
            self.assertEqual(hit["case_id"], "rng")
            self.assertEqual(hit["excerpt_terms"], ["난수 상태", "복구"])

    def test_an_unknown_korean_word_only_relaxes_a_security_question(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rag-ko-") as temp:
            index = RagIndex(Path(temp) / "rag.sqlite")
            index.upsert_case({"id": "can", "title": "can", "body": "# Report\n## Solve\nLeak the canary, then overflow.\n레시피 메모\n"},
                              collection="t")
            self.assertEqual([h["case_id"] for h in index.search("카나리 우회법", collection="t")], ["can"])
            self.assertEqual(index.search("레시피 김치찌개 끓이는 법", collection="t"), [])


if __name__ == "__main__":
    unittest.main()
