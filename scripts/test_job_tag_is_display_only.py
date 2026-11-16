#!/usr/bin/env python3
"""The operator job TAG is a DISPLAY field. This suite pins that it stays one.

Run inside the api container (needs fastapi + the api dependency tree):

    docker cp scripts/test_job_tag_is_display_only.py <api>:/tmp/t.py
    docker exec <api> sh -c \
      'OGAMDO_ROOT=/app DATA_DIR=/tmp/tagtest python3 /tmp/t.py'

WHAT THE OPERATOR ASKED FOR, AND WHY IT NEEDS A TEST

    "job 생성할때 TAG를 입력할 수 있는 기능 ... 문제풀이에 영향을 주지는 말고
     UI상 사용자가 문제를 식별하기 쉽게하기 위함임"

The tag names the challenge in the job list so twelve concurrent jobs stop
reading as "pwn · chal.zip" twelve times over. The second half of that sentence
is the hard part: it must not affect solving. A label like `day2-hard` spent as
prompt tokens is not neutral — it is an unasked-for hint that steers the agent,
and it is invisible in the transcript because nobody thinks of the tag as an
input.

THE ONE REAL LEAK PATH IS `description`, NOT `meta.json`

meta.json sits one level above the agent's cwd (`job_dir/work`), and the agent
runs `danger-full-access`, so it CAN read the file if it goes looking. That is
true of `flag_format`, `model`, and every other meta key, and it is not the
risk worth engineering against.

The risk worth engineering against is `description`. That field IS handed to
the agent — `build_user_prompt(..., description, ...)` in every module — and
the web UI already folds a checkbox directive into it (app.js
CAPTURE_REMOTE_FLAG_DIRECTIVE). A tag concatenated into description "so the
agent knows what it is working on" would be the natural next commit, and it
would be silent. Section B pins that the tag lands in its own key and
contaminates nothing else; section E pins that no prompt builder is reachable
from it.

WHY THE STRUCTURAL CHECKS ARE AST AND NOT GREP

Grepping the tree for "tag" proves nothing — the word appears in `flag`,
`target`, `stage`, and in prose. Section E parses the module tree and asks a
precise question of every `build_user_prompt` call site: does any ARGUMENT
mention a tag, and does any builder take the meta dict at all? That question
has an answer a future refactor can actually fail.
"""
from __future__ import annotations

import ast
import inspect
import json
import os
import sys
import tempfile
from pathlib import Path

# The api container bind-mounts api/, modules/ and web-ui/ at /app but not
# scripts/, so the in-container invocation copies this file to /tmp and points
# ROOT at the mount explicitly.
ROOT = Path(os.environ.get("OGAMDO_ROOT") or Path(__file__).resolve().parent.parent)

# A sentinel no CTF prompt would ever contain by accident, so "absent" is a
# real measurement rather than a coincidence of vocabulary.
SENTINEL = "ZZTAGSENTINEL7f3a"

_results: list[bool] = []


def chk(label: str, cond: bool, got: object = "") -> None:
    _results.append(bool(cond))
    print(("PASS  " if cond else "FAIL  ") + label + ("" if cond else f"  | got={got!r}"))


def section(name: str) -> None:
    print("\n--- " + name + " " + "-" * max(0, 60 - len(name)))


# The nine operator-facing create routes. Named explicitly rather than
# globbed: the point of the list is to fail when a TENTH module is added and
# its form quietly ships without a tag field, which a glob would never notice.
CREATE_ROUTES = [
    ("web", "web_module", "analyze_web"),
    ("pwn", "pwn_module", "analyze_pwn"),
    ("forensic", "forensic_module", "collect_forensic"),
    ("misc", "misc_module", "analyze_misc"),
    ("crypto", "crypto_module", "analyze_crypto"),
    ("web3", "web3_module", "analyze_web3"),
    ("rev", "rev_module", "analyze_rev"),
    ("live_fire", "live_fire_module", "analyze_live_fire"),
]


def main() -> int:  # noqa: C901 - a checklist, not a branching algorithm
    sys.path.insert(0, str(ROOT))

    # Isolate storage BEFORE importing anything that reads DATA_DIR at import
    # time (modules/storage.py line 15). Without this a handler invocation
    # below would mkdir into the live /data/jobs tree.
    tmp = tempfile.mkdtemp(prefix="tagtest-")
    os.environ["DATA_DIR"] = tmp
    import modules.storage as _ms
    if str(_ms.DATA_DIR) != tmp:  # already imported by something upstream
        _ms.DATA_DIR = Path(tmp)
        _ms.JOBS_DIR = Path(tmp) / "jobs"
        _ms.UPLOADS_DIR = Path(tmp) / "uploads"

    from api.storage import JOB_TAG_MAX, sanitize_job_tag, stamp_job_tag

    # ================================================================== A
    section("A. sanitize_job_tag — storage hygiene, not HTML escaping")

    chk("blank input yields no tag at all (None, not \"\")",
        sanitize_job_tag(None) is None and sanitize_job_tag("") is None
        and sanitize_job_tag("   ") is None,
        [sanitize_job_tag(x) for x in (None, "", "   ")])
    chk("surrounding whitespace is trimmed",
        sanitize_job_tag("  day2  ") == "day2", sanitize_job_tag("  day2  "))

    # A tag is rendered into a SINGLE-LINE row. A newline would not "look
    # wrong", it would silently truncate the visible label at the break.
    chk("newlines and tabs collapse to one space — the row is single-line",
        sanitize_job_tag("a\nb") == "a b" and sanitize_job_tag("a\t\tb") == "a b",
        (sanitize_job_tag("a\nb"), sanitize_job_tag("a\t\tb")))
    chk("C0/DEL control characters do not survive",
        sanitize_job_tag("a\x00b\x1fc\x7fd") == "a b c d",
        sanitize_job_tag("a\x00b\x1fc\x7fd"))
    # Distinct from the control-char check above: that regex has a `+`, so it
    # already collapses runs of its OWN characters. Only a run of ordinary
    # SPACES exercises the join/split step, and without this case a mutation
    # that drops it goes unnoticed (M20 in the mutation harness).
    chk("runs of ordinary spaces collapse to one",
        sanitize_job_tag("a   b") == "a b", sanitize_job_tag("a   b"))

    # A route invoked directly in a test (test_live_fire_api_ui.py calls
    # analyze_live_fire positionally) leaves trailing params holding their
    # UNRESOLVED FastAPI default — a Form object, which is truthy and would
    # str() into a nonsense tag on every such job.
    from fastapi import params as _fp
    chk("a non-str input is not a tag — notably an unresolved Form(None) "
        "default, which is truthy",
        sanitize_job_tag(_fp.Form(None)) is None
        and sanitize_job_tag(123) is None
        and sanitize_job_tag(b"bytes") is None,
        [sanitize_job_tag(x) for x in (_fp.Form(None), 123, b"bytes")])
    chk(f"length is capped server-side at {JOB_TAG_MAX} — the HTML maxlength "
        "is a courtesy a direct POST ignores",
        len(sanitize_job_tag("x" * 500)) == JOB_TAG_MAX,
        len(sanitize_job_tag("x" * 500)))

    # Escaping belongs to the renderer (section G). Stripping `<` here would
    # mangle a legitimate operator tag for no security benefit, because the
    # value never reaches an HTML attribute.
    chk("angle brackets are PRESERVED — `web<->pwn` is a real tag an operator "
        "types, and escaping is the renderer's job",
        sanitize_job_tag("web<->pwn") == "web<->pwn", sanitize_job_tag("web<->pwn"))
    chk("non-ASCII survives intact (operators write Korean tags)",
        sanitize_job_tag(" 웹 2일차 ") == "웹 2일차", sanitize_job_tag(" 웹 2일차 "))

    # ================================================================== B
    section("B. stamp_job_tag — the tag lands in its own key and nowhere else")

    base = {
        "id": "j1", "module": "web", "status": "queued",
        "description": "login bypass, flag at /flag.txt",
        "filename": "chal.zip", "flag_format": None,
    }
    m = dict(base)
    stamp_job_tag(m, f"  {SENTINEL}  ")
    chk("a supplied tag is stored, sanitised", m.get("tag") == SENTINEL, m.get("tag"))

    # THE CENTRAL PROPERTY. `description` is the field that IS given to the
    # agent; every other value must be byte-identical to the untagged run.
    others = {k: v for k, v in m.items() if k != "tag"}
    chk("REGRESSION: no OTHER meta field changed — description above all",
        others == base, {k: v for k, v in others.items() if base.get(k) != v})
    chk("REGRESSION: the sentinel appears in no other value",
        SENTINEL not in json.dumps(others, ensure_ascii=False),
        json.dumps(others, ensure_ascii=False)[:200])

    # Absent, not null: thousands of pre-tag jobs on disk have no `tag` key,
    # and a new untagged job must be indistinguishable from them so the UI
    # needs exactly one truthiness test rather than two.
    m2 = dict(base)
    stamp_job_tag(m2, None)
    chk("an untagged job has NO tag key — matching every pre-tag job on disk",
        "tag" not in m2, sorted(m2))
    m3 = dict(base, tag="stale")
    stamp_job_tag(m3, "   ")
    chk("clearing the field removes the key rather than writing an empty string",
        "tag" not in m3, m3.get("tag"))

    # ================================================================== C
    section("C. all nine create routes accept `tag` as a real Form field")

    from fastapi import params as fastapi_params

    for module_name, mod_attr, fn_name in CREATE_ROUTES:
        try:
            mod = __import__(f"api.routes.{mod_attr}", fromlist=["*"])
            fn = getattr(mod, fn_name)
        except Exception as exc:  # noqa: BLE001
            chk(f"{module_name}: route importable", False, f"{type(exc).__name__}: {exc}")
            continue
        sig = inspect.signature(fn)
        p = sig.parameters.get("tag")
        ok = p is not None and isinstance(p.default, fastapi_params.Form)
        chk(f"{module_name}: `tag` is a Form(...) parameter on {fn_name}()",
            ok, None if p is None else type(p.default).__name__)
        # Optional, not required — tagging must never become a step an
        # operator has to complete before a job can be created.
        if p is not None:
            chk(f"{module_name}:   ...and it is OPTIONAL (default None)",
                getattr(p.default, "default", "MISSING") is None,
                getattr(p.default, "default", "MISSING"))

    # ================================================================== D
    section("D. every route wires ITS OWN `tag` param into stamp_job_tag, "
            "before enrich_job_meta")

    for module_name, mod_attr, fn_name in CREATE_ROUTES:
        src = (ROOT / "api" / "routes" / f"{mod_attr}.py").read_text()
        tree = ast.parse(src)
        fn_node = next(
            (n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
             and n.name == fn_name),
            None,
        )
        if fn_node is None:
            chk(f"{module_name}: {fn_name}() found in source", False)
            continue

        stamps, enrichs = [], []
        for node in ast.walk(fn_node):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id == "stamp_job_tag":
                stamps.append(node)
            elif node.func.id == "enrich_job_meta":
                enrichs.append(node)

        chk(f"{module_name}: stamp_job_tag is called exactly once",
            len(stamps) == 1, len(stamps))
        if len(stamps) != 1 or not enrichs:
            continue
        call = stamps[0]
        args = [a for a in call.args]
        # Guards against the copy-paste failure this shape invites: passing
        # `description`, or another route's variable, instead of `tag`.
        chk(f"{module_name}:   stamp_job_tag(meta, tag) — the SECOND argument "
            "is the handler's own `tag` parameter",
            len(args) == 2
            and isinstance(args[0], ast.Name) and args[0].id == "meta"
            and isinstance(args[1], ast.Name) and args[1].id == "tag",
            [getattr(a, "id", type(a).__name__) for a in args])
        chk(f"{module_name}:   it runs BEFORE enrich_job_meta, so a later "
            "provider stamp can still override a colliding key",
            call.lineno < min(e.lineno for e in enrichs),
            (call.lineno, min(e.lineno for e in enrichs)))

    # ================================================================== E
    section("E. the tag is structurally unable to reach an agent prompt")

    # Every module builds its user prompt through build_user_prompt(). The
    # invariant that keeps meta keys out of prompts is that these builders
    # take EXPLICIT named fields and are never handed the meta dict.
    builders = sorted((ROOT / "modules").rglob("prompts.py"))
    chk("prompt builders found to inspect", len(builders) >= 6, len(builders))

    for f in builders:
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name != "build_user_prompt":
                continue
            a = node.args
            names = [p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)]
            if a.vararg:
                names.append(a.vararg.arg)
            if a.kwarg:
                names.append(a.kwarg.arg)
            rel = f.relative_to(ROOT)
            chk(f"{rel}: build_user_prompt takes no `tag` parameter",
                "tag" not in names, names)
            # A `meta` parameter or a **kwargs splat is how a display field
            # reaches a prompt without anyone deciding that it should.
            chk(f"{rel}:   ...and is never handed the meta dict (no `meta` "
                "param, no **kwargs)",
                "meta" not in names and a.kwarg is None, names)

    # Now the call sites: no ARGUMENT at any build_user_prompt call may be
    # derived from a tag. ast.unparse gives the exact expression text, so
    # `meta.get("tag")` is caught while the word "target" is not.
    call_sites = 0
    for f in sorted((ROOT / "modules").rglob("*.py")):
        try:
            tree = ast.parse(f.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fname = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if fname != "build_user_prompt":
                continue
            call_sites += 1
            exprs = [ast.unparse(x) for x in node.args]
            exprs += [f"{k.arg}={ast.unparse(k.value)}" for k in node.keywords]
            bad = [e for e in exprs if "tag" in e.replace("target", "")
                   .replace("stage", "").replace("flag", "")]
            chk(f"{f.relative_to(ROOT)}:{node.lineno}: no argument is "
                "tag-derived", not bad, bad)
            # A **meta splat would defeat every check above in one line.
            chk(f"{f.relative_to(ROOT)}:{node.lineno}:   no dict splat into "
                "the prompt builder",
                not any(k.arg is None for k in node.keywords),
                [k.arg for k in node.keywords])
    chk("call sites were actually found (a rename would silently empty this "
        "whole section)", call_sites >= 6, call_sites)

    # ================================================================== F
    section("F. a retry inherits its parent's tag")

    retry_src = (ROOT / "api" / "routes" / "retry.py").read_text()
    chk("retry's new-job meta carries the parent tag forward",
        'if prev_meta.get("tag")' in retry_src
        and '{"tag": prev_meta["tag"]}' in retry_src)
    # Conditional, so a retry of a pre-tag parent stays keyless rather than
    # gaining `"tag": None` and diverging from every other untagged job.
    chk("REGRESSION: an untagged parent produces no tag key on the retry",
        '**({"tag": prev_meta["tag"]} if prev_meta.get("tag") else {})' in retry_src)

    # ================================================================== G
    section("G. the UI renders the tag escaped, in a TEXT context")

    app_js = (ROOT / "web-ui" / "app.js").read_text()
    index_html = (ROOT / "web-ui" / "index.html").read_text()

    chk("the job list row renders the tag through escapeHtml",
        "escapeHtml(job.tag)" in app_js)
    chk("the job detail panel shows it as a meta chip",
        '_metaChip("tag ", job.tag)' in app_js)

    # escapeHtml() in this file escapes & < > and NOT quotes (verified below).
    # That is correct for element content and WRONG for an attribute value, so
    # the tag must never be interpolated into one.
    esc = app_js.split("function escapeHtml", 1)[1].split("}", 1)[0]
    chk("escapeHtml still escapes only & < > — this is why the tag may not go "
        "in an attribute",
        '"&amp;"' in esc and '"&lt;"' in esc and '"&gt;"' in esc
        and "&quot;" not in esc and "&#39;" not in esc, esc)
    chk("REGRESSION: the tag is never interpolated into an HTML attribute "
        "(no `=\"${...job.tag...}\"`)",
        '="${escapeHtml(job.tag)' not in app_js
        and '="${job.tag' not in app_js)
    chk("the tag pill carries no title= attribute, unlike the meta chips",
        'class="tag-pill"' in app_js
        and 'tag-pill" title' not in app_js)

    forms = index_html.count('name="tag"')
    chk("all nine create forms carry a tag input", forms == 9, forms)
    chk("every tag input is a plain single-line text field (a textarea would "
        "invite the newlines section A strips)",
        index_html.count('type="text" name="tag"') == 9,
        index_html.count('type="text" name="tag"'))
    chk("the form tells the operator it is display-only, so nobody uses it as "
        "a hint channel",
        index_html.count("Never sent to the agent") == 9,
        index_html.count("Never sent to the agent"))

    # ================================================================== H
    section("H. end-to-end: the real handler, the real meta.json on disk")

    # The strongest available statement of "display only": run the actual
    # create route twice — once tagged, once not — and diff the two meta.json
    # files that land on disk. Everything upstream of the diff is real
    # (prepare_job_description, stamp_job_tag, enrich_job_meta,
    # write_job_meta, redact_job_value); only the RQ queue is stubbed, so no
    # job is enqueued and nothing touches the live /data tree.
    import asyncio

    from api.routes import web_module as wm

    class _FakeQueue:
        def __init__(self) -> None:
            self.enqueued: list[tuple] = []

        def enqueue(self, *a, **k):
            self.enqueued.append((a, k))

    fake_q = _FakeQueue()
    real_get_queue = wm.get_queue
    real_new_job_id = wm.new_job_id
    wm.get_queue = lambda: fake_q

    def _run(job_id: str, tag_value):
        wm.new_job_id = lambda: job_id
        return asyncio.get_event_loop().run_until_complete(
            wm.analyze_web(
                file=None,
                target_url="http://127.0.0.1:9/",
                description="login bypass, flag at /flag.txt",
                challenge_secret_key=None,
                challenge_secret_value=None,
                auto_run=False,
                docker_challenge=False,
                job_timeout=600,
                model=None,
                effort=None,
                output_language=None,
                tag=tag_value,
                flag_format=None,
            )
        )

    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
        _run("tagged000001", f"  {SENTINEL}  ")
        _run("untagged0001", None)
    finally:
        wm.get_queue = real_get_queue
        wm.new_job_id = real_new_job_id

    jobs = Path(tmp) / "jobs"
    tagged_raw = (jobs / "tagged000001" / "meta.json").read_text()
    untagged_raw = (jobs / "untagged0001" / "meta.json").read_text()
    tagged = json.loads(tagged_raw)
    untagged = json.loads(untagged_raw)

    chk("the tagged job's meta.json carries the sanitised tag",
        tagged.get("tag") == SENTINEL, tagged.get("tag"))
    chk("the untagged job's meta.json has no tag key at all",
        "tag" not in untagged, sorted(untagged))

    # id and the lifecycle timestamps differ by construction (two separate
    # runs, microseconds apart); `tag` is the field under test. Everything
    # else must match exactly.
    IGNORE = {"id", "tag", "created_at", "updated_at", "started_at",
              "finished_at", "src_root"}
    diff = {
        k: (untagged.get(k), tagged.get(k))
        for k in set(tagged) | set(untagged)
        if k not in IGNORE and tagged.get(k) != untagged.get(k)
    }
    chk("REGRESSION: tagging changes NOTHING else in the job's metadata — "
        "the two runs differ only by the tag key",
        diff == {}, diff)

    # The single most important line in this file. `description` is the string
    # handed to build_user_prompt(); if a tag ever reaches the agent, this is
    # the field it arrives in.
    chk("REGRESSION: `description` — the field the agent actually reads — is "
        "byte-identical between the tagged and untagged runs",
        tagged.get("description") == untagged.get("description"),
        (tagged.get("description"), untagged.get("description")))
    chk("REGRESSION: the sentinel appears in the meta.json ONLY as the tag "
        "value, nowhere else in the document",
        tagged_raw.count(SENTINEL) == 1, tagged_raw.count(SENTINEL))

    # The tag must not ride along into the worker's argv either — run_job gets
    # positional arguments, and an extra one would change the call signature.
    chk("the enqueued worker call carries no tag",
        len(fake_q.enqueued) == 2
        and SENTINEL not in repr(fake_q.enqueued),
        repr(fake_q.enqueued)[:300])

    # ================================================================== I
    section("I. the tag survives the job LIFECYCLE")

    # Section H reads meta.json the instant the job is created — before any
    # worker has touched it. That is the easy half. The tag is only useful if
    # it is still there when the operator actually needs it, which is while
    # twelve jobs are RUNNING, several status writes later.
    #
    # modules/_common.write_meta() is the writer every worker uses for
    # queued -> running -> finished. It re-reads meta.json from disk and
    # meta.update(updates)s it, so unknown keys survive — but nothing pinned
    # that, and a future version that composed a fresh dict per transition
    # would demo perfectly at creation and lose the tag the moment the job
    # started.
    import modules._common as _C

    lifecycle_id = "tagged000001"          # the job section H created, tagged
    _C.write_meta(lifecycle_id, status="running")
    after_running = json.loads((jobs / lifecycle_id / "meta.json").read_text())
    chk("the tag survives the queued -> running transition",
        after_running.get("tag") == SENTINEL, after_running.get("tag"))

    _C.write_meta(lifecycle_id, status="finished", cost_usd=1.5)
    after_finished = json.loads((jobs / lifecycle_id / "meta.json").read_text())
    chk("...and the running -> finished transition",
        after_finished.get("tag") == SENTINEL, after_finished.get("tag"))
    chk("...and a mid-run counter flush that names unrelated fields",
        after_finished.get("cost_usd") == 1.5 and after_finished.get("tag") == SENTINEL,
        (after_finished.get("cost_usd"), after_finished.get("tag")))

    failed = [r for r in _results if not r]
    print(f"\n{len(_results)} checks, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
