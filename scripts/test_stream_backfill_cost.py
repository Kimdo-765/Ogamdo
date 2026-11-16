#!/usr/bin/env python3
"""The SSE stream must not re-send what the client already fetched.

WHY THIS EXISTS

The operator reported the job panel laggy on entry three times. Two rounds of
fixes went into rendering — the poll, the memo, the skip, the field trim, then
active-view-only rendering and item caps — and the lag stayed. The fourth
report finally located it:

    "LIVE AGENT ACTIVITY가 안뜨고 3초후에 렉이 풀리면서 뜸"

That is the whole diagnosis. The `.sdk-live` panel is `hidden` until its first
event arrives (web-ui/app.js `_renderSdkEvent`), and the sdk replay is the LAST
thing the stream's backfill sends. So "the panel appears when the lag ends"
means the lag WAS the backfill ahead of it.

What that backfill was, on job 19cf9578a0fc:

    meta        1 frame     consumed
    log     2,807 frames    433,392 bytes   DISCARDED ON ARRIVAL
    monitor   <=400 frames                  DISCARDED ON ARRIVAL
    sdk       <=400 frames   the panel was waiting for these
    backfill_done

The two discarded replays are dropped by the client's own first line —
`if (payload.backfill) return;` in `_appendLiveLogLine`, and the same in
`_appendMonitorEntry` — because renderJob has ALREADY fetched
`/jobs/{id}/log?tail=262144` and `/jobs/{id}/monitor?tail=400`. The endpoint
docstring says the backfill exists so a client can render "without a separate
fetch"; the UI does both, and paid for the same bytes twice — the second time
one SSE frame per line, each JSON-parsed and thrown away.

It compounds: `backfill_done` is also the signal that WIDENS the poll interval
(app.js), so throughout those seconds the UI was still doing full 2s re-renders.

THE FIX, AND WHAT MUST NOT BREAK

`backfill=sdk` skips the log and monitor replay. The default stays "full", so
the original contract — a client that renders from the stream alone — is intact
for anyone who wants it; the web UI, which fetches separately, opts out.

So this suite has to pin BOTH directions. A change that made the lean mode the
only mode would pass a test that only checked the lean mode, and would silently
break the documented capability.

HOW THIS TESTS

By running the real `stream_job` generator against a real temp job directory
and counting the frames it yields, not by reading its source. Redis and
api.queue are stubbed because the generator only touches them for the LIVE
half; every assertion here is about backfill, which happens before any event
is awaited.

Run:
    python3 scripts/test_stream_backfill_cost.py
    python3 scripts/test_stream_backfill_cost.py --mutate ignores-param
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

APP_JS = (ROOT / "web-ui" / "app.js").read_text()
ROUTES_SRC = (ROOT / "api" / "routes" / "jobs.py").read_text()

MUTATIONS = (
    "ignores-param",     # the server replays the log whatever the client asks
    "always-lean",       # "full" stops replaying — the documented contract dies
    "ui-asks-for-full",  # the UI stops opting out, so the 3s comes back
    "monitor-still-sent",  # only the log is skipped; monitor still floods
    "sdk-dropped",       # the lean mode also drops what the panel NEEDS
)
ap = argparse.ArgumentParser()
ap.add_argument("--mutate", choices=MUTATIONS)
args = ap.parse_args()

_R0, _A0 = ROUTES_SRC, APP_JS
if args.mutate == "ignores-param":
    ROUTES_SRC = ROUTES_SRC.replace('    replay_history = backfill != "sdk"',
                                    "    replay_history = True", 1)
elif args.mutate == "always-lean":
    ROUTES_SRC = ROUTES_SRC.replace('    replay_history = backfill != "sdk"',
                                    "    replay_history = False", 1)
elif args.mutate == "ui-asks-for-full":
    APP_JS = APP_JS.replace("/stream?backfill=sdk`", "/stream`", 1)
elif args.mutate == "monitor-still-sent":
    ROUTES_SRC = ROUTES_SRC.replace("if not is_gpt_job and replay_history:",
                                    "if not is_gpt_job:", 1)
elif args.mutate == "sdk-dropped":
    ROUTES_SRC = ROUTES_SRC.replace('                        yield sse("sdk", entry)',
                                    "                        pass", 1)
if args.mutate and ROUTES_SRC == _R0 and APP_JS == _A0:
    raise SystemExit(f"MUTATION {args.mutate!r} CHANGED NOTHING — anchor is stale.")

PASSED = FAILED = 0


def check(label, got, want=True):
    global PASSED, FAILED
    ok = got == want
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"        got={got!r} want={want!r}")
    PASSED, FAILED = PASSED + ok, FAILED + (not ok)


# --- import the routes module with its live-half deps stubbed --------------
def _stub(name, **attrs):
    m = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(m, k, v)
    sys.modules[name] = m
    return m


class _Any:
    """A stand-in that answers anything, sync or async.

    The generator awaits its redis handles during setup (pubsub.subscribe) and
    only iterates them AFTER backfill_done, which is where every case here
    stops — so the live half never runs and does not need to be faithful.
    """
    def __init__(self, *a, **k): pass
    def __getattr__(self, n): return _Any()
    def __call__(self, *a, **k): return _Any()

    def __await__(self):
        async def _none(): return None
        return _none().__await__()

    def __aiter__(self): return self

    async def __anext__(self): raise StopAsyncIteration


_stub("redis", Redis=_Any,
      asyncio=_stub("redis.asyncio", from_url=lambda *a, **k: _Any()))
_stub("rq", Queue=_Any)
_stub("api.queue", get_queue=lambda *a, **k: _Any(), get_redis=lambda *a, **k: _Any())

# Exec the (possibly mutated) route source as its own module, so a mutation
# bites. Importing api.routes.jobs would load the real file and every case
# would report a false PASS.
import api.routes.jobs as _real                      # noqa: E402  (resolves deps)
MOD = types.ModuleType("_jobs_under_test")
MOD.__dict__.update({"__name__": "_jobs_under_test", "__file__": str(ROOT / "api/routes/jobs.py")})
exec(compile(ROUTES_SRC, "api/routes/jobs.py", "exec"), MOD.__dict__)


class _Req:
    """Enough of starlette's Request for the backfill half: never disconnected."""
    async def is_disconnected(self):
        return False


def frames_for(mode, *, gpt=True, log_lines=500, mon=30, sdk=12):
    """Drive the real generator and tally the backfill it emits."""
    tmp = tempfile.mkdtemp()
    d = Path(tmp) / "abc123abc123"
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps(
        {"status": "finished", "agent_provider": "gpt" if gpt else "claude"}))
    (d / "run.log").write_text(
        "".join(f"[10:00:0{i%10}] line {i}\n" for i in range(log_lines)))
    (d / "monitor.jsonl").write_text(
        "".join(json.dumps({"sev": "info", "text": f"m{i}"}) + "\n" for i in range(mon)))
    (d / "sdk.jsonl").write_text(
        "".join(json.dumps({"kind": "text", "text": f"s{i}"}) + "\n" for i in range(sdk)))

    MOD.JOBS_DIR = Path(tmp)
    tally, nbytes = {}, 0

    async def drive():
        nonlocal nbytes
        resp = await MOD.stream_job("abc123abc123", _Req(), backfill=mode)
        gen = resp.body_iterator
        async for chunk in gen:
            nbytes += len(chunk)
            head = chunk.split(b"\n", 1)[0]
            name = head.decode("utf-8", "replace").replace("event: ", "").strip()
            tally[name] = tally.get(name, 0) + 1
            if name == "backfill_done":
                break
        await gen.aclose()

    asyncio.new_event_loop().run_until_complete(drive())
    return tally, nbytes


def main() -> int:
    print("\nL — the lean mode sends only what the UI cannot get elsewhere")
    lean, lean_b = frames_for("sdk")
    # The two the client drops on arrival.
    check("L1 no run.log replay", lean.get("log", 0), 0)
    check("L2 no monitor replay", lean.get("monitor", 0), 0)
    # The two it needs. The sdk replay is the whole reason the panel un-hides.
    check("L3 the sdk replay still arrives", lean.get("sdk", 0) > 0)
    check("L4 ...and meta, which the UI does consume", lean.get("meta", 0), 1)
    check("L5 backfill_done still closes the backfill", lean.get("backfill_done", 0), 1)

    print("\nF — the documented full mode is untouched")
    full, full_b = frames_for("full")
    check("F1 the log replay is still available on request",
          full.get("log", 0) >= 500)
    check("F2 ...and the monitor replay for a non-GPT job",
          frames_for("full", gpt=False)[0].get("monitor", 0) > 0)
    check("F3 full remains the DEFAULT, so no other client changes behaviour",
          'backfill: str = "full"' in ROUTES_SRC)
    check("F4 ...and an unknown value is treated as full, not as lean",
          frames_for("anything-else")[0].get("log", 0) >= 500)

    print("\nB — the size of what stopped being sent")
    saved = full_b - lean_b
    print(f"        500 lines: {full_b:,} B -> {lean_b:,} B  (saved {saved:,} B)")
    # Measured on the real job this was reported against, 19cf9578a0fc:
    # 2,807 frames and 433,392 bytes, all discarded on arrival.
    check("B1 the lean stream is a fraction of the full one", lean_b * 4 < full_b)
    check("B2 ...and the saving scales with the log, which is the point",
          frames_for("full", log_lines=1000)[1] > full_b * 1.8)

    print("\nU — the UI actually opts out")
    # A server that CAN skip and a client that never asks is the same defect
    # wearing a fix.
    check("U1 the EventSource asks for the lean backfill",
          "/stream?backfill=sdk`" in APP_JS)
    check("U2 ...and the discard that made it redundant is still there",
          "if (payload.backfill) return;" in APP_JS)

    print(f"\n{PASSED} passed, {FAILED} failed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
