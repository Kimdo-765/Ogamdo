"""Platform knowledge the agent can load on demand, from a path it cannot edit.

WHY A PLUGIN AND NOT `.claude/skills/` IN THE JOB DIRECTORY

The CLI finds project skills relative to its cwd, and the agent's cwd is the
job's `work/` -- which is also where challenge archives unpack. A challenge
shipping `CLAUDE.md` or `.claude/settings.json` would then be loaded as
instructions. A `--plugin-dir` under `/app/worker` is read-only to the worker
and outside the job entirely, so challenge content cannot reach it.

WHY `setting_sources=[]`

Unset means "load every filesystem source", which is what these sessions do
today: the operator's own `~/.claude/settings.json` is mounted into the worker
and read on every job. Isolation is the documented SDK posture and it is the
honest one here -- a CTF run should not inherit a person's editor config, and
with `skills` enabled it would also make their personal skills invocable
inside a job. The plugin is unaffected: `--plugin-dir` is independent of
setting sources, verified live before this shipped.

WHAT IS IN IT

`ogamdo-toolchain` -- which tool is in WHICH image, what is not installed
anywhere, and how to reach a sibling image. Three lookups in one session
concluded a tool was missing by asking the wrong container.

`ogamdo-helpers` -- the `python3 -m worker.*` helpers that already exist, so
a job stops re-deriving them. One job wrote three CDP browser drivers before
it could look at a single rendered page.

MEASURED AND NOT DONE: A PROMPT POINTER AT THESE SKILLS

Across four jobs the Skill tool was called exactly once, by the misc agent,
13 seconds in -- `ogamdo-osint` says "read this before a geolocation
challenge" and that matched its task. The two reference skills never fire on
their own, so the obvious next move is a line in CTF_PREAMBLE telling every
module to load one before building something. It was A/B tested against the
real module prompts, one turn each, and it earns nothing:

  web prompt, "I need the rendered DOM of a JS-heavy page"
    without: "python3 -m worker.browser render ... not a hand-rolled CDP driver"
    with:    the same answer, Skill still unused

  web3 prompt, "I must sign with a scheme the standard library lacks"
    without: "probe for a vetted library implementation before hand-rolling
              the primitive"
    with:    the same answer, Skill still unused

Both failures the pointer was written for are already covered. The browser one
was fixed by naming `worker.browser` in `_TOOLS_BASE`, which every module
carries. The library one was never ignorance: the model already says "check
for a library before writing it by hand". One job still spent thirteen
minutes rebuilding a signature primitive -- not because it did not know to check,
but because it checked LATE, after ten minutes inside a committed path. A
static prompt line does not reach that moment, and the A/B cannot either: it
asks for a FIRST step, and the failure happens mid-path.

So the pointer is not here. Adding one would cost ~90 tokens on every job to
change nothing measurable, and this repo has rejected a guard on exactly these
grounds before (`guard/repeat-tool-reminder`, never ported). If the reference
skills are to earn their place, the evidence will have to come from a
mid-path intervention, which is a different mechanism and its own work.
"""
from __future__ import annotations

from pathlib import Path

# /app/worker/plugin in the container; the repo's worker/plugin on the host.
PLUGIN_DIR = str(Path(__file__).resolve().parent.parent / "worker" / "plugin")

# "all" rather than a name list: the names are namespaced (`ogamdo:<skill>`)
# and a list here would have to be kept in step with the directory by hand.
SKILLS = "all"

# Explicit, not defaulted. Leaving it unset lets the SDK pick
# ["user", "project"] once `skills` is set, which is exactly the two sources
# this is trying not to read.
SETTING_SOURCES: list[str] = []


def plugins() -> list[dict]:
    """The one local plugin, in the shape ClaudeAgentOptions expects."""
    return [{"type": "local", "path": PLUGIN_DIR}]
