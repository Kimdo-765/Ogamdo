/**
 * An open job panel must not keep paying for a job that stopped changing.
 *
 * WHY THIS EXISTS
 *
 * Opening a job detail was laggy, and worse on a FINISHED job than a running
 * one. Two separate causes, measured on this deployment:
 *
 * 1. `stopped` was missing from the poller's terminal list, which read
 *    ["finished","failed","no_flag","flag_ready"]. It is the MOST COMMON
 *    status here — 12 of 32 jobs — because the operator stops jobs by hand.
 *    Every one of those kept polling forever: a 256 KB fetch, ~3,350 lines
 *    re-colourised through 7 regexes each, and a full detail.innerHTML
 *    rebuild, every 2 seconds, for as long as the panel stayed open.
 *    The server was never the problem — every endpoint answers in under 5 ms.
 *
 * 2. Even where polling did stop, each pass rebuilt the entire panel
 *    unconditionally. The rebuild is why the surrounding code has to save and
 *    restore log scroll, modal scroll, the SDK feed's HTML, and re-adopt the
 *    live .job-files node: all of it exists to undo damage that did not need
 *    doing, because on a quiet poll the new markup is byte-identical.
 *
 * Both fixes are structural, so both are pinned structurally here — jsdom
 * cannot measure "feels smooth", but it can prove the work is skipped.
 *
 * Run:
 *   node scripts/test_job_panel_idle_cost.js
 *   node scripts/test_job_panel_idle_cost.js --mutate stopped-not-terminal
 */
const fs = require("fs");
const path = require("path");

const MUTATIONS = [
  "none",
  "stopped-not-terminal",  // the status that polls forever is dropped again
  "terminal-list-split",   // one call site keeps its own copy of the list
  "no-colour-memo",        // the colouriser recomputes identical input
  "always-rebuild",        // innerHTML is assigned even when nothing changed
  "skip-drops-files",      // the quiet path stops refreshing the directory
];
const _mi = process.argv.indexOf("--mutate");
const MUTATE = _mi > -1 ? process.argv[_mi + 1] : "none";
if (!MUTATIONS.includes(MUTATE)) {
  console.error(`unknown mutation ${MUTATE}; one of ${MUTATIONS.join(", ")}`);
  process.exit(2);
}

const ROOT = path.resolve(__dirname, "..");
let app = fs.readFileSync(path.join(ROOT, "web-ui/app.js"), "utf8");
const _a0 = app;

if (MUTATE === "stopped-not-terminal") {
  app = app.replace(
    'const JOB_TERMINAL = ["finished", "failed", "stopped", "error", "no_flag", "flag_ready"];',
    'const JOB_TERMINAL = ["finished", "failed", "no_flag", "flag_ready"];');
} else if (MUTATE === "terminal-list-split") {
  app = app.replace("if (job && JOB_TERMINAL.includes(job.status)) {",
    'if (job && ["finished", "failed", "no_flag", "flag_ready"].includes(job.status)) {');
} else if (MUTATE === "no-colour-memo") {
  app = app.replace("  if (_k === _clrKey) return _clrVal;\n", "");
} else if (MUTATE === "always-rebuild") {
  app = app.replace(
    "  if (isSameJob && detail.dataset.renderedHtmlLen === String(_nextHtml.length)",
    "  if (false && isSameJob && detail.dataset.renderedHtmlLen === String(_nextHtml.length)");
} else if (MUTATE === "skip-drops-files") {
  app = app.replace("    mountJobFiles(id);\n    mountFlagGrain(id);\n    return job;",
                    "    mountFlagGrain(id);\n    return job;");
}
if (MUTATE !== "none" && app === _a0) {
  console.error(`MUTATION ${MUTATE} CHANGED NOTHING — its anchor no longer matches.`);
  process.exit(2);
}

let PASS = 0, FAIL = 0;
function check(label, got, want = true) {
  const a = JSON.stringify(got), b = JSON.stringify(want);
  if (a === b) PASS++;
  else { FAIL++; console.log(`FAIL  ${label}\n        got  = ${a}\n        want = ${b}`); }
}

// --- A: the poller stops on every status the server calls terminal ---------
const m = /const JOB_TERMINAL = (\[[^\]]*\]);/.exec(app);
check("JOB_TERMINAL is declared once, as a shared constant", !!m);
const terminal = m ? JSON.parse(m[1]) : [];

// Mirrors modules/_monitor.py:_TERMINAL. Read from the Python so the two
// cannot drift apart silently — that drift is exactly what shipped the bug.
const py = fs.readFileSync(path.join(ROOT, "modules/_monitor.py"), "utf8");
const pym = /_TERMINAL\s*=\s*\{([^}]*)\}/.exec(py);
const pySet = pym ? [...pym[1].matchAll(/"([a-z_]+)"/g)].map((x) => x[1]) : [];
check("the server's terminal set was located", pySet.length > 0);
for (const st of pySet) {
  check(`the UI stops polling on "${st}" — the server calls it terminal`,
    terminal.includes(st));
}
// The one that actually shipped broken, named so a regression is unambiguous.
check('"stopped" is terminal — 12 of 32 jobs in this deployment', terminal.includes("stopped"));

// Every call site must use the constant; a local copy is how it drifted before.
check("no call site keeps its own copy of the list",
  /\["finished",\s*"failed",\s*"no_flag",\s*"flag_ready"\]/.test(app), false);
check("both poll timers consult the shared constant",
  (app.match(/JOB_TERMINAL\.includes\(job\.status\)/g) || []).length, 2);
// A const used before its declaration line throws in the temporal dead zone.
const declAt = app.indexOf("const JOB_TERMINAL =");
check("...and it is declared before every use",
  [...app.matchAll(/JOB_TERMINAL\.includes/g)].every((x) => x.index > declAt));

// --- B1: the colouriser does not redo identical input ----------------------
check("colorizeRunLog is memoised", /if \(_k === _clrKey\) return _clrVal;/.test(app));
check("...keyed on the anchor as well as the text",
  /const _k = anchorIso \+ "\\u0000" \+ text;/.test(app));

// --- B2: an unchanged render is not re-applied -----------------------------
check("the rendered markup is compared before being assigned",
  /const _nextHtml = /.test(app) && /detail\.innerHTML = _nextHtml;/.test(app));
check("...via a cheap hash rather than a second 300 KB string",
  /function _cheapHash\(/.test(app));
check("...and the fingerprint is stored for the next pass",
  /detail\.dataset\.renderedHtmlHash = _cheapHash\(_nextHtml\)/.test(app));
// Guarded on the same job: job A's fingerprint must never suppress job B.
check("the skip only applies within the same job", /if \(isSameJob && detail\.dataset/.test(app));

// The skip must not silently freeze the parts that legitimately keep moving.
// Slice to the ASSIGNMENT, not to the first occurrence of the field name —
// that one is inside the if-condition (`... === String(...)`), which made the
// block come out nearly empty and three checks fail against correct code.
const _skipFrom = app.indexOf("if (isSameJob && detail.dataset");
const _skipTo = app.indexOf("\n  detail.dataset.renderedHtmlLen = String(", _skipFrom);
const skipBlock = app.slice(_skipFrom, _skipTo > -1 ? _skipTo : _skipFrom);
check("the quiet path still refreshes the directory listing",
  /mountJobFiles\(id\);/.test(skipBlock));
check("...and the flag_grain box", /mountFlagGrain\(id\);/.test(skipBlock));
check("...and returns the job, matching renderJob's contract",
  /return job;/.test(skipBlock));

// --- the hash must actually distinguish content ----------------------------
const hm = /function _cheapHash\(str\) \{[\s\S]*?\n\}/.exec(app);
if (hm) {
  const hash = new Function(hm[0] + "\nreturn _cheapHash;")();
  check("the hash separates different markup", hash("<div>a</div>") !== hash("<div>b</div>"));
  check("...and is stable for identical markup", hash("<div>a</div>"), hash("<div>a</div>"));
  // Same length, different bytes — a length check alone would call these equal,
  // which is why the code stores both.
  check("...including same-length changes", hash("abcd") !== hash("abce"));
} else {
  check("the hash function was found", false);
}

console.log(`\n${PASS + FAIL} checks, ${FAIL} failed`);
process.exit(FAIL ? 1 : 0);
