/**
 * The job panel must not build what nobody is looking at.
 *
 * WHY THIS EXISTS
 *
 * The operator reported the panel laggy ON ENTRY — "들어갈때마다", and on
 * finished jobs too — after four fixes had already shipped for it. Every one
 * of those four targets REPEAT polls: the terminal-status poll stop, the
 * colouriser memo, the skip-if-unchanged innerHTML, the timeline field trim.
 * On entry the poll has not repeated, the memo is empty by definition, and the
 * skip is guarded on `isSameJob`. None of them reduce what entry builds.
 *
 * Entry builds a lot. Measured with jsdom on real jobs:
 *
 *     48fadce3dde7   timeline  8,460 + run log 10,728 = 19,188 elements
 *     29f1d8f14268   timeline  1,844 + run log  7,069 =  8,913 elements
 *
 * and BOTH halves were built every time, because renderJob emitted the
 * timeline feed and the fully colourised <pre class="run-log"> into the same
 * markup while style.css hid one of them:
 *
 *     .run-log-window[data-view="timeline"] .run-log      { display: none }
 *     .run-log-window[data-view="log"] .gpt-timeline-feed { display: none }
 *     .run-log-window[data-show-tools="0"] .gpt-tool-event { display: none }
 *
 * That third rule matters as much as the first two: tool cards are 43.6% of
 * the events on 48fadce3dde7 and `gptTimelineTools` defaults to false, so
 * 3,899 elements were parsed for cards the stylesheet immediately hid.
 *
 * After: entry builds only the active view, and only what the cap allows.
 *
 *     48fadce3dde7   19,188 -> 3,040 elements in the default timeline view
 *     29f1d8f14268    8,913 -> 1,069
 *
 * WHAT THE OPERATOR ASKED FOR, AND WHY THE NUMBER MOVED
 *
 * The request was a 1 MB display cap on the Timeline and the Raw log. Both
 * were already under it — timeline 366 KB after trimming, raw log 256 KB from
 * a `tail=262144` fetch — so a byte cap would have cut exactly nothing. Worse,
 * bytes do not predict the cost: the same 256 KB budget yields ~29,000 nodes
 * on one job and ~110,000 on a short-line job. The axis is ITEMS, so the caps
 * here are in cards and lines.
 *
 * THERE IS NO KNEE, AND THIS SUITE DOES NOT PRETEND OTHERWISE
 *
 * Marginal cost is flat on every axis measured (nodes/line 11.80, 10.78,
 * 11.06, 11.11, 11.18 from N=50 to N=2553; nodes/card likewise; file rows
 * exactly 3.00). So 300 and 1000 are a ~10,000-node-per-view budget divided by
 * measured per-item cost, not an inflection. The checks below pin the
 * BEHAVIOUR — tail-anchored, announced, reversible — and deliberately do not
 * assert the specific numbers, which are a policy choice a future operator
 * should be free to change by changing the budget.
 *
 * Run:
 *   node scripts/test_job_panel_render_cap.js
 *   node scripts/test_job_panel_render_cap.js --mutate build-both-views
 */
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const MUTATIONS = [
  "none",
  "build-both-views",   // the hidden half is built again — the shipped bug
  "cap-from-head",      // the cap keeps the OLDEST items instead of the newest
  "no-more-banner",     // capped output looks complete; the operator is misled
  "tools-always-built",  // CSS-hidden tool cards are parsed again
  "uncap-ignored",      // "더 보기" does nothing, so content is unreachable
  "view-not-in-markup", // data-view leaves the markup, so the skip hash collides
  "search-clear-uncaps", // clearing the search box restores the WHOLE log
  "search-ignores-view", // search colourises into a display:none <pre>
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

if (MUTATE === "build-both-views") {
  app = app.replace("  const showTimeline = isGptJob && activityView === \"timeline\";\n" +
                    "  const showLog = activityView === \"log\";",
                    "  const showTimeline = isGptJob;\n  const showLog = true;");
} else if (MUTATE === "cap-from-head") {
  app = app.replace("events = events.slice(-_RENDER_MAX_CARDS);",
                    "events = events.slice(0, _RENDER_MAX_CARDS);");
} else if (MUTATE === "no-more-banner") {
  app = app.replace("  if (!dropped) return \"\";", "  return \"\";");
} else if (MUTATE === "tools-always-built") {
  app = app.replace("  if (!gptTimelineTools) {", "  if (false) {");
} else if (MUTATE === "uncap-ignored") {
  app = app.replace("      _renderUncapped.add(btn.dataset.jobId || id);\n", "");
} else if (MUTATE === "search-clear-uncaps") {
  app = app.replace("pre.innerHTML = raw ? _cappedLogHtml(id, raw, anchor) : \"(empty)\";",
                    "pre.innerHTML = raw ? colorizeRunLog(raw, anchor) : \"(empty)\";");
} else if (MUTATE === "search-ignores-view") {
  app = app.replace('  if (win && win.dataset && win.dataset.view !== "log") return;\n', "");
} else if (MUTATE === "view-not-in-markup") {
  app = app.replace('<div class="run-log-window" data-view="${activityView}"',
                    '<div class="run-log-window"');
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

// --- run the real render helpers, not a paraphrase of them -----------------
// Contiguous slices anchored on the functions that open and close each region,
// so a moved helper fails loudly instead of quietly dropping out and leaving
// this suite measuring nothing.
function slice(startRe, endRe) {
  const L = app.split("\n");
  const a = L.findIndex((l) => startRe.test(l));
  const b = L.findIndex((l, i) => i > a && endRe.test(l));
  if (a < 0 || b < 0) throw new Error(`slice not found: ${startRe} .. ${endRe}`);
  return L.slice(a, b).join("\n");
}

function ctx(toolsOn) {
  const dom = new JSDOM("<div id=x></div>");
  const body =
    slice(/^function _fmtMonTime\(/, /^let livePillTimer/) + "\n" +
    slice(/^function escapeHtml\(/, /^const _LANG_FROM_EXT/) + "\n";
  const api = new Function(
    "gptTimelineTools", "runlogTz", "document", "window",
    body + "\nreturn { renderGptTimeline, colorizeRunLog, _cappedLogHtml," +
           " _tailLines, _moreBanner, _renderUncapped, applyLogSearch,"
         + " _runLogRaw, _runLogAnchor, _logSearch," +
           " _RENDER_MAX_CARDS, _RENDER_MAX_LOG_LINES };",
  )(toolsOn, "utc", dom.window.document, dom.window);
  const count = (html) => {
    const d = dom.window.document.createElement("div");
    d.innerHTML = html;
    return d.querySelectorAll("*").length;
  };
  return { api, count, dom };
}

const events = (n, kindAt) => Array.from({ length: n }, (_, i) => ({
  ts: `2026-09-06T10:${String(i % 60).padStart(2, "0")}:00Z`,
  kind: kindAt ? kindAt(i) : "message",
  role: "main", status: "info", title: `event ${i}`,
  summary: `요약 ${i}`, detail: "X".repeat(200),
}));
const payload = (evs) => ({ enabled: true, agents: [], events: evs, source: "gpt-events.jsonl" });
const logOf = (n) => Array.from({ length: n }, (_, i) => `[10:00:00] line ${i}`).join("\n") + "\n";

// --- A: the cap keeps the NEWEST, and says what it dropped -----------------
{
  console.log("\nA — the caps are tail-anchored and announced");
  const { api, count } = ctx(false);
  const N = api._RENDER_MAX_CARDS;
  const html = api.renderGptTimeline(payload(events(N + 120)), "jobA");
  check("A1 a run past the cap is clipped", count(html) < count(
    api.renderGptTimeline(payload(events(N + 120)), null)));
  // The operator opens a job to see what JUST happened. Keeping the head
  // would show them the opening minutes of a run that has since finished.
  check("A2 ...keeping the newest events", html.includes(`event ${N + 119}`));
  check("A3 ...and dropping the oldest", html.includes("event 0"), false);
  check("A4 ...and saying so, with a count", /120.*생략됨/.test(html));
  check("A5 ...offering a way to see the rest", /data-action="render-uncap"/.test(html));

  const short = api.renderGptTimeline(payload(events(10)), "jobA");
  check("A6 a run under the cap gets no banner", /생략됨/.test(short), false);

  const { text, clipped } = api._tailLines(logOf(1500), api._RENDER_MAX_LOG_LINES);
  check("A7 the log cap keeps the tail too", text.includes("line 1499"));
  check("A8 ...drops the head", text.includes("line 0\n"), false);
  check("A9 ...and reports how many lines went", clipped, 500);
  const whole = api._tailLines(logOf(10), 1000);
  check("A10 a short log is returned untouched", whole.clipped, 0);
}

// --- B: CSS-hidden tool cards are never built ------------------------------
{
  console.log("\nB — cards the stylesheet would hide are not parsed");
  const evs = events(200, (i) => (i % 2 ? "tool" : "message"));
  const off = ctx(false), on = ctx(true);
  const hOff = off.api.renderGptTimeline(payload(evs), "jobB");
  const hOn = on.api.renderGptTimeline(payload(evs), "jobB");
  check("B1 with tools OFF the tool cards are absent",
    /gpt-tool-event/.test(hOff), false);
  check("B2 ...and the panel is materially smaller",
    off.count(hOff) * 1.5 < on.count(hOn));
  // Not a feature removal: the toggle re-renders and brings them back.
  check("B3 with tools ON they are built", /gpt-tool-event/.test(hOn));
  check("B4 ...and the toggle forces a rebuild",
    /_toggleGptTimelineTools[\s\S]{0,220}renderJob\(selectedJob, \{ force: true \}\)/.test(app));
  // A run that is ALL tool calls must not look like a dead job.
  const allTools = off.api.renderGptTimeline(
    payload(events(40, () => "tool")), "jobB2");
  check("B5 an all-tools run explains itself rather than looking empty",
    /도구 보기/.test(allTools));
}

// --- C: "더 보기" actually lifts the cap -----------------------------------
{
  console.log("\nC — the capped content stays reachable");
  const { api, count } = ctx(false);
  const evs = events(api._RENDER_MAX_CARDS + 200);
  const capped = api.renderGptTimeline(payload(evs), "jobC");
  api._renderUncapped.add("jobC");
  const full = api.renderGptTimeline(payload(evs), "jobC");
  check("C1 lifting the cap shows everything", full.includes("event 0"));
  check("C2 ...and is materially bigger", count(full) > count(capped));
  check("C3 ...with no banner left to click", /생략됨/.test(full), false);
  // Per job, not global: a cap lifted once must not make every later entry
  // expensive again.
  const other = api.renderGptTimeline(payload(evs), "jobC-other");
  check("C4 the lift does not leak to another job", other.includes("event 0"), false);
  check("C5 the button is wired to record the job it belongs to",
    /_renderUncapped\.add\(btn\.dataset\.jobId \|\| id\)/.test(app));
  check("C6 ...and re-renders past the skip",
    /render-uncap[\s\S]{0,320}renderJob\(id, \{ force: true \}\)/.test(app));
}

// --- D: only the active view is built --------------------------------------
{
  console.log("\nD — the hidden half is not built");
  // renderJob is a 900-line async function that cannot be executed here, so
  // this half is structural. It is still discriminating: the mutation
  // build-both-views restores exactly the shipped defect and fails D1/D2.
  check("D1 the timeline is built only for the timeline view",
    /const showTimeline = isGptJob && activityView === "timeline";/.test(app));
  check("D2 the log is colourised only for the log view",
    /const showLog = activityView === "log";/.test(app));
  check("D3 the timeline container is emitted either way, so CSS and scroll" +
        " restoration still find it",
    /<div class="gpt-timeline-feed" data-job-id="\$\{id\}">\$\{gptTimelineHTML\}<\/div>/.test(app));
  check("D4 ...as is the <pre>, which applyLogSearch fills from _runLogRaw",
    /<pre class="run-log" data-job-id="\$\{id\}"[\s\S]{0,160}!showLog \? "" :/.test(app));
  // The skip fingerprint hashes _nextHtml. If data-view left the markup, two
  // different views could hash the same and a toggle would never paint.
  check("D5 data-view is inside the hashed markup",
    /<div class="run-log-window" data-view="\$\{activityView\}"/.test(app));
  check("D6 ...and so is the tools toggle",
    /data-show-tools="\$\{gptTimelineTools \? "1" : "0"\}"/.test(app));
  check("D7 switching view re-renders with force",
    /_setGptLogView[\s\S]{0,220}renderJob\(selectedJob, \{ force: true \}\)/.test(app));
}

// --- E: search is unaffected by an unbuilt <pre> ---------------------------
{
  console.log("\nE — the log search does not depend on what was rendered");
  // This is why an empty <pre> is safe: applyLogSearch rebuilds its content
  // from the raw text it keeps in memory, not from the DOM.
  check("E1 applyLogSearch reads the raw log, not the rendered node",
    /function applyLogSearch\(id\)[\s\S]{0,1400}const raw = _runLogRaw\[id\] \|\| "";/.test(app));
  check("E2 ...and writes the result into the <pre> itself",
    /function applyLogSearch\(id\)[\s\S]{0,2000}pre\.innerHTML =/.test(app));
}

// --- F: the search box is the OTHER door into the <pre> --------------------
{
  console.log("\nF — applyLogSearch honours the same two rules as renderJob");
  // It does not read the DOM (E1) but it does WRITE it, so it can undo both the
  // cap and the view guard. Both bypasses were reachable by typing one
  // character into the filter box and deleting it again.
  const { api, dom } = ctx(false);
  const JOB = "jobF";
  const bigLog = logOf(2600);

  function panel(view) {
    dom.window.document.body.innerHTML =
      `<div class="run-log-window" data-view="${view}">
         <span class="run-log-search-count" data-job-id="${JOB}"></span>
         <pre class="run-log" data-job-id="${JOB}"></pre>
       </div>`;
    return dom.window.document.querySelector("pre.run-log");
  }
  api._runLogRaw[JOB] = bigLog;
  api._runLogAnchor[JOB] = null;

  // F1: clearing the box must restore the CAPPED view, not all 2,600 lines.
  let pre = panel("log");
  api._logSearch[JOB] = "";
  api.applyLogSearch(JOB);
  const clearedEls = pre.querySelectorAll("*").length;
  const cappedEls = (() => {
    const d = dom.window.document.createElement("div");
    d.innerHTML = api._cappedLogHtml(JOB, bigLog, null);
    return d.querySelectorAll("*").length;
  })();
  const uncappedEls = (() => {
    const d = dom.window.document.createElement("div");
    d.innerHTML = api.colorizeRunLog(bigLog, null);
    return d.querySelectorAll("*").length;
  })();
  check("F1 clearing the search restores the capped view, not the whole log",
    clearedEls <= cappedEls + 4);
  check("F2 ...which is a fraction of the uncapped log",
    clearedEls * 2 < uncappedEls);

  // F3: a loose query matches almost everything and must be capped too.
  pre = panel("log");
  api._logSearch[JOB] = "line";           // matches all 2,600
  api.applyLogSearch(JOB);
  const searchEls = pre.querySelectorAll("*").length;
  // The highlighter wraps each hit, so a capped search is NOT element-identical
  // to the capped plain view — it is compared against the same search run
  // without a cap, which is the thing being prevented.
  api._renderUncapped.add(JOB);
  const preFull = panel("log");
  api.applyLogSearch(JOB);
  const searchFullEls = preFull.querySelectorAll("*").length;
  api._renderUncapped.delete(JOB);
  pre = panel("log");
  api.applyLogSearch(JOB);
  check("F3 a query matching nearly every line is still capped",
    searchEls * 2 < searchFullEls);
  check("F4 ...and says how much it withheld", /생략됨/.test(pre.innerHTML));
  // The COUNT still reports the true total — capping the render must not lie
  // about how many lines matched.
  const countEl = dom.window.document.querySelector(".run-log-search-count");
  check("F5 the match count still reports the real total",
    /2600 \/ 260[01] lines/.test(countEl.textContent), true);

  // F6: not while hidden. renderJob re-applies an active search every pass.
  pre = panel("timeline");
  api._logSearch[JOB] = "line";
  api.applyLogSearch(JOB);
  check("F6 nothing is colourised into a hidden <pre>",
    pre.innerHTML.length, 0);
  pre = panel("monitor");
  api.applyLogSearch(JOB);
  check("F7 ...in the monitor view either", pre.innerHTML.length, 0);
}

console.log(`\n${PASS + FAIL} checks, ${FAIL} failed`);
process.exit(FAIL ? 1 : 0);
