/**
 * The flag_grain box is where an advisory component becomes visible.
 *
 * WHY THIS EXISTS
 *
 * The harvester can never write `meta.flags`, set a status, or end a job —
 * that restriction is its whole safety argument, because run.log was banned as
 * a flag source in 2026-07 after three jobs false-finished on fakes. The cost
 * of that restriction is that NOTHING in the UI would otherwise show its work.
 * This box is the only surface.
 *
 * Two things it must get right, both learned the hard way:
 *
 * 1. ERROR ROWS. Job 8e12a5fb1475: a grok-routed harvester consumed
 *    `FLAG_CANDIDATE: INCOGNITO{...}`, passed the gate, called the model, and
 *    wrote nothing — the model tried a `Web search:` the text-only helper
 *    refuses, and the turn was discarded. From outside, "could not run" and
 *    "found nothing" were identical. note_error() now writes the failure into
 *    the same file, so the box has to render it, and render it as a FAILURE.
 *
 * 2. NOT REBUILDING UNCHANGED CONTENT. renderJob() repaints the detail every
 *    2s. Rewriting the box on every pass destroys a text selection mid-drag
 *    and makes Copy unclickable — on the one string an operator is racing to
 *    paste into a scoreboard.
 *
 * Run:
 *   node scripts/test_flag_grain_ui.js
 *   node scripts/test_flag_grain_ui.js --mutate rebuild-every-poll
 */
const fs = require("fs");
const path = require("path");

let JSDOM;
try {
  ({ JSDOM } = require("jsdom"));
} catch (e) {
  console.log("SKIP: jsdom not installed");
  process.exit(0);
}

const MUTATIONS = [
  "none",
  "rebuild-every-poll",   // the cache guard is dropped; the DOM churns
  "errors-render-plain",  // a failure row looks like a finding
  "shows-empty-box",      // an empty box appears on every job
  "flag-not-selectable",  // user-select:all removed from the flag
  "no-box",               // the markup is never emitted
  "cache-ignores-dom",    // the guard trusts the text alone; a rebuilt box stays empty
  "tally-counts-as-error", // the drain summary is tallied as a failure
  "tally-row-swallowed",  // the summary is written but never shown
  "dropped-not-flagged",  // lost candidates render as quietly as a clean run
  "missing-accepted-zero", // an unrecorded count is printed as a real zero
  "no-grain-adoption",    // the panel is rebuilt every poll and visibly blinks
];
const _mi = process.argv.indexOf("--mutate");
const MUTATE = _mi > -1 ? process.argv[_mi + 1] : "none";
if (!MUTATIONS.includes(MUTATE)) {
  console.error(`unknown mutation ${MUTATE}; one of ${MUTATIONS.join(", ")}`);
  process.exit(2);
}

const ROOT = path.resolve(__dirname, "..");
let appjs = fs.readFileSync(path.join(ROOT, "web-ui/app.js"), "utf8");
let css = fs.readFileSync(path.join(ROOT, "web-ui/style.css"), "utf8");

let PASS = 0, FAIL = 0;
function check(label, got, want) {
  const a = JSON.stringify(got), b = JSON.stringify(want);
  if (a === b) PASS++;
  else { FAIL++; console.log(`FAIL  ${label}\n        got  = ${a}\n        want = ${b}`); }
}

const _a0 = appjs, _c0 = css;
if (MUTATE === "rebuild-every-poll") {
  // Drop the guard entirely: every poll repaints, so a surviving node is
  // replaced under the operator's cursor.
  appjs = appjs.replace(
    "  if (_GRAIN_CACHE.get(id) === text && list && list.children.length) return;\n", "");
} else if (MUTATE === "errors-render-plain") {
  appjs = appjs.replace('  if ("error" in f || line.startsWith("error\\t")) {', "  if (false) {");
} else if (MUTATE === "shows-empty-box") {
  appjs = appjs.replace("  if (!lines.length) { box.hidden = true; return; }", "  if (!lines.length) { box.hidden = false; }");
} else if (MUTATE === "flag-not-selectable") {
  css = css.replace("  user-select: all;\n", "");
} else if (MUTATE === "cache-ignores-dom") {
  appjs = appjs.replace(
    "  if (_GRAIN_CACHE.get(id) === text && list && list.children.length) return;",
    "  if (_GRAIN_CACHE.get(id) === text) return;");
} else if (MUTATE === "tally-counts-as-error") {
  appjs = appjs.replace(
    'const errs = lines.filter((l) => l.startsWith("error\\t")).length;',
    "const errs = lines.length - flags;");
} else if (MUTATE === "tally-row-swallowed") {
  appjs = appjs.replace('if (line.startsWith("tally\\t")) {', "if (false) {");
} else if (MUTATE === "dropped-not-flagged") {
  appjs = appjs.replace('is-tally${drop ? " is-lost" : ""}', "is-tally");
} else if (MUTATE === "missing-accepted-zero") {
  appjs = appjs.replace(
    'escapeHtml(f.accepted === undefined ? "?" : f.accepted)',
    'escapeHtml(f.accepted || "0")');
} else if (MUTATE === "no-grain-adoption") {
  appjs = appjs.replace(
    "  if (_keptGrain) {\n"
    + "    const _freshG = detail.querySelector(`.flag-grain[data-job=\"${(window.CSS && CSS.escape) ? CSS.escape(id) : id}\"]`);\n"
    + "    if (_freshG) _freshG.replaceWith(_keptGrain);\n"
    + "  }\n", "");
} else if (MUTATE === "no-box") {
  appjs = appjs.replace('      <div class="flag-grain" data-job="${escapeHtml(id)}" hidden>', '      <div class="not-the-box" hidden>');
}
if (MUTATE !== "none" && appjs === _a0 && css === _c0) {
  console.error(`MUTATION ${MUTATE} CHANGED NOTHING — its anchor no longer matches.`);
  process.exit(2);
}

// --------------------------------------------------------------------------
// Pull the two pure functions out and drive them against a real DOM.
// --------------------------------------------------------------------------
const dom = new JSDOM(`<!doctype html><body>
  <div class="flag-grain" data-job="J" hidden>
    <div class="flag-grain-bar"><span class="flag-grain-title">flag_grain</span>
      <span class="flag-grain-count"></span></div>
    <div class="flag-grain-list"></div>
  </div></body>`, { url: "http://localhost/" });
const { window } = dom;
global.window = window; global.document = window.document;
global.navigator = window.navigator;

let FETCHED = 0, BODY = "";
global.fetch = async () => { FETCHED++; return { ok: BODY !== null, text: async () => BODY }; };

const sandbox = {
  API: "/api", document: window.document, window, fetch: global.fetch,
  escapeHtml: (s) => String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])),
  Map, Math, Object, parseFloat, setTimeout, navigator: window.navigator,
  encodeURIComponent, JSON, String, RegExp,
};
function grab(name) {
  // Anchor on the LINE START so an `async function` keeps its `async` — the
  // first draft sliced from "function <name>(" and produced a body full of
  // `await` in a non-async function.
  const re = new RegExp(`^(?:async )?function ${name}\\(`, "m");
  const m = re.exec(appjs);
  if (!m) throw new Error(`could not locate ${name} in app.js`);
  const i = m.index;
  const j = appjs.indexOf("\n\n", appjs.indexOf("\n}", i));
  return appjs.slice(i, j > -1 ? j : undefined);
}
const src = "const _GRAIN_CACHE = new Map();\n"
  + grab("_grainRow") + "\n" + grab("mountFlagGrain")
  + "\nreturn { _grainRow, mountFlagGrain, _GRAIN_CACHE };";
const api = new Function(...Object.keys(sandbox), src)(...Object.values(sandbox));

const BOX_HTML = `<div class="flag-grain" data-job="J" hidden>
    <div class="flag-grain-bar"><span class="flag-grain-title">flag_grain</span>
      <span class="flag-grain-count"></span></div>
    <div class="flag-grain-list"></div>
  </div>`;
// renderJob() rewrites detail.innerHTML every 2s and carries only `.job-files`
// across, so this box is a NEW EMPTY element on every poll. The first version
// of this suite reused one persistent node and therefore could not see the
// defect it was written to prevent: a text-only cache guard unhid an empty box
// forever after the first paint.
function rebuildBox() {
  window.document.body.innerHTML = BOX_HTML;
  return window.document.querySelector(".flag-grain");
}
let box = window.document.querySelector(".flag-grain");
const FLAG = "INCOGNITO{INCOGNITOEXAMPLEVALUENOTREALzzxx}";
const GRAIN = `flag=${FLAG}\tconfidence=0.92\tat=14:26:32\twhy=appears in run message output\tsources=main/message,run.log`;
const ERRLINE = "error\tat=14:21:15\tdetail=tool_use_in_text_only_role: grok attempted `Web search:`";
// The drain summary. Job e18c947b1a74 is the real one: a TimeoutError sat in
// the same file, and only these counts said it was one retry out of seven that
// the loop absorbed rather than a dead adjudicator.
const TALLY_OK = "tally\tat=14:30:01\tadjudicated=6\taccepted=1\tfailed=1\tdropped=0";
const TALLY_LOST = "tally\tat=14:30:01\tadjudicated=3\taccepted=0\tfailed=9\tdropped=3";
// Written before the field was renamed: three such lines are on disk.
const TALLY_OLD = "tally\tat=14:30:01\tadjudicated=6\twith_findings=6\tfailed=1\tdropped=0";

// A suite that THROWS must never read as a pass. On this Node an unhandled
// promise rejection leaves the exit code at 0, so `errors-render-plain` bit
// every check it was written for and the sweep still recorded an escape.
process.on("unhandledRejection", (e) => {
  console.log(`FAIL  the suite threw: ${e && e.message}`);
  process.exit(1);
});

(async () => {
  // --- the box is emitted at all -----------------------------------------
  check("the markup names the box and binds it to the job",
    /class="flag-grain" data-job="\$\{escapeHtml\(id\)\}"/.test(appjs), true);
  check("...and it sits under the directory browser, not above it",
    appjs.indexOf('class="job-files-list"') < appjs.indexOf('class="flag-grain"'), true);
  check("...and is mounted next to the file browser",
    /mountJobFiles\(id\);\s*\n\s*mountFlagGrain\(id\);/.test(appjs), true);

  // --- the panel must SURVIVE the 2s rebuild, not be recreated -----------
  // renderJob re-assigns detail.innerHTML on every poll. The rebuilt markup
  // starts `hidden` with an empty list and mountFlagGrain only unhides it
  // AFTER an awaited fetch, so a panel that is not carried across vanishes
  // and returns twice a second. Reported from the operator's screen while
  // job 04ddd2ead5a1 ran: "flag grain이 정신없이 주기적으로 깜빡거림".
  // `.job-files` already had this treatment; `.flag-grain` did not.
  check("the live grain node is captured before the rebuild",
    /const _keptGrain = detail\.querySelector\(`\.flag-grain\[data-job=/.test(appjs), true);
  check("...and moved into the rebuilt tree, the way .job-files is",
    /if \(_keptGrain\) \{[\s\S]{0,260}?_freshG\.replaceWith\(_keptGrain\)/.test(appjs), true);
  check("...job-guarded, so job A's rows cannot land in job B's panel",
    (appjs.match(/\.flag-grain\[data-job=/g) || []).length >= 3, true);

  // --- no file: stay out of the way --------------------------------------
  BODY = "";
  await api.mountFlagGrain("J");
  check("no flag_grain.txt -> the box stays hidden", box.hidden, true);

  // --- a finding ----------------------------------------------------------
  BODY = GRAIN + "\n";
  await api.mountFlagGrain("J");
  check("a finding reveals the box", box.hidden, false);
  check("...the flag text is rendered",
    box.querySelector(".flag-grain-flag").textContent, FLAG);
  check("...with a copy button carrying the exact string",
    box.querySelector(".flag-grain-copy").dataset.flag, FLAG);
  check("...confidence shown as a percentage",
    box.querySelector(".flag-grain-conf").textContent, "92%");
  check("...and the count reads one flag",
    box.querySelector(".flag-grain-count").textContent, "1 flag");
  check("no error row for a clean file",
    box.querySelectorAll(".flag-grain-row.is-error").length, 0);

  // --- an unchanged poll must not churn a SURVIVING node ------------------
  const before = box.querySelector(".flag-grain-list").innerHTML;
  const node = box.querySelector(".flag-grain-flag");
  await api.mountFlagGrain("J");
  check("an unchanged poll leaves a surviving node alone",
    box.querySelector(".flag-grain-list").innerHTML, before);
  check("...and does not replace it (selection/copy survive mid-drag)",
    box.querySelector(".flag-grain-flag") === node, true);

  // --- ...but a REBUILT box must be refilled ------------------------------
  // The real page throws this element away every 2s. Same file content, brand
  // new empty box: the rows have to come back or the operator watches an empty
  // panel for the rest of the run.
  box = rebuildBox();
  await api.mountFlagGrain("J");
  check("a rebuilt box is repainted even though the file did not change",
    box.querySelector(".flag-grain-flag") ? box.querySelector(".flag-grain-flag").textContent : "",
    FLAG);
  check("...and is visible", box.hidden, false);
  check("...and the count is restored too",
    box.querySelector(".flag-grain-count").textContent, "1 flag");

  // --- a failure is a FAILURE --------------------------------------------
  BODY = GRAIN + "\n" + ERRLINE + "\n";
  await api.mountFlagGrain("J");
  const errs = box.querySelectorAll(".flag-grain-row.is-error");
  check("an adjudication failure renders as an error row", errs.length, 1);
  // Index defensively: when the error branch is gone there is no row, and a
  // throw here would be reported as a crash instead of the failure it is.
  check("...carrying the reason the operator needs",
    /tool_use_in_text_only_role/.test(errs[0] ? errs[0].textContent : ""), true);
  check("...and is counted apart from findings",
    box.querySelector(".flag-grain-count").textContent, "1 flag · 1 error");
  check("the finding is still shown alongside it",
    box.querySelectorAll(".flag-grain-row:not(.is-error)").length, 1);

  // --- the drain tally ---------------------------------------------------
  BODY = GRAIN + "\n" + ERRLINE + "\n" + TALLY_OK + "\n";
  box = rebuildBox();
  await api.mountFlagGrain("J");
  const tal = box.querySelectorAll(".flag-grain-row.is-tally");
  check("the drain tally renders as its own row", tal.length, 1);
  check("...carrying all four counts",
    /adjudicated 6 · accepted 1 · failed 1 · dropped 0/.test(tal[0] ? tal[0].textContent : ""),
    true);
  // THE regression this section exists for. `errs = lines.length - flags`
  // counted the summary as a failure, so a healthy run with one absorbed
  // retry reported twice the errors it had.
  check("...and is NOT counted as an error",
    box.querySelector(".flag-grain-count").textContent, "1 flag · 1 error");
  check("the error row is still its own thing",
    box.querySelectorAll(".flag-grain-row.is-error").length, 1);
  // Lines written before `accepted` existed carried `with_findings`, which
  // counted something else. Folding a missing field to 0 would print a wrong
  // number for the three runs already on disk, so it reads "?" instead.
  BODY = GRAIN + "\n" + TALLY_OLD + "\n";
  box = rebuildBox();
  await api.mountFlagGrain("J");
  const oldrow = box.querySelector(".flag-grain-row.is-tally");
  check("a pre-`accepted` tally does not invent a zero",
    /accepted \?/.test(oldrow ? oldrow.textContent : ""), true);
  check("...while still showing the counts it does have",
    /adjudicated 6 · accepted \? · failed 1 · dropped 0/.test(oldrow ? oldrow.textContent : ""),
    true);

  BODY = GRAIN + "\n" + ERRLINE + "\n" + TALLY_OK + "\n";
  box = rebuildBox();
  await api.mountFlagGrain("J");
  const tal2 = box.querySelectorAll(".flag-grain-row.is-tally");
  check("a clean tally is not styled as a loss",
    tal2[0] ? tal2[0].classList.contains("is-lost") : true, false);

  // dropped > 0 is the only number that means candidates are gone for good:
  // a failure the retry loop absorbed lost nothing.
  BODY = GRAIN + "\n" + TALLY_LOST + "\n";
  box = rebuildBox();
  await api.mountFlagGrain("J");
  const lost = box.querySelector(".flag-grain-row.is-tally");
  check("a dropped batch is called out, not left quiet",
    lost ? lost.classList.contains("is-lost") : false, true);
  check("...and the file with no error line still reports zero errors",
    box.querySelector(".flag-grain-count").textContent, "1 flag");
  check("the stylesheet actually distinguishes a loss",
    /\.flag-grain-row\.is-tally\.is-lost[^}]*\}/.test(css), true);

  // --- the flag must be selectable as one unit ---------------------------
  check("the flag is selectable as a whole (paste under time pressure)",
    /\.flag-grain-flag\s*\{[^}]*user-select:\s*all/.test(css), true);
  check("...and error rows are styled apart from findings",
    /\.flag-grain-row\.is-error/.test(css), true);

  console.log(`\n${PASS + FAIL} checks, ${FAIL} failed`);
  process.exit(FAIL ? 1 : 0);
})().catch((e) => {
  console.log(`FAIL  the suite threw: ${e && e.message}`);
  process.exit(1);
});
