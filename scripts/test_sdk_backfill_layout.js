/**
 * Replaying the live-agent feed must not force a layout per event.
 *
 * WHY THIS EXISTS
 *
 * The operator reported the job panel laggy on entry FOUR times. Three rounds
 * of fixes missed, and each miss has the same cause: every measurement
 * available from the server side said the entry was fast.
 *
 *     server handlers            4-61 ms
 *     real HTTP round trips       1-9 ms   (the three entry fetches ~13 ms)
 *     whole SSE stream over HTTP    28 ms   (first sdk event at 8.5 ms)
 *     renderJob, timed in the browser with performance.now()   65 ms
 *     what the operator saw                                 ~3,000 ms
 *
 * performance.now() stops when the task ends. Style, layout and paint happen
 * after it, on the same thread, and nothing else runs until they finish — so a
 * fast script in front of a slow frame reports 65 ms and feels like three
 * seconds. jsdom cannot see that half at all.
 *
 * WHAT IT WAS
 *
 * Opening a job replays up to 400 sdk events, and each went through
 * _renderSdkEvent, which per event did a document-wide querySelector and FOUR
 * geometry reads — scrollTop, clientHeight and scrollHeight before the append,
 * scrollHeight again after. A geometry read invalidates layout for the WHOLE
 * document, not the subtree, which is why the cost hid from every measurement
 * taken against the panel alone.
 *
 * Measured in real Chrome 148, real style.css, the real 400 payloads from
 * job 19cf9578a0fc:
 *
 *     panel only        (1,182 elements)      39 ms
 *     with the page     (2,316 elements)   1,370 ms      35x
 *     after this fix    (2,316 elements)       8 ms     152x
 *
 * Both reported symptoms follow from it. "LIVE AGENT ACTIVITY가 안뜨고 3초후에
 * 렉이 풀리면서 뜸" — the panel is the thing the loop is building, so it lands
 * last. And "job directory도 loading... 에서 3초후 디렉토리가 보이네" — the
 * directory fetch had already returned; its callback could not run while the
 * main thread was doing 1,600 forced layouts.
 *
 * Only the last _SDK_MAX_LINES rows survive the trim, so 340 of the 400 were
 * built, laid out and destroyed for nothing.
 *
 * WHAT THIS GUARDS
 *
 * The cost is geometry reads, so that is what this counts — with instrumented
 * accessors on the feed element, not by timing, which jsdom cannot do honestly.
 *
 * The one thing that must NOT be done is the obvious fix. The log and monitor
 * handlers drop their backfill with `if (payload.backfill) return;`, but
 * _renderSdkEvent is the ONLY thing that ever un-hides this panel or puts a row
 * in it — renderJob ships it empty and `hidden`. Guarding it the same way would
 * leave a permanently blank box on every finished job. B3/B4 pin that.
 *
 * Run:
 *   node scripts/test_sdk_backfill_layout.js
 *   node scripts/test_sdk_backfill_layout.js --mutate per-event-backfill
 */
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const MUTATIONS = [
  "none",
  "per-event-backfill",  // the backfill goes through _renderSdkEvent again
  "bare-guard",          // the "obvious" fix: drop it, and the panel stays empty
  "batch-not-called",    // events are buffered and then never drawn
  "batch-reads-per-row",  // the batch measures inside its loop, undoing the win
  "batch-renders-all",   // all 400 rows are built, though only 60 survive
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

if (MUTATE === "per-event-backfill") {
  app = app.replace("      if (payload && payload.backfill) sdkBuf.push(payload);\n"
                  + "      else _renderSdkEvent(id, payload);",
                    "      _renderSdkEvent(id, payload);");
} else if (MUTATE === "bare-guard") {
  app = app.replace("      if (payload && payload.backfill) sdkBuf.push(payload);\n"
                  + "      else _renderSdkEvent(id, payload);",
                    "      if (payload && payload.backfill) return;\n"
                  + "      _renderSdkEvent(id, payload);");
} else if (MUTATE === "batch-not-called") {
  app = app.replace("    try { _renderSdkBatch(id, sdkBuf.splice(0)); } catch (_) {}\n", "");
} else if (MUTATE === "batch-reads-per-row") {
  app = app.replace("    const el = document.createElement(\"div\");\n"
                  + "    _fillSdkRow(el, p);\n"
                  + "    frag.appendChild(el);",
                    "    const el = document.createElement(\"div\");\n"
                  + "    _fillSdkRow(el, p);\n"
                  + "    feed.scrollTop = feed.scrollHeight;\n"
                  + "    frag.appendChild(el);");
} else if (MUTATE === "batch-renders-all") {
  app = app.replace("  const keep = payloads.slice(-_SDK_MAX_LINES);", "  const keep = payloads;");
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

function slice(startRe, endRe) {
  const L = app.split("\n");
  const a = L.findIndex((l) => startRe.test(l));
  const b = L.findIndex((l, i) => i > a && endRe.test(l));
  if (a < 0 || b < 0) throw new Error(`slice not found: ${startRe} .. ${endRe}`);
  return L.slice(a, b).join("\n");
}

function ctx() {
  const dom = new JSDOM(
    `<div class="sdk-live" data-job-id="J" hidden><div class="sdk-live-feed"></div></div>`);
  const doc = dom.window.document;
  const api = new Function(
    "document", "window", "_sdkLiveHidden",
    slice(/^const _SDK_MAX_LINES/, /^function _appendLiveLogLine/) + "\n" +
    slice(/^function escapeHtml\(/, /^function _highlightLogHtml/) + "\n" +
    "return { _renderSdkEvent, _renderSdkBatch: typeof _renderSdkBatch !== 'undefined'"
    + " ? _renderSdkBatch : null, _SDK_MAX_LINES };",
  )(doc, dom.window, false);

  // Count the reads that force layout. This is the cost, so it is what the
  // suite measures — jsdom cannot time a real one.
  const feed = doc.querySelector(".sdk-live-feed");
  const counts = { reads: 0, removed: 0 };
  // Rows built and then thrown away. The final DOM is identical either way, so
  // only the discarded work distinguishes "render the last 60" from "render all
  // 400 and trim" — and the 340 wasted rows are the whole point of the fix.

  const origRemove = feed.removeChild.bind(feed);
  feed.removeChild = (n) => { counts.removed++; return origRemove(n); };
  for (const prop of ["scrollTop", "scrollHeight", "clientHeight"]) {
    let v = 0;
    Object.defineProperty(feed, prop, {
      configurable: true,
      get() { counts.reads++; return v; },
      set(x) { v = x; },
    });
  }
  return { api, doc, feed, counts, dom };
}

const evs = (n, backfill) => Array.from({ length: n }, (_, i) => ({
  kind: "text", tag: "main", text: `event ${i}`, backfill: !!backfill,
}));

// Drive the real listener wiring by extracting it from _openLiveStream, so the
// test exercises the code that actually runs rather than a paraphrase of it.
function runStream({ api, doc }, backfillEvents, liveEvents) {
  const buf = [];
  const src = slice(/^function _openLiveStream/, /^function _closeLiveStream/);
  const buffers = /if \(payload && payload\.backfill\) sdkBuf\.push\(payload\);/.test(src);
  const bare = /if \(payload && payload\.backfill\) return;/.test(src);
  const drawsOnDone = /_renderSdkBatch\(id, sdkBuf\.splice\(0\)\)/.test(src);
  for (const p of backfillEvents) {
    if (bare) continue;
    if (buffers) buf.push(p); else api._renderSdkEvent("J", p);
  }
  for (const p of liveEvents || []) api._renderSdkEvent("J", p);
  if (drawsOnDone && api._renderSdkBatch) api._renderSdkBatch("J", buf.splice(0));
  return { buffers, bare, drawsOnDone };
}

// --- B: the backfill is drawn once ----------------------------------------
{
  console.log("\nB — 400 replayed events cost one layout, not four hundred");
  const c = ctx();
  const shape = runStream(c, evs(400, true), []);
  check("B1 the panel ends up visible", c.doc.querySelector(".sdk-live").hidden, false);
  // The regression the obvious fix would cause: _renderSdkEvent is the only
  // thing that un-hides this panel, so dropping the backfill empties it.
  check("B2 ...and populated", c.feed.children.length > 0);
  check("B3 ...to exactly the cap, not 400 rows",
        c.feed.children.length, c.api._SDK_MAX_LINES);
  check("B4 ...keeping the NEWEST events",
        c.feed.lastChild.textContent.includes("event 399"));
  check("B5 ...and dropping the oldest",
        c.feed.textContent.includes("event 0 "), false);
  // The headline. 400 events x 4 reads was 1,600; one pass is a handful.
  console.log(`        geometry reads for 400 backfilled events: ${c.counts.reads}`);
  check("B6 geometry reads do not scale with the replay", c.counts.reads <= 10);
  // Rendering all 400 and trimming leaves the same DOM, so the only way to see
  // it is the discarded work: 340 rows built, laid out and removed.
  console.log(`        rows built then discarded: ${c.counts.removed}`);
  check("B7 ...and neither does the number of rows built",
        c.counts.removed, 0);
}

// --- L: live events are unchanged -----------------------------------------
{
  console.log("\nL — a live event still renders immediately");
  const c = ctx();
  runStream(c, [], evs(3, false));
  check("L1 live events appear without waiting for a batch",
        c.feed.children.length, 3);
  check("L2 ...and still keep the feed pinned to the bottom", c.counts.reads > 0);
  // A live event arriving DURING the backfill must not be lost when the batch
  // lands: the batch appends, it does not replace.
  const c2 = ctx();
  const buf = evs(10, true);
  c2.api._renderSdkEvent("J", { kind: "text", tag: "main", text: "live-mid" });
  c2.api._renderSdkBatch("J", buf);
  check("L3 a live event during the backfill survives it",
        c2.feed.textContent.includes("live-mid"));
}

// --- S: the wiring, not just the helper ------------------------------------
{
  console.log("\nS — the stream actually uses it");
  const src = slice(/^function _openLiveStream/, /^function _closeLiveStream/);
  check("S1 backfilled sdk events are buffered",
        /if \(payload && payload\.backfill\) sdkBuf\.push\(payload\);/.test(src));
  check("S2 ...and drawn on backfill_done",
        /_renderSdkBatch\(id, sdkBuf\.splice\(0\)\)/.test(src));
  check("S3 ...while live ones go straight through",
        /else _renderSdkEvent\(id, payload\);/.test(src));
  // Both paths must build the same row, or the backfill and the live feed
  // drift apart in appearance.
  check("S4 one row builder serves both paths",
        /function _sdkRowHtml\(/.test(app)
        && (app.match(/_fillSdkRow\(/g) || []).length >= 3);
}

console.log(`\n${PASS + FAIL} checks, ${FAIL} failed`);
process.exit(FAIL ? 1 : 0);
