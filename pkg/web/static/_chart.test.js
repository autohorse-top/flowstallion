// _chart.test.js — node --test suite for chart.js (TASK 2026-10-29-charts, C6).
//
// The leading underscore is intentional: `//go:embed static` (without `all:`)
// excludes files starting with '_', so this file is never shipped by the
// console. Verified live: GET /static/_chart.test.js -> 404 (smoke-charts.sh).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const PHChart = require("./chart.js");

const BAD = /NaN|Infinity/;
const DAYS7 = [
  "2026-10-23", "2026-10-24", "2026-10-25", "2026-10-26",
  "2026-10-27", "2026-10-28", "2026-10-29",
];

test("UMD export exposes the four builders", () => {
  for (const k of ["svgStacked", "svgCostBars", "legend", "fmtShort"]) {
    assert.equal(typeof PHChart[k], "function", "missing " + k);
  }
});

test("svgStacked: mixed buckets -> clipPath/flowstallion-seg/flowstallion-total, tooltip, no NaN", () => {
  const days = ["2026-10-22", "2026-10-23"];
  const buckets = {
    "2026-10-22": { success: 3, failed: 1, running: 0, other: 0 },
    "2026-10-23": { success: 0, failed: 0, running: 2, other: 1 },
  };
  const out = PHChart.svgStacked(days, buckets);
  assert.ok(out.includes('viewBox="0 0 920 240"'), "canvas geometry");
  assert.ok(out.includes('aria-label="runs per day by status"'), "a11y label");
  assert.ok(out.includes("flowstallion-clip-"), "missing column clipPath");
  assert.ok(out.includes('class="flowstallion-seg"'), "missing segment rect class");
  assert.ok(out.includes('class="flowstallion-total"'), "missing daily total label");
  assert.ok(out.includes("animation-delay:35ms"), "staggered entry delay (day i=1)");
  assert.ok(out.includes("2026-10-22 — success: 3"), "tooltip wording kept");
  assert.ok(!BAD.test(out), "NaN/Infinity leaked into SVG");
  assert.ok(!out.includes("No runs"), "empty-state text must not appear");
});

test("svgStacked: all-zero -> baseline kept, centered message, no rects", () => {
  const out = PHChart.svgStacked(DAYS7, {});
  assert.ok(out.includes("No runs in the last 7 days"), "empty-state text");
  assert.ok(out.includes('stroke="#d0d7de"'), "baseline line kept");
  assert.ok(!out.includes("<rect"), "no rect expected in empty state");
  assert.ok(!BAD.test(out), "NaN/Infinity leaked into SVG");
});

test("svgCostBars: [0, 0.0108, 1.5] -> clipPath, fmtShort labels, zero day silent", () => {
  const days = ["2026-10-27", "2026-10-28", "2026-10-29"];
  const out = PHChart.svgCostBars(days, [0, 0.0108, 1.5]);
  assert.ok(out.includes('viewBox="0 0 920 240"'), "canvas geometry");
  assert.ok(out.includes('aria-label="cost per day in USD"'), "a11y label");
  assert.ok(out.includes("flowstallion-c-"), "missing cost clipPath");
  assert.ok(out.includes("flowstallion-seg flowstallion-bar"), "cost bar class");
  assert.ok(out.includes("$0.0108"), "fmtShort value label for 0.0108");
  assert.ok(out.includes("$1.50"), "fmtShort value label for 1.5");
  assert.ok(!out.includes("$0.0000"), "zero day must have no value label");
  assert.ok(out.includes("2026-10-28: $0.0108"), "tooltip keeps full precision");
  assert.ok(!BAD.test(out), "NaN/Infinity leaked into SVG");
});

test("svgCostBars: all-zero -> centered message, no rects", () => {
  const out = PHChart.svgCostBars(DAYS7, [0, 0, 0, 0, 0, 0, 0]);
  assert.ok(out.includes("No cost in the last 7 days"), "empty-state text");
  assert.ok(!out.includes("<rect"), "no rect expected in empty state");
  assert.ok(!BAD.test(out), "NaN/Infinity leaked into SVG");
});

test("legend: structure + HTML-escaped labels", () => {
  const out = PHChart.legend([{ color: "#1a7f37", label: '<b>&"x"' }]);
  assert.ok(out.startsWith('<div class="legend">'), "legend wrapper");
  assert.ok(out.includes('<span class="legend-item">'), "legend item");
  assert.ok(out.endsWith("</div>"), "legend close");
  assert.ok(out.includes("&lt;b&gt;&amp;&quot;x&quot;"), "label HTML-escaped");
  assert.ok(out.includes('style="background:#1a7f37"'), "swatch inline color");
});

test("fmtShort: boundary values", () => {
  assert.equal(PHChart.fmtShort(0.9999), "$0.9999");
  assert.equal(PHChart.fmtShort(1), "$1.00");
  assert.equal(PHChart.fmtShort(100), "$100.00");
});

// Palette v2 pin (TASK 2026-10-29-chart-palette): the four stacked-bar
// fills and the cost-bar fill must use the lighter GitHub-light hues, and
// the legacy dark fills must be gone. Data below keeps all four buckets
// non-zero on a 7-day window so every v2 fill appears in the output.
const PALETTE_V2 = ["#2da44e", "#d73a49", "#388bfd", "#8c959f"];
const PALETTE_V1 = ["#1a7f37", "#cf222e", "#0969da"];

test("palette v2: svgStacked uses v2 fills only (all four buckets non-zero)", () => {
  const buckets = {};
  for (const d of DAYS7) {
    buckets[d] = { success: 3, failed: 2, running: 1, other: 1 };
  }
  const out = PHChart.svgStacked(DAYS7, buckets);
  for (const c of PALETTE_V2) {
    assert.ok(out.includes('fill="' + c + '"'), "missing v2 fill " + c);
  }
  for (const c of PALETTE_V1) {
    assert.ok(!out.includes(c), "legacy fill " + c + " still in svgStacked output");
  }
});

test("palette v2: svgCostBars bar fill is #388bfd (no #0969da)", () => {
  const out = PHChart.svgCostBars(DAYS7, [1.25, 0.4, 2.0, 0.1, 0.8, 0.05, 1.5]);
  assert.ok(out.includes('fill="#388bfd"'), "cost bar must use v2 blue fill");
  assert.ok(!out.includes("#0969da"), "legacy dark blue still in svgCostBars output");
});
