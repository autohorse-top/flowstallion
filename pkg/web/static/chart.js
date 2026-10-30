// FlowStallion console — chart builders (TASK 2026-10-29-charts).
//
// Pure string-building: no DOM access, no dependencies. The UMD wrapper
// exposes the builders as the browser global PHChart (loaded before
// app.js) and as module.exports under node, so the SVG geometry can be
// unit-tested with `node --test`.
(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory();
  } else {
    root.PHChart = factory();
  }
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  // Compact USD label: >= $1 keeps 2 decimals, smaller values keep 4
  // (per-run costs are usually far below a dollar).
  function fmtShort(v) {
    v = Number(v) || 0;
    return v >= 1 ? "$" + v.toFixed(2) : "$" + v.toFixed(4);
  }

  // Layout constants, fixed by TASK §3.
  var W = 920, H = 240, padT = 26, padB = 28, padR = 12;
  var innerH = H - padT - padB;

  // Baseline (solid). Kept even in the empty state.
  function baseline(padL, baseY) {
    return '<line x1="' + padL + '" y1="' + baseY + '" x2="' + (W - padR) +
      '" y2="' + baseY + '" stroke="#d0d7de"/>';
  }

  // 50% and 100% gridlines (dashed).
  function midTopGrid(padL) {
    var midY = padT + innerH / 2;
    return '<line x1="' + padL + '" y1="' + midY + '" x2="' + (W - padR) +
      '" y2="' + midY + '" stroke="#d8dee4" stroke-dasharray="3 4"/>' +
      '<line x1="' + padL + '" y1="' + padT + '" x2="' + (W - padR) +
      '" y2="' + padT + '" stroke="#d8dee4" stroke-dasharray="3 4"/>';
  }

  // Left axis labels at 0 / mid / max (10px muted).
  function axisLabels(padL, labels) {
    var baseY = padT + innerH;
    return '<text x="' + (padL - 6) + '" y="' + (baseY + 3) +
      '" font-size="10" fill="#656d76" text-anchor="end">' + labels[0] + "</text>" +
      '<text x="' + (padL - 6) + '" y="' + (padT + innerH / 2 + 3) +
      '" font-size="10" fill="#656d76" text-anchor="end">' + labels[1] + "</text>" +
      '<text x="' + (padL - 6) + '" y="' + (padT + 3) +
      '" font-size="10" fill="#656d76" text-anchor="end">' + labels[2] + "</text>";
  }

  // X-axis date label ("MM-DD").
  function dateLabel(x, d) {
    return '<text x="' + x + '" y="' + (H - 8) + '" font-size="10" fill="#656d76"' +
      ' text-anchor="middle">' + esc(String(d).slice(5)) + "</text>";
  }

  // Centered empty-state message (12px muted).
  function emptyMsg(msg) {
    return '<text x="' + (W / 2) + '" y="' + (padT + innerH / 2) +
      '" font-size="12" fill="#656d76" text-anchor="middle">' + msg + "</text>";
  }

  // svgStacked: 7-day stacked bars by status.
  // days: ["YYYY-MM-DD", ...]; buckets: { "YYYY-MM-DD": {success,failed,running,other} }.
  function svgStacked(days, buckets) {
    var padL = 34;
    var innerW = W - padL - padR;
    var slot = innerW / 7;
    var barW = slot * 0.5;
    var baseY = padT + innerH;
    var order = ["success", "failed", "running", "other"];
    var colors = {
      success: "#2da44e",
      failed: "#d73a49",
      running: "#388bfd",
      other: "#8c959f",
    };
    var totals = days.map(function (d) {
      var b = (buckets && buckets[d]) || {};
      var t = 0;
      order.forEach(function (k) { t += Number(b[k]) || 0; });
      return t;
    });
    // Round the axis max up to an even count so the 0/mid/max labels are ints.
    var max = Math.max(1, Math.max.apply(null, totals));
    if (max % 2 !== 0) max += 1;
    var hasData = totals.some(function (t) { return t > 0; });

    var s = '<svg viewBox="0 0 ' + W + " " + H + '" role="img" ' +
      'aria-label="runs per day by status" style="width:100%;height:auto">';
    s += baseline(padL, baseY);
    if (hasData) {
      s += midTopGrid(padL);
      s += axisLabels(padL, ["0", String(max / 2), String(max)]);
    } else {
      s += emptyMsg("No runs in the last 7 days");
    }
    days.forEach(function (d, i) {
      var total = totals[i];
      var x = padL + i * slot + (slot - barW) / 2;
      if (total > 0) {
        var colH = (total / max) * innerH;
        var colTop = padT + innerH - colH;
        s += '<clipPath id="flowstallion-clip-' + i + '"><rect x="' + x + '" y="' + colTop +
          '" width="' + barW + '" height="' + colH + '" rx="5"/></clipPath>';
        s += '<g class="flowstallion-bar" style="animation-delay:' + i * 35 + 'ms"' +
          ' clip-path="url(#flowstallion-clip-' + i + ')">';
        var b = (buckets && buckets[d]) || {};
        var y = baseY;
        order.forEach(function (k) {
          var n = Number(b[k]) || 0;
          if (!n) return;
          var h = (n / max) * innerH;
          y -= h;
          s += '<rect class="flowstallion-seg" x="' + x + '" y="' + y + '" width="' + barW +
            '" height="' + h + '" fill="' + colors[k] + '"><title>' + esc(d) +
            " — " + k + ": " + n + "</title></rect>";
        });
        s += "</g>";
        s += '<text class="flowstallion-total" x="' + (x + barW / 2) + '" y="' + (colTop - 6) +
          '" font-size="11" text-anchor="middle">' + total + "</text>";
      }
      s += dateLabel(padL + i * slot + slot / 2, d);
    });
    s += "</svg>";
    return s;
  }

  // svgCostBars: 7-day single-series cost bars (USD).
  // days: ["YYYY-MM-DD", ...]; values: [costUsd, ...] aligned by index.
  function svgCostBars(days, values) {
    var padL = 44;
    var innerW = W - padL - padR;
    var slot = innerW / 7;
    var barW = slot * 0.5;
    var baseY = padT + innerH;
    var vals = (values || []).map(function (v) {
      var n = Number(v);
      return n > 0 ? n : 0; // NaN / negative / zero -> 0
    });
    var max = Math.max(0.0001, Math.max.apply(null, vals));
    var hasData = vals.some(function (v) { return v > 0; });

    var s = '<svg viewBox="0 0 ' + W + " " + H + '" role="img" ' +
      'aria-label="cost per day in USD" style="width:100%;height:auto">';
    s += baseline(padL, baseY);
    if (hasData) {
      s += midTopGrid(padL);
      s += axisLabels(padL, ["0", fmtShort(max / 2), fmtShort(max)]);
    } else {
      s += emptyMsg("No cost in the last 7 days");
    }
    days.forEach(function (d, i) {
      var v = vals[i] || 0;
      var x = padL + i * slot + (slot - barW) / 2;
      if (v > 0) {
        var h = (v / max) * innerH;
        var top = baseY - h;
        s += '<clipPath id="flowstallion-c-' + i + '"><rect x="' + x + '" y="' + top +
          '" width="' + barW + '" height="' + h + '" rx="5"/></clipPath>';
        s += '<rect class="flowstallion-seg flowstallion-bar" x="' + x + '" y="' + top + '" width="' +
          barW + '" height="' + h + '" fill="#388bfd" style="animation-delay:' +
          i * 35 + 'ms" clip-path="url(#flowstallion-c-' + i + ')"><title>' + esc(d) +
          ": $" + v.toFixed(4) + "</title></rect>";
        s += '<text x="' + (x + barW / 2) + '" y="' + (top - 6) +
          '" font-size="10" fill="#656d76" text-anchor="middle">' + fmtShort(v) + "</text>";
      }
      s += dateLabel(padL + i * slot + slot / 2, d);
    });
    s += "</svg>";
    return s;
  }

  // legend: <div class="legend"> with one .legend-item per entry.
  function legend(items) {
    return '<div class="legend">' + (items || []).map(function (it) {
      return '<span class="legend-item"><span class="swatch" style="background:' +
        it.color + '"></span>' + esc(it.label) + "</span>";
    }).join("") + "</div>";
  }

  return { svgStacked: svgStacked, svgCostBars: svgCostBars, legend: legend, fmtShort: fmtShort };
}));
