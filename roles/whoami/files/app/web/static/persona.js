// Draws the guilloché rosette for a persona: two braided rings and a looped
// centre star, the fine-line pattern printed on passports and banknotes. Every
// parameter comes from the identity's bits (see internal/persona), so the
// same identity always draws the same rosette.

const SVG = "http://www.w3.org/2000/svg";

function path(points) {
  let d = "";
  for (let i = 0; i < points.length; i++) {
    const [x, y] = points[i];
    d += (i ? "L" : "M") + x.toFixed(4) + " " + y.toFixed(4);
  }
  return d + "Z";
}

// A ring of `strands` wavy circles, each shifted by a fraction of a lobe so
// they cross and form a braid.
function ring(radius, depth, lobes, strands, twist, steps) {
  const out = [];
  for (let s = 0; s < strands; s++) {
    const phase = (s / strands + twist) * (2 * Math.PI / lobes);
    const pts = [];
    for (let i = 0; i < steps; i++) {
      const t = (i / steps) * 2 * Math.PI;
      const r = radius + depth * Math.sin(lobes * (t - phase)) + depth * 0.28 * Math.sin(2 * lobes * (t + phase));
      pts.push([r * Math.cos(t), r * Math.sin(t)]);
    }
    out.push(path(pts));
  }
  return out;
}

// A hypotrochoid star: points with loops when `loop` is large.
function star(points, loop, copies, steps) {
  const out = [];
  const a = 0.25, b = a * loop / Math.max(points - 1, 1) * 1.6;
  for (let c = 0; c < copies; c++) {
    const rot = (c / copies) * (2 * Math.PI / points) * 0.5;
    const pts = [];
    for (let i = 0; i < steps; i++) {
      const t = (i / steps) * 2 * Math.PI;
      const x = a * Math.cos(t) + b * Math.cos((points - 1) * t);
      const y = a * Math.sin(t) - b * Math.sin((points - 1) * t);
      pts.push([x * Math.cos(rot) - y * Math.sin(rot), x * Math.sin(rot) + y * Math.cos(rot)]);
    }
    out.push(path(pts));
  }
  return out;
}

/**
 * Fills `svg` (viewBox -1 -1 2 2) with the rosette of persona `p`.
 * detail: "full" for large renderings, "small" for badges.
 */
export function drawRosette(svg, p, detail = "full") {
  const r = p.rosette;
  const steps = detail === "full" ? 900 : 420;
  const width = detail === "full" ? 0.0065 : 0.012;
  svg.replaceChildren();
  const layers = [
    { d: ring(0.84, r.outerDepth, r.outerLobes, r.outerStrands, r.twist, steps), color: p.color },
    { d: ring(0.55, r.innerDepth * 0.8, r.innerLobes, r.innerStrands, r.twist / 2, steps), color: p.color2 },
    { d: star(r.starPoints, r.starLoop, 3, steps), color: p.color },
  ];
  for (const layer of layers) {
    const g = document.createElementNS(SVG, "g");
    g.setAttribute("fill", "none");
    g.setAttribute("stroke", layer.color);
    g.setAttribute("stroke-width", String(width));
    g.setAttribute("stroke-linejoin", "round");
    for (const d of layer.d) {
      const el = document.createElementNS(SVG, "path");
      el.setAttribute("d", d);
      g.append(el);
    }
    svg.append(g);
  }
  // A fine outer border line, as on printed rosettes.
  const border = document.createElementNS(SVG, "circle");
  border.setAttribute("r", "0.975");
  border.setAttribute("fill", "none");
  border.setAttribute("stroke", p.color2);
  border.setAttribute("stroke-width", String(width * 1.4));
  svg.append(border);
}

/** Builds a small badge: rosette with the persona's emoji in the middle. */
export function badge(p, size = "small") {
  const wrap = document.createElement("span");
  wrap.className = "badge";
  wrap.style.setProperty("--c1", p.color);
  wrap.style.setProperty("--c2", p.color2);
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "-1 -1 2 2");
  svg.setAttribute("aria-hidden", "true");
  drawRosette(svg, p, size);
  const emoji = document.createElement("span");
  emoji.className = "badge-emoji";
  emoji.textContent = p.emoji;
  emoji.setAttribute("aria-hidden", "true");
  wrap.append(svg, emoji);
  return wrap;
}
