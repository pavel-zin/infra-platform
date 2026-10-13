import { collect, fingerprintJS, webrtcProbe } from "./collect.js";
import { drawRosette, badge } from "./persona.js";

const $ = (id) => document.getElementById(id);
const meta = (name) => document.querySelector(`meta[name="${name}"]`)?.content ?? "";

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
// The page is written in English, so dates are too, in the day-month-year
// order passports use, whatever the browser's own locale.
const dateFmt = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric" });
const relFmt = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

function relative(iso) {
  const seconds = (new Date(iso).getTime() - Date.now()) / 1000;
  if (Math.abs(seconds) < 90) return "just now";
  const units = [["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60]];
  for (const [unit, s] of units) {
    if (Math.abs(seconds) >= s) return relFmt.format(Math.round(seconds / s), unit);
  }
  return "just now";
}

const plural = (n, one, many) => `${n.toLocaleString("en")} ${n === 1 ? one : many}`;

// A neutral persona for the specimen passport shown before the first scan.
const SPECIMEN = {
  color: "#8b93a7", color2: "#b5bccb", emoji: "👤",
  rosette: { outerLobes: 18, outerDepth: 0.06, outerStrands: 8, innerLobes: 7, innerDepth: 0.14, innerStrands: 6, starPoints: 6, starLoop: 0.6, twist: 0.25 },
};

const state = { result: null, local: null };

// ---------------------------------------------------------------- passport

const MRZ_CHARS = "ABCDEFGHJKMNPQRSTVWXYZ0123456789<<<<<<";

function showProgress(done, total) {
  const n = Math.round((done / total) * 44);
  let line = "";
  for (let i = 0; i < 44; i++) line += i < n ? MRZ_CHARS[(i * 7 + done) % MRZ_CHARS.length] : "<";
  $("mrz-2").textContent = line;
  $("scan").textContent = `Scanning… ${Math.round((done / total) * 100)}%`;
}

function paintPassport(p) {
  const pass = $("passport");
  pass.style.setProperty("--c1", p.color);
  pass.style.setProperty("--c2", p.color2);
  drawRosette($("pp-rosette"), p, "full");
  drawRosette($("pp-watermark"), p, "full");
  $("pp-emoji").textContent = p.emoji;
}

function placeName(loc) {
  if (!loc || !loc.country) return "Unknown";
  return [loc.city, loc.country].filter(Boolean).join(", ");
}

function fillPassport(r) {
  const b = r.browser;
  const pass = $("passport");
  pass.classList.remove("specimen", "scanning");
  paintPassport(b.persona);
  $("pp-name").textContent = b.persona.name;
  $("pp-code").textContent = b.persona.code;
  $("pp-browser").textContent = r.ua.label;
  $("pp-place").textContent = placeName(r.server.ip.location);
  $("pp-first").textContent = dateFmt.format(new Date(b.firstSeen));
  $("pp-expires").textContent = dateFmt.format(new Date(b.expires));
  $("mrz-1").textContent = b.mrz[0];
  $("mrz-2").textContent = b.mrz[1];
  pass.setAttribute("aria-label", `Your browser identity: ${b.persona.name}, code ${b.persona.code}`);
}

function verdictFor(r) {
  const b = r.browser;
  const when = relative(b.firstSeen);
  const since = when === "just now" ? "a moment ago" : when;
  let word, note, text;
  if (r.recognizedWithoutCookie && b.people >= 3) {
    word = "Shared";
    note = `${b.people} cookie IDs`;
    text = `This fingerprint has turned up with ${b.people} different cookie IDs. That's one person who keeps clearing cookies, or several people whose browsers look identical. Only the second kind of person is hidden.`;
  } else if (r.recognizedWithoutCookie) {
    word = "Recognized";
    note = "without cookies";
    text = `You brought no cookie from this site, yet your fingerprint matches a scan from ${since}. If that was you, clearing cookies didn't make you a stranger. If it wasn't, another browser looks exactly like yours, and you blend in.`;
  } else if (r.cookie.status === "moved") {
    word = "Changed";
    note = "cookie kept";
    text = "Your cookie recognized you, but your fingerprint changed since last time: a browser update, a settings change, or protection that changes it on purpose.";
  } else if (b.seen) {
    word = "Recognized";
    note = `visit ${b.visits}`;
    text = `Welcome back. This browser has been scanned ${plural(b.visits, "time", "times")} since ${dateFmt.format(new Date(b.firstSeen))}, and its fingerprint alone was enough to know it.`;
  } else if (b.total <= 1) {
    word = "Unique";
    note = "first scan";
    text = "You're the first browser scanned here, so you're unique by default. Scan again in a private window to see whether the name sticks.";
  } else {
    word = "Unique";
    note = `1 of ${b.total.toLocaleString("en")}`;
    text = `No other browser among the ${b.total.toLocaleString("en")} scanned here has this fingerprint. A site could recognize it on your next visit even with cookies cleared.`;
  }
  if (b.total > 1 && b.total < 100) {
    text += ` Only ${b.total} browsers have been scanned so far; with so few, almost everyone looks unique.`;
  }
  return { word, note, text };
}

function stampIt(word, note) {
  const stamp = $("stamp");
  $("stamp-word").textContent = word;
  $("stamp-note").textContent = note;
  stamp.hidden = false;
  stamp.classList.remove("landed");
  void stamp.offsetWidth; // restart the animation on rescans
  stamp.classList.add("landed");
}

// ------------------------------------------------------------- other names

const KINDS = [
  { key: "device", label: "Device", text: (r) => `Built from your screen, time zone, hardware and system. Most browsers on this computer report it alike. ${r.device.matches > 1 ? `Seen with ${plural(r.device.matches, "browser fingerprint", "browser fingerprints")} so far.` : ""}` },
  { key: "network", label: "Network", text: (r) => `Your IP address${r.server.ip.network?.org ? ` at ${r.server.ip.network.org}` : ""}. Everyone on your Wi-Fi or VPN shares it, and it changes when you move.` },
  { key: "cookie", label: "Cookie", text: (r) => ({ new: "A random ID this site just stored in a cookie. It's gone after a private window or clearing cookies.", returning: `The cookie this site gave you ${relative(r.cookie.firstSeen)}. Clearing cookies resets it.`, moved: "Your cookie survived even though your fingerprint changed: the two methods back each other up." })[r.cookie.status] },
  { key: "fingerprintjs", label: "FingerprintJS", text: () => "The visitor ID from FingerprintJS, the open-source library many sites embed. It only sees what scripts see." },
];

function renderNames(r) {
  const list = $("name-list");
  list.replaceChildren();
  for (const kind of KINDS) {
    const data = r[kind.key];
    if (!data) continue;
    const p = data.persona;
    list.append(h("li", { class: "name-card" },
      badge(p),
      h("div", { class: "name-body" },
        h("p", { class: "name-kind", text: kind.label }),
        h("p", { class: "name-title", text: p.name }),
        h("p", { class: "name-code mono", text: p.code }),
        h("p", { class: "name-text", text: kind.text(r) }),
      ),
    ));
  }
  const sibs = r.device.siblings ?? [];
  $("siblings").hidden = sibs.length === 0;
  $("sibling-list").replaceChildren(...sibs.map((s) =>
    h("li", { class: "sibling" }, badge(s.persona), h("div", {},
      h("p", { class: "name-title", text: s.persona.name }),
      h("p", { class: "name-text", text: `${s.label}, ${relative(s.lastSeen)}` }),
    ))));
  $("names").hidden = false;
}

// ----------------------------------------------------------------- signals

const HASHES = new Set(["canvas.2d", "gpu.webglRender", "gpu.webglParams", "audio.fingerprint", "tls.ja4", "h2.akamai"]);

function generic(v) {
  if (v === null || v === undefined) return "Not available";
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (Array.isArray(v)) return v.length ? v.map(generic).join(", ") : "None";
  if (typeof v === "object") return Object.entries(v).filter(([, x]) => x !== null && x !== "").map(([k, x]) => `${k}: ${generic(x)}`).join("; ");
  return String(v);
}

function show(key, v) {
  if (v === null || v === undefined) return "Not available";
  switch (key) {
    case "js.features": return `${v.supported} of ${v.of} recent features: ${v.list.join(", ")}`;
    case "fonts.installed": return v.length ? `${v.length} found: ${v.join(", ")}` : "None of the fonts tested";
    case "speech.voices": return v.count ? `${plural(v.count, "voice", "voices")}, such as ${v.sample.join(", ")}` : "None";
    case "gpu.webgl": return `${v.renderer} (${v.vendor})`;
    case "gpu.webgpu": return [v.description || v.device, v.vendor, v.architecture].filter(Boolean).join(", ") || "Available, details withheld";
    case "hw.touch": return v.points ? `${v.points} touch points` : "No touch screen";
    case "hw.memory": return `${v} GB`;
    case "hw.cores": return String(v);
    case "keyboard.layout": return v.layout === "other" ? `Keys produce ${v.keys}` : `${v.layout} (keys produce ${v.keys})`;
    case "nav.engine": return [
      v.vendor ? `vendor "${v.vendor}"` : "no vendor string",
      v.productSub && `product ${v.productSub}`,
      v.oscpu && `CPU string "${v.oscpu}"`,
      `eval() source ${v.evalLength} characters`,
      v.errorText && `error message "${v.errorText}"`,
      v.stackTraceLimit !== null && `stack limit ${v.stackTraceLimit}`,
      v.brave && "Brave's navigator.brave present",
    ].filter(Boolean).join("; ");
    case "intl.locale": return [v.locale, v.calendar && `${v.calendar} calendar`, v.numberingSystem && `${v.numberingSystem} digits`, v.hourCycle && (v.hourCycle.startsWith("h1") ? "12-hour clock" : "24-hour clock")].filter(Boolean).join(", ");
    case "intl.formats": return [v.date, v.number, v.list, v.relative].filter(Boolean).map((x) => `“${x}”`).join(", ");
    case "storage.available": return Object.entries(v).filter(([, ok]) => ok).map(([k]) => ({ cookies: "cookies", localStorage: "local storage", sessionStorage: "session storage", indexedDB: "IndexedDB", cacheStorage: "Cache Storage" })[k] ?? k).join(", ") || "No storage available";
    case "perms.states": return Object.entries(v).map(([k, s]) => `${k} ${s}`).join(", ");
    case "window.size": return `inside ${v.inner.replace("x", " × ")}, outside ${v.outer.replace("x", " × ")}`;
    case "net.connection": return [v.type, v.rtt !== null && `${v.rtt} ms round trip`, v.downlink !== null && `${v.downlink} Mbit/s`, v.saveData && "data saver on"].filter(Boolean).join(", ");
    case "audio.fingerprint": return v;
    case "media.devices": return `${plural(v.videoinput, "camera", "cameras")}, ${plural(v.audioinput, "microphone", "microphones")}, ${plural(v.audiooutput, "speaker", "speakers")}`;
    case "audio.context": return `${v.sampleRate.toLocaleString("en")} Hz, ${v.channels} channels`;
    case "screen.size": case "screen.avail": return `${v.replace("x", " × ")} pixels`;
    case "screen.colorDepth": return `${v} bits`;
    case "nav.languages": return v.join(", ");
    case "nav.plugins": return v.length ? v.join(", ") : "None";
    case "fonts.emoji": return `Glyph sizes ${v.widths.join(", ")}…`;
    case "css.colorScheme": return v === "dark" ? "Dark" : "Light";
    case "screen.dpr": return `${v}`;
    case "css.media": return [
      v.reducedMotion === "reduce" ? "reduced motion" : "full motion",
      v.contrast && v.contrast !== "no-preference" && `${v.contrast} contrast`, v.forcedColors === "active" && "forced colors",
      v.colorGamut && `${v.colorGamut} gamut`, v.dynamicRange === "high" && "HDR",
      v.pointer && `${v.pointer} pointer`, v.hover === "none" && "no hover",
    ].filter(Boolean).join(", ").replace(/^./, (c) => c.toUpperCase());
    case "privacy.signals": return `Do Not Track: ${v.dnt === "1" ? "on" : "off"}; Global Privacy Control: ${v.gpc ? "on" : "off"}`;
    case "privacy.adblock": return v ? "Detected" : "Not detected";
    case "timing.resolution": return `${v} ms`;
    case "nav.webdriver": return v ? "Set" : "Not set";
    case "uach.brands": return `${v.brands.join(", ")}; ${v.platform}${v.mobile ? ", mobile" : ""}`;
    case "uach.highEntropy": return [v.fullVersionList?.join(", "), v.platform && `${v.platform} ${v.platformVersion}`, v.architecture && `${v.architecture} ${v.bitness}-bit`, v.model].filter(Boolean).join("; ");
    default: return generic(v);
  }
}

function rarityText(st) {
  const count = st.count || 1;
  if (count >= st.total) return st.total === 1 ? "only you so far" : `all ${st.total.toLocaleString("en")} browsers`;
  if (count === 1) return "only you";
  if (count / st.total >= 0.5) return `${count.toLocaleString("en")} of ${st.total.toLocaleString("en")} browsers`;
  return `1 in ${Math.round(st.total / count).toLocaleString("en")}`;
}

function rarity(stat) {
  if (!stat || !stat.total) return null;
  const count = stat.count || 1;
  const maxBits = Math.log2(Math.max(stat.total, 2));
  const share = count / stat.total;
  const label = rarityText(stat);
  const level = share <= 0.05 ? "rare" : share <= 0.3 ? "uncommon" : "common";
  const bar = h("span", { class: "meter", role: "img", "aria-label": `Shared by ${count} of ${stat.total} scanned browsers` });
  const fill = h("span", { class: "meter-fill" });
  fill.style.width = `${Math.min(100, ((stat.bits || 0) / maxBits) * 100).toFixed(1)}%`;
  bar.append(fill);
  return h("span", { class: `rarity ${level}` }, bar, h("span", { class: "rarity-label", text: label }));
}

function renderSignals(r, local) {
  const stats = Object.fromEntries(r.stats.map((s) => [s.key, s]));
  const byGroup = new Map(r.groups.map((g) => [g.id, []]));
  for (const a of r.attributes) byGroup.get(a.group)?.push(a);
  const root = $("signal-groups");
  root.replaceChildren();
  for (const g of r.groups) {
    const items = byGroup.get(g.id);
    if (!items?.length) continue;
    const list = h("ul", { class: "signal-list" });
    for (const a of items) {
      const st = stats[a.key];
      // Absent values that aren't part of the ID say nothing; skip them.
      if (!a.browser && !st?.present) continue;
      const value = a.server ? (st?.value ?? "Not available") : show(a.key, local.signals[a.key]);
      const row = h("li", { class: "signal" },
        h("div", { class: "signal-head" },
          h("h4", { text: a.label }),
          a.browser ? rarity(st) : h("span", { class: "rarity none", text: g.id === "volatile" || !a.browser ? "Not used in your ID" : "" }),
        ),
        h("p", { class: `signal-value${HASHES.has(a.key) || a.key === "http.headerOrder" ? " mono wrap" : ""}`, text: value }),
      );
      if (a.key === "canvas.2d" && local.previews.canvas) {
        row.append(h("img", { class: "preview", src: local.previews.canvas, alt: "The hidden drawing your browser produced", width: "280", height: "64" }));
      }
      if (a.key === "gpu.webglRender" && local.previews.webgl) {
        row.append(h("img", { class: "preview preview-square", src: local.previews.webgl, alt: "The WebGL scene your graphics card drew", width: "96", height: "96" }));
      }
      row.append(h("p", { class: "signal-help", text: a.help }));
      list.append(row);
    }
    if (list.childElementCount) root.append(h("div", { class: "signal-group" }, h("h3", { text: g.label }), list));
  }
  const ranked = r.attributes
    .filter((a) => a.browser && stats[a.key]?.count)
    .sort((x, y) => (stats[y.key].bits || 0) - (stats[x.key].bits || 0))
    .slice(0, 3);
  const total = r.browser.total;
  $("signals-lede").textContent = total > 1
    ? `Each trait below is compared with the ${total.toLocaleString("en")} browsers scanned here. The longer the bar, the fewer browsers share your value. Your rarest: ${ranked.map((a) => `${a.label.toLowerCase()} (${rarityText(stats[a.key])})`).join(", ")}.`
    : "Each trait below will be compared with other browsers as more people scan. Right now yours is the only one.";
  $("signals").hidden = false;
}

// ------------------------------------------------------------------ checks

const ICONS = { ok: "✓", warn: "!", info: "i" };

function checkItem(c) {
  return h("li", { class: `check ${c.status}` },
    h("span", { class: "check-icon", "aria-hidden": "true", text: ICONS[c.status] ?? "i" }),
    h("div", {}, h("h3", { text: c.title }), h("p", { text: c.detail })),
  );
}

function renderChecks(r) {
  const list = $("check-list");
  list.replaceChildren(...r.checks.map(checkItem));
  if (!r.checks.length) list.append(checkItem({ status: "info", title: "Nothing to cross-check", detail: "The server couldn't place your IP address or read your handshake, so there was nothing to compare." }));
  $("checks").hidden = false;
}

// ------------------------------------------------------------------ server

function fact(label, ...value) {
  return h("div", {}, h("dt", { text: label }), h("dd", {}, ...value));
}

function renderServer(s) {
  const facts = $("facts");
  const items = [fact("IP address", h("span", { class: "mono", text: s.ip.address }))];
  if (s.ip.rdns) items.push(fact("Reverse DNS", h("span", { class: "mono wrap", text: s.ip.rdns })));
  if (s.ip.network?.asn) items.push(fact("Network", `${s.ip.network.org} `, h("span", { class: "muted", text: `AS${s.ip.network.asn}` })));
  if (s.ip.location?.country) items.push(fact("Location", [s.ip.location.city, s.ip.location.region, s.ip.location.country].filter(Boolean).join(", ")));
  if (s.ip.tor) items.push(fact("Tor", "This address is a Tor exit relay"));
  else if (s.ip.hosting) items.push(fact("Network type", "Hosting, cloud or VPN provider"));
  if (s.tls) {
    items.push(fact("Connection", `${s.protocol} over ${s.tls.version}, ${s.tls.cipher}`));
    items.push(fact("TLS fingerprint", h("span", { class: "mono", text: s.tls.ja4 }), " ", h("span", { class: "muted", text: "JA4" })));
    items.push(fact("Older TLS fingerprint", h("span", { class: "mono", text: s.tls.ja3Hash }), " ", h("span", { class: "muted", text: s.tls.family === "chromium" ? "JA3, changes every connection in Chromium" : "JA3" })));
    items.push(fact("TLS stack looks like", s.tls.familyName));
    items.push(fact("Key exchange", `${s.tls.keyShares?.join(", ") || "unknown"}${s.tls.postQuantum ? " (post-quantum)" : ""}`));
  }
  if (s.http2) {
    items.push(fact("HTTP/2 fingerprint", h("span", { class: "mono wrap", text: s.http2.akamai })));
    items.push(fact("HTTP/2 looks like", s.http2.familyName));
  }
  facts.replaceChildren(...items);
  $("header-list").replaceChildren(...s.headers.map(([k, v]) => h("div", {}, h("dt", { class: "mono", text: k }), h("dd", { class: "mono wrap", text: v }))));
}

// ------------------------------------------------------------------ webrtc

function isPrivate(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fc|fd|fe80:)/i.test(ip);
}

async function runWebRTC() {
  const btn = $("webrtc-run");
  const out = $("webrtc-result");
  btn.disabled = true;
  out.textContent = "Asking the STUN server…";
  try {
    const res = await webrtcProbe(meta("whoami-stun"));
    const serverIP = state.result?.server.ip.address ?? $("facts").querySelector(".mono")?.textContent ?? "";
    if (!res.supported) {
      out.replaceChildren(checkItem({ status: "ok", title: "WebRTC is unavailable", detail: "Your browser doesn't offer WebRTC here, so it can't leak addresses." }));
      return;
    }
    const pub = res.candidates.filter((c) => c.type === "srflx").map((c) => c.address);
    const local = res.candidates.filter((c) => c.type === "host" && !c.address.endsWith(".local") && isPrivate(c.address)).map((c) => c.address);
    const masked = res.candidates.some((c) => c.address.endsWith(".local"));
    const items = [];
    const leaked = pub.filter((a) => a !== serverIP);
    if (leaked.length) items.push({ status: "warn", title: "WebRTC reveals a different IP address", detail: `The STUN server saw you at ${leaked.join(", ")}, while this page's server sees ${serverIP}. Sites can use this to look past a VPN or proxy.` });
    else if (pub.length) items.push({ status: "ok", title: "WebRTC shows the same IP address", detail: `The STUN server saw ${pub.join(", ")}, the same address as this page's server. Nothing extra leaks.` });
    else items.push({ status: "ok", title: "WebRTC found no public address", detail: "Your browser or network blocked the STUN request, so WebRTC can't reveal your IP address." });
    if (local.length) items.push({ status: "warn", title: "Your local network address is exposed", detail: `WebRTC lists ${local.join(", ")}, the address inside your home or office network.` });
    else if (masked) items.push({ status: "ok", title: "Your local address is hidden", detail: "Your browser replaced its local network address with a random .local name." });
    out.replaceChildren(h("ul", { class: "check-list" }, items.map(checkItem)));
  } catch (e) {
    out.textContent = `The test couldn't run: ${e.message}`;
  } finally {
    btn.disabled = false;
  }
}

// -------------------------------------------------------------------- scan

async function scan() {
  const btn = $("scan");
  btn.disabled = true;
  $("forget").hidden = true;
  $("verdict").hidden = true;
  $("stamp").hidden = true;
  $("passport").classList.add("scanning");
  const fpjs = fingerprintJS().catch(() => null);
  try {
    const local = await collect(showProgress);
    btn.textContent = "Comparing…";
    const body = { signals: local.signals, noise: local.noise, fingerprintjs: await fpjs };
    const resp = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const r = await resp.json().catch(() => ({ error: `The server answered ${resp.status}.` }));
    if (!resp.ok) throw new Error(r.error || `The server answered ${resp.status}.`);
    state.result = r;
    state.local = local;
    render(r, local);
  } catch (e) {
    $("passport").classList.remove("scanning");
    const v = $("verdict");
    v.textContent = `The scan didn't finish: ${e.message}`;
    v.hidden = false;
    btn.textContent = "Try again";
  } finally {
    btn.disabled = false;
  }
}

function render(r, local) {
  fillPassport(r);
  const { word, note, text } = verdictFor(r);
  $("headline").textContent = `To websites, you're ${r.browser.persona.name}.`;
  $("lede").textContent = "That name came from your browser alone. Open this page in a private window, another browser or behind a VPN, scan again, and see which of your names change.";
  const v = $("verdict");
  v.textContent = text;
  v.hidden = false;
  stampIt(word, note);
  $("scan").textContent = "Scan again";
  $("forget").hidden = false;
  renderNames(r);
  renderSignals(r, local);
  renderChecks(r);
  renderServer(r.server);
}

async function forget() {
  const r = state.result;
  if (!r) return;
  const btn = $("forget");
  btn.disabled = true;
  try {
    const resp = await fetch("/api/forget", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ browser: r.browser.id }) });
    const out = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(out.error || `The server answered ${resp.status}.`);
    const v = $("verdict");
    v.textContent = "Forgotten. This browser's record and its cookie are deleted; the next scan starts from nothing.";
    v.hidden = false;
    $("stamp").hidden = true;
    btn.hidden = true;
  } catch (e) {
    $("verdict").textContent = `Couldn't forget this browser: ${e.message}`;
  } finally {
    btn.disabled = false;
  }
}

function init() {
  paintPassport(SPECIMEN);
  const stun = meta("whoami-stun");
  $("stun-host").textContent = stun.replace(/^stuns?:/, "");
  $("scan").addEventListener("click", scan);
  $("forget").addEventListener("click", forget);
  $("webrtc-run").addEventListener("click", runWebRTC);
  $("scan").disabled = false;
  if (reduceMotion) document.documentElement.classList.add("reduce-motion");
}

init();
