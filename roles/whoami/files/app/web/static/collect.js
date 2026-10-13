// Collects the browser properties that fingerprinting scripts read. Every
// probe is passive: nothing here shows a permission prompt, plays sound or
// leaves the page, except the WebRTC test, which runs only on request.

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const timeout = (promise, ms, fallback = null) =>
  Promise.race([Promise.resolve(promise).catch(() => fallback), sleep(ms).then(() => fallback)]);

export async function sha256(input) {
  const data = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

const short = async (input) => (await sha256(input)).slice(0, 16);

// ---------------------------------------------------------------- navigator

function engine() {
  let errorText = null;
  try {
    null.f();
  } catch (e) {
    errorText = String(e.message);
  }
  return {
    vendor: navigator.vendor ?? null,
    productSub: navigator.productSub ?? null,
    oscpu: navigator.oscpu ?? null,
    evalLength: eval.toString().length,
    errorText,
    stackTraceLimit: Error.stackTraceLimit ?? null,
    brave: "brave" in navigator,
  };
}

async function clientHints() {
  const uad = navigator.userAgentData;
  if (!uad) return { brands: null, high: null };
  const brands = { brands: uad.brands.map((b) => `${b.brand} ${b.version}`), mobile: uad.mobile, platform: uad.platform };
  const high = await timeout(
    uad.getHighEntropyValues(["architecture", "bitness", "model", "platformVersion", "fullVersionList", "wow64", "formFactors"]),
    1000,
  );
  if (!high) return { brands, high: null };
  return {
    brands,
    high: {
      ...brands,
      architecture: high.architecture ?? "",
      bitness: high.bitness ?? "",
      model: high.model ?? "",
      platformVersion: high.platformVersion ?? "",
      wow64: high.wow64 ?? false,
      formFactors: high.formFactors ?? [],
      fullVersionList: (high.fullVersionList ?? []).map((b) => `${b.brand} ${b.version}`),
    },
  };
}

// Feature detection pins down engine and version: each line is a feature
// added to (or only present in) some browsers.
const FEATURES = [
  ["structuredClone", () => "structuredClone" in window],
  ["Array.findLast", () => "findLast" in Array.prototype],
  ["Array.toSorted", () => "toSorted" in Array.prototype],
  ["Object.groupBy", () => "groupBy" in Object],
  ["Promise.withResolvers", () => "withResolvers" in Promise],
  ["Array.fromAsync", () => "fromAsync" in Array],
  ["Set.union", () => "union" in Set.prototype],
  ["Iterator helpers", () => typeof Iterator !== "undefined" && "map" in Iterator.prototype],
  ["RegExp.escape", () => "escape" in RegExp],
  ["Error.isError", () => "isError" in Error],
  ["Math.sumPrecise", () => "sumPrecise" in Math],
  ["Uint8Array.fromBase64", () => "fromBase64" in Uint8Array],
  ["Float16Array", () => "Float16Array" in window],
  ["Temporal", () => "Temporal" in window],
  ["URL.parse", () => "parse" in URL],
  ["CSS :has()", () => CSS.supports("selector(:has(a))")],
  ["CSS scroll timelines", () => CSS.supports("animation-timeline: scroll()")],
  ["CSS text-wrap: balance", () => CSS.supports("text-wrap: balance")],
  ["CSS field-sizing", () => CSS.supports("field-sizing: content")],
  ["CSS anchor positioning", () => CSS.supports("anchor-name: --a")],
  ["CSS interpolate-size", () => CSS.supports("interpolate-size: allow-keywords")],
  ["CSS reading-flow", () => CSS.supports("reading-flow: normal")],
  ["CSS if()", () => CSS.supports("color: if(style(--x: 1): red; else: blue)")],
  ["CSS @starting-style", () => "CSSStartingStyleRule" in window],
  ["Popover", () => "popover" in HTMLElement.prototype],
  ["View transitions", () => "startViewTransition" in document],
  ["Navigation API", () => "navigation" in window],
  ["Scheduler", () => "scheduler" in window],
  ["Cookie Store", () => "cookieStore" in window],
  ["File System Access", () => "showOpenFilePicker" in window],
  ["Web Serial", () => "serial" in navigator],
  ["WebUSB", () => "usb" in navigator],
  ["Web Bluetooth", () => "bluetooth" in navigator],
  ["WebHID", () => "hid" in navigator],
  ["WebGPU", () => "gpu" in navigator],
  ["WebTransport", () => "WebTransport" in window],
  ["Compression streams", () => "CompressionStream" in window],
  ["Document PiP", () => "documentPictureInPicture" in window],
  ["EyeDropper", () => "EyeDropper" in window],
  ["Sanitizer", () => "Sanitizer" in window],
  ["Built-in AI (Prompt API)", () => "LanguageModel" in window],
  ["Built-in AI (Translator)", () => "Translator" in window],
  ["Shared Storage", () => "sharedStorage" in window],
  ["Topics API", () => "browsingTopics" in document],
  ["Attribution reporting", () => "attributionReporting" in window || "attributionsrc" in HTMLAnchorElement.prototype],
  ["Storage Access API", () => "requestStorageAccess" in document],
  ["Mozilla-only CSS", () => CSS.supports("-moz-appearance: none")],
  ["WebKit-only API", () => "webkitConvertPointFromNodeToPage" in window || "safari" in window],
];

function features() {
  const supported = [];
  for (const [name, test] of FEATURES) {
    try {
      if (test()) supported.push(name);
    } catch {
      /* treat errors as unsupported */
    }
  }
  return { supported: supported.length, of: FEATURES.length, list: supported };
}

function mathFingerprint() {
  const M = Math;
  return [
    M.acos(0.123124234234234242), M.acosh(1e308), M.asin(0.123124234234234242), M.asinh(1),
    M.atanh(0.5), M.atan(0.5), M.sin(-1e300), M.sinh(1), M.cos(10.000000000123), M.cosh(1),
    M.tan(-1e300), M.tanh(1), M.exp(1), M.expm1(1), M.log1p(10), M.pow(M.PI, -100),
  ].map((v) => String(v));
}

// ------------------------------------------------------------ locale & time

function locale() {
  const o = Intl.DateTimeFormat().resolvedOptions();
  return {
    locale: o.locale,
    calendar: o.calendar,
    numberingSystem: o.numberingSystem,
    hourCycle: new Intl.DateTimeFormat(undefined, { hour: "numeric" }).resolvedOptions().hourCycle ?? null,
  };
}

function formats() {
  const date = new Date(Date.UTC(2006, 0, 2, 15, 4, 5));
  return {
    date: date.toLocaleString(),
    number: (1234567.891).toLocaleString(),
    list: typeof Intl.ListFormat === "function" ? new Intl.ListFormat().format(["a", "b", "c"]) : null,
    relative: typeof Intl.RelativeTimeFormat === "function" ? new Intl.RelativeTimeFormat().format(-1, "day") : null,
  };
}

async function keyboardLayout() {
  if (!navigator.keyboard?.getLayoutMap) return null;
  const map = await timeout(navigator.keyboard.getLayoutMap(), 800);
  if (!map || map.size === 0) return null;
  const keys = ["KeyQ", "KeyW", "KeyE", "KeyY", "KeyZ", "KeyA", "KeyM", "Semicolon", "Quote", "BracketLeft", "Digit2", "Backquote"];
  const chars = keys.map((k) => map.get(k) ?? "_").join("");
  const name = chars.startsWith("azer") ? "AZERTY" : chars.startsWith("qwer") && chars[4] === "z" ? "QWERTZ" : chars.startsWith("qwerty") ? "QWERTY" : "other";
  return { layout: name, keys: chars };
}

// ------------------------------------------------------------------ display

function media() {
  const q = (query) => matchMedia(query).matches;
  const pick = (feature, values) => values.find((v) => q(`(${feature}: ${v})`)) ?? null;
  return {
    reducedMotion: pick("prefers-reduced-motion", ["reduce", "no-preference"]),
    contrast: pick("prefers-contrast", ["more", "less", "custom", "no-preference"]),
    reducedTransparency: pick("prefers-reduced-transparency", ["reduce", "no-preference"]),
    forcedColors: pick("forced-colors", ["active", "none"]),
    invertedColors: pick("inverted-colors", ["inverted", "none"]),
    colorGamut: pick("color-gamut", ["rec2020", "p3", "srgb"]),
    dynamicRange: pick("dynamic-range", ["high", "standard"]),
    pointer: pick("pointer", ["coarse", "fine", "none"]),
    anyPointer: pick("any-pointer", ["coarse", "fine", "none"]),
    hover: pick("hover", ["hover", "none"]),
    monochrome: q("(monochrome)"),
  };
}

// ----------------------------------------------------------------- graphics

function drawCanvas() {
  const c = document.createElement("canvas");
  c.width = 280;
  c.height = 64;
  const x = c.getContext("2d", { willReadFrequently: true });
  if (!x) return null;
  x.textBaseline = "alphabetic";
  x.fillStyle = "#f60";
  x.fillRect(120, 2, 70, 22);
  x.fillStyle = "#069";
  x.font = '15px "Times New Roman", serif';
  x.fillText("Cwm fjordbank glyphs vext quiz 😃", 4, 20);
  x.fillStyle = "rgba(102, 204, 0, 0.7)";
  x.font = "bold 18px Arial, sans-serif";
  x.fillText("Cwm fjordbank glyphs vext quiz 🦊", 6, 46);
  x.globalCompositeOperation = "multiply";
  for (const [cx, color] of [[40, "#f2f"], [70, "#2ff"], [100, "#ff2"]]) {
    x.fillStyle = color;
    x.beginPath();
    x.arc(cx, 40, 22, 0, Math.PI * 2, true);
    x.closePath();
    x.fill();
  }
  x.globalCompositeOperation = "source-over";
  const g = x.createLinearGradient(190, 0, 280, 64);
  g.addColorStop(0, "#c8102e");
  g.addColorStop(1, "#0047ab");
  x.fillStyle = g;
  x.beginPath();
  x.moveTo(200, 60);
  x.bezierCurveTo(220, -10, 250, 90, 276, 8);
  x.lineTo(276, 60);
  x.fill();
  return { canvas: c, pixels: x.getImageData(0, 0, c.width, c.height).data };
}

// Pixels of a PNG data URL, to compare what the browser exports with what it
// drew.
async function decodePixels(url, w, h) {
  const img = new Image();
  img.src = url;
  await img.decode();
  const c = document.createElement("canvas");
  c.width = w;
  c.height = h;
  const x = c.getContext("2d", { willReadFrequently: true });
  x.drawImage(img, 0, 0);
  return x.getImageData(0, 0, w, h).data;
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// The fingerprint is the hash of the raw pixels. Two kinds of protection are
// told apart: noise on every read (the value is useless, so it is replaced
// by a marker) and noise only in exported images, which Firefox applies per
// session and which reading pixels directly sidesteps.
async function canvas2d() {
  const a = drawCanvas();
  if (!a) return { value: null, image: null, noise: false, exportNoise: false };
  const b = drawCanvas();
  const image = a.canvas.toDataURL();
  let exportNoise = false;
  try {
    exportNoise = !sameBytes(await decodePixels(image, a.canvas.width, a.canvas.height), a.pixels);
  } catch {
    /* decoding unavailable: leave unknown */
  }
  return { value: await short(a.pixels), image, noise: !sameBytes(a.pixels, b.pixels), exportNoise };
}

function webgl() {
  const canvas = document.createElement("canvas");
  canvas.width = 96;
  canvas.height = 96;
  const gl = canvas.getContext("webgl", { preserveDrawingBuffer: true }) || canvas.getContext("experimental-webgl");
  if (!gl) return { info: null, params: null, render: null, image: null };
  const dbg = gl.getExtension("WEBGL_debug_renderer_info");
  const info = {
    vendor: dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR),
    renderer: dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER),
  };
  const names = [
    "MAX_TEXTURE_SIZE", "MAX_RENDERBUFFER_SIZE", "MAX_VIEWPORT_DIMS", "MAX_VERTEX_ATTRIBS",
    "MAX_VERTEX_UNIFORM_VECTORS", "MAX_FRAGMENT_UNIFORM_VECTORS", "MAX_VARYING_VECTORS",
    "MAX_COMBINED_TEXTURE_IMAGE_UNITS", "MAX_TEXTURE_IMAGE_UNITS", "MAX_VERTEX_TEXTURE_IMAGE_UNITS",
    "MAX_CUBE_MAP_TEXTURE_SIZE", "ALIASED_LINE_WIDTH_RANGE", "ALIASED_POINT_SIZE_RANGE",
    "SHADING_LANGUAGE_VERSION", "VERSION",
  ];
  const params = {};
  for (const n of names) {
    const v = gl.getParameter(gl[n]);
    params[n] = v && typeof v === "object" && "length" in v ? Array.from(v) : v;
  }
  const hp = gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT);
  params.highFloat = hp ? [hp.rangeMin, hp.rangeMax, hp.precision] : null;
  params.extensions = (gl.getSupportedExtensions() || []).slice().sort();

  // Draw a shaded triangle fan and read the pixels back.
  const vs = gl.createShader(gl.VERTEX_SHADER);
  gl.shaderSource(vs, "attribute vec2 p;varying vec2 v;void main(){v=p;gl_Position=vec4(p,0.0,1.0);}");
  gl.compileShader(vs);
  const fs = gl.createShader(gl.FRAGMENT_SHADER);
  gl.shaderSource(fs, "precision highp float;varying vec2 v;void main(){float a=atan(v.y,v.x);float r=length(v);gl_FragColor=vec4(0.5+0.5*sin(a*7.0+r*9.0),r*r,0.5+0.5*cos(r*13.0),1.0);}");
  gl.compileShader(fs);
  const prog = gl.createProgram();
  gl.attachShader(prog, vs);
  gl.attachShader(prog, fs);
  gl.linkProgram(prog);
  gl.useProgram(prog);
  const buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  const pts = [0, 0];
  for (let i = 0; i <= 9; i++) {
    const t = (i / 9) * Math.PI * 2;
    pts.push(Math.cos(t) * (i % 2 ? 0.95 : 0.55), Math.sin(t) * (i % 2 ? 0.95 : 0.55));
  }
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(pts), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(prog, "p");
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
  gl.clearColor(0, 0, 0, 0);
  gl.clear(gl.COLOR_BUFFER_BIT);
  gl.drawArrays(gl.TRIANGLE_FAN, 0, pts.length / 2);
  const pixels = new Uint8Array(96 * 96 * 4);
  gl.readPixels(0, 0, 96, 96, gl.RGBA, gl.UNSIGNED_BYTE, pixels);
  return { info, params, pixels, image: canvas.toDataURL() };
}

async function webgpu() {
  if (!navigator.gpu) return null;
  const adapter = await timeout(navigator.gpu.requestAdapter(), 1500);
  if (!adapter) return null;
  const info = adapter.info ?? (adapter.requestAdapterInfo ? await timeout(adapter.requestAdapterInfo(), 800) : null);
  return {
    vendor: info?.vendor ?? "",
    architecture: info?.architecture ?? "",
    device: info?.device ?? "",
    description: info?.description ?? "",
    features: adapter.features ? adapter.features.size : null,
  };
}

// -------------------------------------------------------------------- audio

async function audioFingerprint() {
  const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (!Ctx) return null;
  const ctx = new Ctx(1, 5000, 44100);
  const osc = ctx.createOscillator();
  osc.type = "triangle";
  osc.frequency.value = 10000;
  const comp = ctx.createDynamicsCompressor();
  comp.threshold.value = -50;
  comp.knee.value = 40;
  comp.ratio.value = 12;
  comp.attack.value = 0;
  comp.release.value = 0.25;
  osc.connect(comp);
  comp.connect(ctx.destination);
  osc.start(0);
  const buffer = await timeout(
    new Promise((resolve, reject) => {
      ctx.oncomplete = (e) => resolve(e.renderedBuffer);
      const p = ctx.startRendering();
      if (p && p.then) p.then(resolve, reject);
    }),
    2000,
  );
  if (!buffer) return null;
  const data = buffer.getChannelData(0).subarray(4500, 5000);
  let sum = 0;
  for (const v of data) sum += Math.abs(v);
  return String(sum);
}

async function audio() {
  const a = await audioFingerprint();
  const b = a === null ? null : await audioFingerprint();
  return { value: a, noise: a !== null && a !== b };
}

function audioContext() {
  const Ctx = window.AudioContext || window.webkitAudioContext;
  if (!Ctx) return null;
  try {
    const ctx = new Ctx();
    const out = { sampleRate: ctx.sampleRate, channels: ctx.destination.maxChannelCount };
    ctx.close?.();
    return out;
  } catch {
    return null;
  }
}

// -------------------------------------------------------------------- fonts

const FONTS = [
  // Windows
  "Arial", "Arial Black", "Bahnschrift", "Calibri", "Cambria", "Candara", "Comic Sans MS", "Consolas",
  "Constantia", "Corbel", "Courier New", "Ebrima", "Franklin Gothic Medium", "Gabriola", "Gadugi",
  "Georgia", "Impact", "Ink Free", "Javanese Text", "Leelawadee UI", "Lucida Console",
  "Lucida Sans Unicode", "Malgun Gothic", "Microsoft Himalaya", "Microsoft JhengHei", "Microsoft YaHei",
  "MS Gothic", "MV Boli", "Myanmar Text", "Nirmala UI", "Palatino Linotype", "Segoe Print",
  "Segoe Script", "Segoe UI", "Segoe UI Emoji", "SimSun", "Sitka Text", "Sylfaen", "Tahoma",
  "Times New Roman", "Trebuchet MS", "Verdana", "Yu Gothic",
  // Office and common apps
  "Aptos", "Agency FB", "Book Antiqua", "Bookman Old Style", "Century Gothic", "Garamond",
  "Gill Sans MT", "Monotype Corsiva", "Rockwell", "Tw Cen MT", "Myriad Pro", "Minion Pro",
  // macOS and iOS
  "American Typewriter", "Andale Mono", "Apple Chancery", "Apple SD Gothic Neo", "Avenir",
  "Avenir Next", "Baskerville", "Big Caslon", "Chalkboard", "Chalkduster", "Charter", "Cochin",
  "Copperplate", "Didot", "Futura", "Geneva", "Gill Sans", "Helvetica", "Helvetica Neue",
  "Hoefler Text", "Lucida Grande", "Marker Felt", "Menlo", "Monaco", "Noteworthy", "Optima",
  "Palatino", "Papyrus", "Phosphate", "Savoye LET", "Skia", "Snell Roundhand", "Zapfino",
  // Linux, Android, ChromeOS
  "Cantarell", "DejaVu Sans", "DejaVu Serif", "DejaVu Sans Mono", "Liberation Sans",
  "Liberation Serif", "Liberation Mono", "Noto Sans", "Noto Serif", "Noto Color Emoji", "Ubuntu",
  "Ubuntu Mono", "Droid Sans", "Roboto", "FreeSans", "Nimbus Sans", "URW Bookman", "Source Code Pro",
];

function measure(spans) {
  return spans.map((s) => [s.offsetWidth, s.offsetHeight]);
}

function fontsInstalled() {
  const bases = ["monospace", "sans-serif", "serif"];
  const text = "mmMwWLliI0fiflO&1";
  const box = document.createElement("div");
  box.setAttribute("aria-hidden", "true");
  Object.assign(box.style, { position: "absolute", left: "-9999px", top: "0", visibility: "hidden" });
  const make = (family) => {
    const s = document.createElement("span");
    s.textContent = text;
    Object.assign(s.style, { fontFamily: family, fontSize: "72px", lineHeight: "normal", whiteSpace: "nowrap", position: "absolute" });
    box.append(s);
    return s;
  };
  const baseSpans = bases.map(make);
  const testSpans = FONTS.flatMap((f) => bases.map((b) => make(`"${f}", ${b}`)));
  document.body.append(box);
  const baseDims = measure(baseSpans);
  const testDims = measure(testSpans);
  box.remove();
  const found = [];
  FONTS.forEach((f, i) => {
    for (let j = 0; j < bases.length; j++) {
      const [w, h] = testDims[i * bases.length + j];
      if (w !== baseDims[j][0] || h !== baseDims[j][1]) {
        found.push(f);
        break;
      }
    }
  });
  return found;
}

async function emojiRendering() {
  const glyphs = ["😀", "🦊", "🫠", "🩷", "🪿", "🫎", "🙂‍↔️", "🍋‍🟩", "🏳️‍⚧️", "🧑🏽‍💻"];
  const box = document.createElement("div");
  Object.assign(box.style, { position: "absolute", left: "-9999px", top: "0", visibility: "hidden" });
  const spans = glyphs.map((g) => {
    const s = document.createElement("span");
    s.textContent = g;
    Object.assign(s.style, { fontSize: "40px", whiteSpace: "nowrap", position: "absolute" });
    box.append(s);
    return s;
  });
  document.body.append(box);
  const dims = spans.map((s) => {
    const r = s.getBoundingClientRect();
    return `${r.width.toFixed(2)}x${r.height.toFixed(2)}`;
  });
  box.remove();
  return { hash: await short(dims.join(",")), widths: dims.slice(0, 4) };
}

// ------------------------------------------------------------- media, speech

async function mediaDevices() {
  if (!navigator.mediaDevices?.enumerateDevices) return null;
  const list = await timeout(navigator.mediaDevices.enumerateDevices(), 1000);
  if (!list) return null;
  const counts = { audioinput: 0, audiooutput: 0, videoinput: 0 };
  for (const d of list) counts[d.kind] = (counts[d.kind] ?? 0) + 1;
  return counts;
}

async function speechVoices() {
  if (!("speechSynthesis" in window)) return null;
  let voices = speechSynthesis.getVoices();
  if (!voices.length) {
    await timeout(new Promise((resolve) => speechSynthesis.addEventListener("voiceschanged", resolve, { once: true })), 1200);
    voices = speechSynthesis.getVoices();
  }
  const list = voices.map((v) => `${v.name}|${v.lang}|${v.localService ? 1 : 0}`).sort();
  return { count: list.length, hash: list.length ? await short(list.join("\n")) : null, sample: voices.slice(0, 6).map((v) => v.name) };
}

// ------------------------------------------------------- storage & privacy

function storage() {
  const test = (s) => {
    try {
      s.setItem("__whoami", "1");
      s.removeItem("__whoami");
      return true;
    } catch {
      return false;
    }
  };
  let local = false, session = false;
  try { local = test(window.localStorage); } catch { /* blocked */ }
  try { session = test(window.sessionStorage); } catch { /* blocked */ }
  return { cookies: navigator.cookieEnabled, localStorage: local, sessionStorage: session, indexedDB: "indexedDB" in window, cacheStorage: "caches" in window };
}

async function adblock() {
  const bait = document.createElement("div");
  bait.className = "ad ads adsbox ad-banner ad-placement doubleclick sponsored-ad";
  bait.id = "ad-banner";
  bait.setAttribute("aria-hidden", "true");
  bait.textContent = " ";
  Object.assign(bait.style, { position: "absolute", left: "-9999px", height: "10px", width: "10px" });
  document.body.append(bait);
  await sleep(150);
  const blocked = bait.offsetParent === null || bait.offsetHeight === 0 || getComputedStyle(bait).display === "none" || !bait.isConnected;
  bait.remove();
  return blocked;
}

function timerResolution() {
  let min = Infinity;
  let last = performance.now();
  const end = last + 30;
  while (last < end) {
    const now = performance.now();
    const d = now - last;
    if (d > 0 && d < min) min = d;
    last = now;
  }
  return Number(min.toPrecision(2));
}

async function permissions() {
  if (!navigator.permissions?.query) return null;
  const names = ["geolocation", "notifications", "camera", "microphone", "persistent-storage", "clipboard-read", "midi"];
  const out = {};
  await Promise.all(names.map(async (name) => {
    const st = await timeout(navigator.permissions.query({ name }), 600);
    if (st) out[name] = st.state;
  }));
  return out;
}

// --------------------------------------------------------------- the scan

/**
 * Runs every probe. onStep(done, total) reports progress.
 * Returns { signals, noise, previews, display } where signals go to the
 * server and previews/display stay in the page.
 */
export async function collect(onStep = () => {}) {
  const signals = {};
  const previews = {};
  const noise = { canvas: false, canvasExport: false, audio: false };
  const tasks = [];
  let done = 0;
  const step = () => onStep(++done, tasks.length);
  const task = (fn) => tasks.push(fn);
  const set = (key, fn) => task(async () => {
    try {
      signals[key] = await fn();
    } catch {
      signals[key] = null;
    }
  });

  set("nav.userAgent", () => navigator.userAgent);
  set("nav.platform", () => navigator.platform);
  set("nav.engine", engine);
  set("js.features", features);
  set("js.math", mathFingerprint);
  set("nav.plugins", () => Array.from(navigator.plugins ?? [], (p) => p.name));
  set("nav.webdriver", () => navigator.webdriver === true);
  task(async () => {
    const ch = await clientHints().catch(() => ({ brands: null, high: null }));
    signals["uach.brands"] = ch.brands;
    signals["uach.highEntropy"] = ch.high;
  });

  set("intl.timeZone", () => Intl.DateTimeFormat().resolvedOptions().timeZone ?? null);
  set("nav.languages", () => Array.from(navigator.languages?.length ? navigator.languages : [navigator.language]));
  set("intl.locale", locale);
  set("intl.formats", formats);
  set("keyboard.layout", keyboardLayout);

  set("screen.size", () => `${screen.width}x${screen.height}`);
  set("screen.avail", () => `${screen.availWidth}x${screen.availHeight}`);
  set("screen.colorDepth", () => screen.colorDepth);
  set("screen.dpr", () => Math.round(devicePixelRatio * 100) / 100);
  set("css.media", media);
  set("css.colorScheme", () => ["dark", "light"].find((v) => matchMedia(`(prefers-color-scheme: ${v})`).matches) ?? null);

  set("hw.cores", () => navigator.hardwareConcurrency ?? null);
  set("hw.memory", () => navigator.deviceMemory ?? null);
  set("hw.touch", () => ({ points: navigator.maxTouchPoints ?? 0, events: "ontouchstart" in window }));
  task(async () => {
    try {
      const g = webgl();
      signals["gpu.webgl"] = g.info;
      signals["gpu.webglParams"] = g.params ? await short(JSON.stringify(g.params)) : null;
      signals["gpu.webglRender"] = g.pixels ? await short(g.pixels) : null;
      previews.webgl = g.image;
      previews.webglParams = g.params;
    } catch {
      signals["gpu.webgl"] = signals["gpu.webglParams"] = signals["gpu.webglRender"] = null;
    }
  });
  set("gpu.webgpu", webgpu);
  set("media.devices", mediaDevices);
  set("speech.voices", speechVoices);
  set("audio.context", audioContext);

  task(async () => {
    const c = await canvas2d().catch(() => ({ value: null, image: null, noise: false, exportNoise: false }));
    signals["canvas.2d"] = c.value;
    previews.canvas = c.image;
    noise.canvas = c.noise;
    noise.canvasExport = c.exportNoise;
  });
  task(async () => {
    const a = await audio().catch(() => ({ value: null, noise: false }));
    signals["audio.fingerprint"] = a.value;
    noise.audio = a.noise;
  });
  set("fonts.installed", fontsInstalled);
  set("fonts.emoji", emojiRendering);

  set("storage.available", storage);
  set("privacy.signals", () => ({ dnt: navigator.doNotTrack ?? window.doNotTrack ?? null, gpc: navigator.globalPrivacyControl ?? null }));
  set("privacy.adblock", adblock);
  set("timing.resolution", timerResolution);

  set("window.size", () => ({ inner: `${innerWidth}x${innerHeight}`, outer: `${outerWidth}x${outerHeight}` }));
  set("net.connection", () => {
    const c = navigator.connection;
    return c ? { type: c.effectiveType ?? null, rtt: c.rtt ?? null, downlink: c.downlink ?? null, saveData: c.saveData ?? null } : null;
  });
  set("storage.quota", async () => {
    const e = await timeout(navigator.storage?.estimate?.(), 800);
    return e?.quota ? `${(e.quota / 2 ** 30).toFixed(1)} GB` : null;
  });
  set("perms.states", permissions);

  // Sequential on purpose: probes that measure layout or time must not
  // compete with each other, and the progress bar stays honest.
  for (const t of tasks) {
    await t();
    step();
    await sleep(0);
  }
  return { signals, noise, previews };
}

/** Runs FingerprintJS with its usage telemetry disabled. */
export async function fingerprintJS() {
  for (let i = 0; i < 20 && !window.FingerprintJS; i++) await sleep(100);
  if (!window.FingerprintJS) return null;
  const agent = await window.FingerprintJS.load({ monitoring: false });
  const result = await timeout(agent.get(), 5000);
  return result ? { visitorId: result.visitorId, confidence: result.confidence?.score ?? null } : null;
}

/**
 * Asks a STUN server which addresses this browser reaches it from, the way
 * sites use WebRTC to find the real IP behind a proxy.
 */
export async function webrtcProbe(stun) {
  if (!("RTCPeerConnection" in window)) return { supported: false, candidates: [] };
  const pc = new RTCPeerConnection({ iceServers: [{ urls: stun }] });
  const candidates = new Set();
  const finished = new Promise((resolve) => {
    pc.onicecandidate = (e) => {
      if (!e.candidate) return resolve();
      const m = /candidate:\S+ \d+ \S+ \d+ (\S+) \d+ typ (\w+)/.exec(e.candidate.candidate);
      if (m) candidates.add(`${m[2]} ${m[1]}`);
    };
    pc.onicegatheringstatechange = () => pc.iceGatheringState === "complete" && resolve();
  });
  pc.createDataChannel("whoami");
  await pc.setLocalDescription(await pc.createOffer());
  await timeout(finished, 4000);
  pc.close();
  const list = [...candidates].map((c) => {
    const [type, address] = c.split(" ");
    return { type, address };
  });
  return { supported: true, candidates: list };
}
