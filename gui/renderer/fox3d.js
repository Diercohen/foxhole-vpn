// The hero's fox: the app icon's low-poly fox head in 3D (WebGL), lit by the connection's colors (--a1, --a2) and
// in a mood for each phase (body[data-phase]): asleep when off, searching while busy, awake and watching the pointer
// when connected, its eyes glowing in a ring of stars in whole-system mode. Without WebGL the orb keeps its power icon.
(() => {
  const canvas = document.querySelector("#fox3d");
  const wrap = canvas.closest(".orb-wrap");
  const gl = canvas.getContext("webgl", { antialias: true, premultipliedAlpha: true });
  if (!gl) return;

  // ── The model: [x, y, z], x right, y up, z toward the viewer; the left half, mirrored for the right ─────────
  // After the icon (its #fox symbol, 64 units across: x = (sx - 32) / 24, y = (32 - sy) / 24), given depth.
  const P = {
    T: [-0.92, 1.22, -0.3], Eo: [-1, 0.46, -0.4], Ei: [-0.3, 0.66, -0.05], Eb: [-0.66, 0.7, -0.68], // the ear: tip, base, back
    F: [0, 0.74, 0.12], B: [0, 0.12, 0.52], Bo: [-0.56, 0.32, 0.16], Yo: [-0.52, 0.15, 0.27], Yi: [-0.2, 0, 0.47],
    Cw: [-1.04, 0.16, -0.3], Ce: [-0.6, 0, 0.2], Vl: [-0.25, -0.14, 0.56], Sc: [0, -0.2, 0.68],
    Nt: [0, -0.58, 0.9], Nl: [-0.13, -0.66, 0.86], N: [0, -0.76, 0.97], Mo: [0, -0.9, 0.74], Ms: [-0.21, -0.62, 0.7],
    Cm: [-0.24, -0.86, 0.54], Ch: [0, -1.06, 0.4], Jw: [-0.5, -0.74, 0.16], Ck: [-0.86, -0.32, -0.08],
    Hb: [0, 0.52, -0.7], Hs: [-0.8, 0.08, -0.62], Hl: [-0.44, -0.62, -0.42], Hc: [0, -0.04, -0.98], Th: [0, -0.86, -0.22],
  };
  // Faces as "a b c kind": f fur, l the forehead's lighter fur, c cheeks, d dark (the nose)
  const HEAD = `F Ei B l, Ei Bo B f, Ei Eo Bo f, F Hb Ei f, Ei Hb Eo f, Bo Yo Yi f, Bo Yi B f, B Yi Sc f, Yi Vl Sc f,
    Bo Eo Cw f, Bo Cw Yo f, Yo Cw Ce f, Yo Ce Yi f, Yi Ce Vl f, Vl Nt Sc f, Cw Ck Ce c, Ce Ck Jw c, Ce Jw Vl c, Vl Jw Ms c,
    Vl Ms Nt c, Nt Nl N d, Nl Mo N d, Nt Ms Nl c, Ms Cm Nl c, Nl Cm Mo c, Ms Jw Cm c, Jw Ch Cm c, Cm Ch Mo c, Jw Th Ch c,
    Ck Th Jw c, Eo Hs Cw f, Eo Hb Hs f, Cw Hs Ck f, Ck Hs Hl f, Hb Hc Hs f, Hs Hc Hl f, Hl Hc Th f, Ck Hl Th f`;
  // The left eye, a slanted slit as on the icon, and the glint in it; shut, the lower lid meets the upper
  const EYE = [[-0.49, 0.15, 0.33], [-0.21, 0.03, 0.51], [-0.43, -0.03, 0.37]];
  const LID = [-0.36, 0.085, 0.43];
  const GLINT = [-0.322, 0.04, 0.455];

  const hex = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
  const mix = (a, b, t) => a.map((v, i) => v + (b[i] - v) * t);
  const sub = (a, b) => a.map((v, i) => v - b[i]);
  const add = (a, b) => a.map((v, i) => v + b[i]);
  const cross = ([a, b, c], [d, e, f]) => [b * f - c * e, c * d - a * f, a * e - b * d];
  const dot = (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
  const unit = (a) => a.map((v) => v / Math.hypot(...a));
  const flip = ([x, y, z]) => [-x, y, z];
  /** The color at height y on a gradient of [y, color] stops, top first. */
  const ramp = (stops, y) => {
    for (let i = 1; i < stops.length; i++)
      if (y >= stops[i][0]) return mix(stops[i - 1][1], stops[i][1], (stops[i - 1][0] - y) / (stops[i - 1][0] - stops[i][0]));
    return stops[stops.length - 1][1];
  };
  // The icon's colors: its orange gradient (#g-fox), the cheeks' (#g-cheek), its dark plum
  const FUR = [[1.2, hex("#ffc061")], [0.3, hex("#ff7a1a")], [-1.05, hex("#ff3d5a")]];
  const CREAM = [[0.3, hex("#fff8ef")], [-1.05, hex("#ffd9c2")]];
  const DARK = hex("#2a1430");
  const tint = (kind, y) => (kind === "d" ? DARK : kind === "c" ? ramp(CREAM, y) : kind === "l" ? mix(ramp(FUR, y), [1, 1, 1], 0.3) : ramp(FUR, y));

  // A part: triangles { p: [a, b, c], shut?: [a, b, c], color, kind, out? } turned to face away from `center` (or
  // toward `out`), as one interleaved buffer: position, shut position (the eyes), flat normal, color, kind (0 lit, 1 eye, 2 glint).
  const STRIDE = 13;
  function part(list, center) {
    const data = [];
    for (const { p, shut = p, color, kind = 0, out } of list) {
      let [a, b, c] = p, [sa, sb, sc] = shut;
      let n = unit(cross(sub(b, a), sub(c, a)));
      const mid = [0, 1, 2].map((i) => (a[i] + b[i] + c[i]) / 3);
      if (dot(n, out ?? sub(mid, center)) < 0) ([b, c, sb, sc] = [c, b, sc, sb]), (n = n.map((v) => -v)); // counter-clockwise from outside
      for (const [v, s] of [[a, sa], [b, sb], [c, sc]]) data.push(...v, ...s, ...n, ...color, kind);
    }
    return { data: new Float32Array(data), count: data.length / STRIDE };
  }
  const faces = (spec, pts) =>
    spec.split(",").map((f) => {
      const [a, b, c, k] = f.trim().split(/\s+/);
      const p = [pts(a), pts(b), pts(c)];
      return { p, color: tint(k, (p[0][1] + p[1][1] + p[2][1]) / 3) };
    });
  const both = (spec) => [...faces(spec, (n) => P[n]), ...faces(spec, (n) => flip(P[n]))];

  /** An ear: its front with the dark inside set in, and its back. side 1: the left, -1: the right. */
  function ear(side) {
    const at = side > 0 ? (v) => v : flip;
    const [t, i, o, b] = [P.T, P.Ei, P.Eo, P.Eb].map(at);
    const mid = [0, 1, 2].map((k) => (t[k] + i[k] + o[k]) / 3);
    const front = unit(cross(sub(o, t), sub(i, t))).map((v) => v * side); // toward the viewer
    const inset = (v) => add(mix(v, mid, 0.34), front.map((f) => f * -0.05)); // set back into the ear
    const [ti, ii, oi] = [t, i, o].map(inset);
    const fur = (p, out) => ({ p, out, color: tint("f", (p[0][1] + p[1][1] + p[2][1]) / 3) });
    // the front's rim, its thin pieces turned to face the viewer (from the ear's middle they're seen edge on), then the back
    const list = [[t, i, ii], [t, ii, ti], [i, o, oi], [i, oi, ii], [o, t, ti], [o, ti, oi]].map((p) => fur(p, front));
    list.push(...[[t, o, b], [t, b, i], [i, b, o]].map((p) => fur(p)), { p: [ti, ii, oi], color: DARK, out: front });
    const inside = [0, 1, 2].map((k) => (t[k] + i[k] + o[k] + b[k]) / 4);
    return { ...part(list, inside), pivot: i, axis: unit(sub(o, i)), side };
  }

  function eyes() {
    const list = [];
    for (const at of [(v) => v, flip]) {
      const [a, b, c] = EYE.map(at), lid = at(LID), g = at(GLINT);
      list.push({ p: [a, b, c], shut: [a, b, lid], color: DARK, kind: 1 });
      const glint = [[-0.032, 0.012, 0], [0.02, 0.018, 0], [-0.004, -0.026, 0]].map((d) => add(g, at(d)));
      list.push({ p: glint, shut: [g, g, g], color: [1, 1, 1], kind: 2 });
    }
    return part(list, [0, 0, -0.3]);
  }

  const MODEL = { head: part(both(HEAD), [0, -0.05, -0.15]), earL: ear(1), earR: ear(-1), eyes: eyes() };
  // the eyes' middles, for their glow
  const EYE_MID = [EYE, EYE.map(flip)].map((e) => [0, 1, 2].map((k) => (e[0][k] + e[1][k] + e[2][k]) / 3 + (k === 2 ? 0.06 : 0)));

  // ── WebGL ─────────────────────────────────────────────────────────────────────────────────────────────────
  const MESH_VS = `
    attribute vec3 aPos, aShut, aNormal, aColor; attribute float aKind;
    uniform mat4 uModel, uView; uniform mediump float uOpen; // mediump: the fragment shader's precision, as it uses it too
    varying vec3 vNormal, vColor, vWorld; varying float vKind;
    void main() {
      vec4 w = uModel * vec4(mix(aShut, aPos, uOpen), 1.0);
      vWorld = w.xyz; vNormal = (uModel * vec4(aNormal, 0.0)).xyz; vColor = aColor; vKind = aKind;
      gl_Position = uView * w;
    }`;
  // Flat facets: a warm key light from the top left, the phase's second color filling from the right, a rim of
  // its first color, a glint of specular; asleep, the colors drain away (uSat).
  const MESH_FS = `
    precision mediump float;
    varying vec3 vNormal, vColor, vWorld; varying float vKind;
    uniform vec3 uRim, uFill, uGlow;
    uniform float uSat, uLight, uRimAmt, uGlowAmt, uScan, uScanY, uOpen;
    void main() {
      vec3 n = normalize(vNormal), v = normalize(vec3(0.0, 0.0, 7.0) - vWorld);
      vec3 key = normalize(vec3(-0.55, 0.8, 0.9)), fill = normalize(vec3(0.9, -0.15, 0.5));
      float d1 = max(dot(n, key), 0.0), d2 = max(dot(n, fill), 0.0);
      float spec = pow(max(dot(n, normalize(key + v)), 0.0), 36.0);
      float rim = pow(1.0 - max(dot(n, v), 0.0), 2.2);
      vec3 base = mix(vec3(dot(vColor, vec3(0.3, 0.59, 0.11))), vColor, uSat);
      vec3 c = base * (0.3 + 0.8 * d1 * vec3(1.0, 0.95, 0.88) + 0.45 * d2 * uFill) * uLight;
      c += spec * 0.22 * uLight + rim * uRim * uRimAmt;
      c += uRim * uScan * smoothstep(0.22, 0.0, abs(vWorld.y - uScanY)) * 0.55;
      if (vKind > 1.5) c = vec3(uOpen);
      else if (vKind > 0.5) c = mix(c, uGlow, uGlowAmt);
      gl_FragColor = vec4(c, 1.0);
    }`;
  // Points of light: a bright core in a soft halo, and for a star (aSpark), four rays
  const DOT_VS = `
    attribute vec3 aPos; attribute vec4 aColor; attribute float aSize, aSpark;
    uniform mat4 uView; uniform float uPx;
    varying vec4 vColor; varying float vSpark;
    void main() { vec4 p = uView * vec4(aPos, 1.0); gl_Position = p; gl_PointSize = aSize * uPx / p.w; vColor = aColor; vSpark = aSpark; }`;
  const DOT_FS = `
    precision mediump float;
    varying vec4 vColor; varying float vSpark;
    void main() {
      vec2 c = (gl_PointCoord - 0.5) * 2.0;
      float d = dot(c, c);
      float a = exp(-d * 16.0) + exp(-d * 3.5) * 0.4;
      a += vSpark * (exp(-abs(c.x) * 26.0 - abs(c.y) * 2.8) + exp(-abs(c.y) * 26.0 - abs(c.x) * 2.8));
      a *= smoothstep(1.0, 0.7, max(abs(c.x), abs(c.y))) * vColor.a;
      gl_FragColor = vec4(vColor.rgb * a, a * 0.75);
    }`;

  let mesh, dots, buffers, dotBuf;
  function program(vs, fs) {
    const p = gl.createProgram();
    for (const [type, src] of [[gl.VERTEX_SHADER, vs], [gl.FRAGMENT_SHADER, fs]]) {
      const s = gl.createShader(type);
      gl.shaderSource(s, src);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s));
      gl.attachShader(p, s);
    }
    gl.linkProgram(p);
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p));
    const loc = (name) => (name[0] === "a" ? gl.getAttribLocation(p, name) : gl.getUniformLocation(p, name));
    return { p, at: new Proxy({}, { get: (c, name) => (c[name] ??= loc(name)) }) };
  }
  function init() {
    mesh = program(MESH_VS, MESH_FS);
    dots = program(DOT_VS, DOT_FS);
    buffers = {};
    for (const [name, m] of Object.entries(MODEL)) {
      buffers[name] = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buffers[name]);
      gl.bufferData(gl.ARRAY_BUFFER, m.data, gl.STATIC_DRAW);
    }
    dotBuf = gl.createBuffer();
    gl.enable(gl.DEPTH_TEST);
    gl.enable(gl.CULL_FACE);
  }

  // ── Matrices, column-major ────────────────────────────────────────────────────────────────────────────────
  const mul = (a, b) => {
    const o = new Float32Array(16);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) for (let k = 0; k < 4; k++) o[c * 4 + r] += a[k * 4 + r] * b[c * 4 + k];
    return o;
  };
  const move = (x, y, z) => new Float32Array([1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, x, y, z, 1]);
  const grow = (s) => new Float32Array([s, 0, 0, 0, 0, s, 0, 0, 0, 0, s, 0, 0, 0, 0, 1]);
  const turn = ([x, y, z], a) => {
    const c = Math.cos(a), s = Math.sin(a), t = 1 - c;
    return new Float32Array([t * x * x + c, t * x * y + s * z, t * x * z - s * y, 0, t * x * y - s * z, t * y * y + c, t * y * z + s * x, 0,
      t * x * z + s * y, t * y * z - s * x, t * z * z + c, 0, 0, 0, 0, 1]);
  };
  const apply = (m, [x, y, z]) => [0, 1, 2].map((r) => m[r] * x + m[4 + r] * y + m[8 + r] * z + m[12 + r]);
  const FOV = 0.46, CAM = 7; // ≈ 26°, from 7 units away
  const perspective = (aspect) => {
    const f = 1 / Math.tan(FOV / 2), near = 0.1, far = 30;
    return new Float32Array([f / aspect, 0, 0, 0, 0, f, 0, 0, 0, 0, (far + near) / (near - far), -1, 0, 0, (2 * far * near) / (near - far), 0]);
  };

  // ── Moods: where each phase takes the fox; what's drawn eases toward it ───────────────────────────────────
  const MOODS = {
    off: { pitch: -0.34, roll: 0.13, ear: -0.55, open: 0, sat: 0.14, light: 0.72, rim: 0.55, glow: 0, scan: 0, search: 0, watch: 0, gather: 0, drift: 0, stars: 0, breathe: 1, lift: 0.06 },
    busy: { pitch: 0.03, roll: 0, ear: 0.35, open: 1, sat: 1, light: 1, rim: 0.9, glow: 0.15, scan: 1, search: 1, watch: 0.2, gather: 1, drift: 0, stars: 0, breathe: 0.3, lift: 0.02 },
    on: { pitch: 0, roll: 0, ear: 0.12, open: 1, sat: 1, light: 1, rim: 0.8, glow: 0, scan: 0, search: 0, watch: 1, gather: 0, drift: 1, stars: 0, breathe: 0.5, lift: 0 },
    global: { pitch: 0.07, roll: 0, ear: 0.2, open: 1, sat: 1.08, light: 1.06, rim: 1.15, glow: 1, scan: 0, search: 0, watch: 1, gather: 0, drift: 0, stars: 1, breathe: 0.5, lift: 0.03 },
  };
  const phaseNow = () => (MOODS[document.body.dataset.phase] ? document.body.dataset.phase : "off");
  let phase = phaseNow();
  const cur = { ...MOODS[phase] };

  // where the fox looks, easing toward the pointer (-1..1 around it); perk: its ears up while the pointer is on the orb
  const look = { x: 0, y: 0, tx: 0, ty: 0, perk: 0, tperk: 0 };
  // With less motion asked for, it holds the mood's pose: no time passes, no blinks, no burst
  const still = matchMedia("(prefers-reduced-motion: reduce)");

  // one-offs: a blink, an ear's twitch, the pop and burst of light on connecting
  const ev = { blink: -9, nextBlink: 1.5, twitch: -9, twitchEar: 0, nextTwitch: 3, pop: 0, popV: 0, burst: -9 };
  const css = getComputedStyle(document.body);
  const color = (name) => (css.getPropertyValue(name).match(/[\d.]+/g) ?? [255, 255, 255]).slice(0, 3).map((v) => v / 255);
  const hash = (i) => ((Math.sin(i * 127.1 + 311.7) * 43758.5453) % 1 + 1) % 1;

  function draw(t, dt) {
    const now = phaseNow();
    if (now !== phase) {
      if (phase === "busy" && (now === "on" || now === "global") && !still.matches) (ev.popV += 7), (ev.burst = t);
      phase = now;
    }
    const goal = MOODS[phase];
    const k = still.matches ? 1 : 1 - Math.exp(-dt / 0.45);
    for (const key in cur) cur[key] += (goal[key] - cur[key]) * k;
    const kl = 1 - Math.exp(-dt / 0.2);
    if (still.matches) look.x = look.y = look.perk = 0; // facing ahead, not following the pointer
    look.x += (look.tx - look.x) * kl;
    look.y += (look.ty - look.y) * kl;
    look.perk += (look.tperk - look.perk) * kl;
    ev.popV += (-140 * ev.pop - 11 * ev.popV) * dt; // a spring
    ev.pop += ev.popV * dt;
    if (t > ev.nextBlink) (ev.blink = t), (ev.nextBlink = t + 2.4 + Math.random() * 3.6);
    // listening while it searches: its ears twitch more often
    if (t > ev.nextTwitch) (ev.twitch = t), (ev.twitchEar = Math.random() < 0.5 ? 0 : 1), (ev.nextTwitch = t + (cur.search > 0.5 ? 0.9 + Math.random() * 1.4 : 3 + Math.random() * 5));
    const pulse = (since, len) => (since >= 0 && since < len ? Math.sin((since / len) * Math.PI) : 0);
    const open = cur.open * (1 - pulse(t - ev.blink, 0.17));
    const twitch = pulse(t - ev.twitch, 0.32) * (0.3 + 0.2 * cur.open);

    // the head: searching side to side, or turned to the pointer; asleep, bowed and breathing
    const search = cur.search * Math.sin(t * 2.1) * 0.52;
    const yaw = search + cur.watch * look.x * 0.5 + Math.sin(t * 0.6) * 0.05;
    const pitch = cur.pitch - cur.watch * look.y * 0.3 + Math.sin(t * 0.8) * 0.025 + ev.pop * -0.12;
    const roll = cur.roll - yaw * 0.18 + cur.search * Math.sin(t * 2.1 + 0.7) * 0.07;
    const size = (1 + Math.sin(t * 1.25) * 0.016 * cur.breathe) * (1 + ev.pop * 0.07);
    const head = mul(mul(mul(mul(move(0, 0.14 + cur.lift + Math.sin(t * 1.1) * 0.03, 0), turn([0, 1, 0], yaw)), turn([1, 0, 0], -pitch)), turn([0, 0, 1], roll)), grow(size * 0.92));
    // an ear turns on its base: up and forward for more, back for less
    const earM = (e, extra) => mul(head, mul(mul(move(...e.pivot), turn(e.axis, (cur.ear + look.perk * 0.3 * cur.open + extra) * -e.side)), move(...e.pivot.map((v) => -v))));

    const w = canvas.width, h = canvas.height;
    const view = mul(perspective(w / h), move(0, 0, -CAM));
    const [a1, a2] = [color("--a1"), color("--a2")];
    gl.viewport(0, 0, w, h);
    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

    const m = mesh;
    gl.useProgram(m.p);
    gl.disable(gl.BLEND);
    gl.depthMask(true);
    gl.uniformMatrix4fv(m.at.uView, false, view);
    gl.uniform3fv(m.at.uRim, a1);
    gl.uniform3fv(m.at.uFill, mix(a2, [1, 1, 1], 0.55));
    gl.uniform3fv(m.at.uGlow, mix(a2, [1, 0.85, 0.9], 0.45));
    gl.uniform1f(m.at.uSat, cur.sat);
    gl.uniform1f(m.at.uLight, cur.light);
    gl.uniform1f(m.at.uRimAmt, cur.rim * (1 + 0.15 * cur.glow * Math.sin(t * 2.4))); // in whole-system mode its light breathes
    gl.uniform1f(m.at.uGlowAmt, cur.glow);
    gl.uniform1f(m.at.uScan, cur.scan);
    gl.uniform1f(m.at.uScanY, ((t * 0.9) % 1.6) * 2.4 - 1.4);
    for (const [name, model, o] of [["head", head, 1], ["earL", earM(MODEL.earL, ev.twitchEar === 0 ? twitch : 0), 1], ["earR", earM(MODEL.earR, ev.twitchEar === 1 ? twitch : 0), 1], ["eyes", head, open]]) {
      gl.bindBuffer(gl.ARRAY_BUFFER, buffers[name]);
      for (const [attr, size, off] of [["aPos", 3, 0], ["aShut", 3, 3], ["aNormal", 3, 6], ["aColor", 3, 9], ["aKind", 1, 12]]) {
        gl.enableVertexAttribArray(m.at[attr]);
        gl.vertexAttribPointer(m.at[attr], size, gl.FLOAT, false, STRIDE * 4, off * 4);
      }
      gl.uniformMatrix4fv(m.at.uModel, false, model);
      gl.uniform1f(m.at.uOpen, o);
      gl.drawArrays(gl.TRIANGLES, 0, MODEL[name].count);
    }
    for (const attr of ["aPos", "aShut", "aNormal", "aColor", "aKind"]) gl.disableVertexAttribArray(m.at[attr]);

    // points of light: gathering in while busy, drifting up while connected, orbiting in whole-system mode
    const pts = [];
    const put = (p, c, alpha, size, spark = 0) => alpha > 0.004 && pts.push(...p, ...c, Math.min(alpha, 1), size, spark);
    for (let i = 0; i < 30 && cur.gather > 0.01; i++) {
      const s = hash(i), p = (t * 0.42 + s) % 1, r = 1.9 * (1 - p) + 0.55, a = s * 19 + p * 3.4;
      put([r * Math.cos(a), (hash(i + 50) - 0.5) * 1.9 * (1 - p) + 0.1, r * Math.sin(a) * 0.75], a1, Math.sin(p * Math.PI) * cur.gather, 0.07 + 0.06 * (1 - p));
    }
    for (let i = 0; i < 14 && cur.drift > 0.01; i++) {
      const s = hash(i + 9), p = (t * 0.09 + s) % 1, a = s * 23 + t * 0.22, r = 1.28 + Math.sin(t + i) * 0.12;
      put([r * Math.cos(a), -1.25 + p * 2.7, r * Math.sin(a) * 0.6], mix(a1, [1, 1, 1], 0.3), Math.sin(p * Math.PI) * 0.75 * cur.drift, 0.06);
    }
    for (let i = 0; i < 32 && cur.stars > 0.01; i++) {
      const ring = i % 2, th = (i / 32) * Math.PI * 2 * 2 + t * (ring ? -0.5 : 0.62), tilt = ring ? 0.5 : -0.42;
      const q = apply(turn([1, 0, 0.3 * (ring ? 1 : -1)], tilt), [1.4 * Math.cos(th), 0, 1.4 * Math.sin(th)]);
      const tw = 0.5 + 0.5 * Math.sin(t * 3.1 + i * 1.7);
      put(add(q, [0, 0.12, 0]), i % 3 === 0 ? [1, 1, 1] : i % 3 === 1 ? a1 : a2, (0.35 + 0.65 * tw) * cur.stars, 0.09 + 0.07 * tw, tw * tw);
    }
    for (const e of EYE_MID) put(apply(head, e), mix(a2, [1, 1, 1], 0.4), cur.glow * open * 0.85, 0.55);
    const b = (t - ev.burst) / 1.1;
    for (let i = 0; i < 26 && b >= 0 && b < 1; i++) {
      const a = (i / 26) * Math.PI * 2, r = 0.7 + b * 1.4;
      put([r * Math.cos(a), r * Math.sin(a) * 0.9 + 0.1, 0.2], mix(a1, [1, 1, 1], 0.3), (1 - b) * (1 - b), 0.11, 0.4);
    }
    if (!pts.length) return;
    const d = dots;
    gl.useProgram(d.p);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
    gl.depthMask(false);
    gl.bindBuffer(gl.ARRAY_BUFFER, dotBuf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(pts), gl.DYNAMIC_DRAW);
    for (const [attr, size, off] of [["aPos", 3, 0], ["aColor", 4, 3], ["aSize", 1, 7], ["aSpark", 1, 8]]) {
      gl.enableVertexAttribArray(d.at[attr]);
      gl.vertexAttribPointer(d.at[attr], size, gl.FLOAT, false, 9 * 4, off * 4);
    }
    gl.uniformMatrix4fv(d.at.uView, false, view);
    gl.uniform1f(d.at.uPx, h / (2 * Math.tan(FOV / 2)));
    gl.drawArrays(gl.POINTS, 0, pts.length / 9);
    for (const attr of ["aPos", "aColor", "aSize", "aSpark"]) gl.disableVertexAttribArray(d.at[attr]);
  }

  // ── Running: every frame while the window has focus (as the backdrop moves), else until the mood settles ────
  let raf = 0, last = 0, t = 0, focused = document.hasFocus();
  // out of focus it stops once nothing is on its way: the mood reached, the look turned, no blink or twitch midway
  const settled = () =>
    phaseNow() === phase && Object.keys(cur).every((key) => Math.abs(cur[key] - MOODS[phase][key]) < 0.002) &&
    Math.abs(ev.pop) + Math.abs(ev.popV) < 0.002 && Math.abs(look.x - look.tx) + Math.abs(look.y - look.ty) + Math.abs(look.perk - look.tperk) < 0.002 &&
    t - ev.blink > 0.17 && t - ev.twitch > 0.32 && t - ev.burst > 1.1;
  function frame(now) {
    const dt = still.matches ? 0 : Math.min(0.05, (now - last) / 1000 || 0);
    last = now;
    t += dt;
    draw(t, dt);
    raf = !still.matches && (focused || !settled()) ? requestAnimationFrame(frame) : 0;
  }
  const wake = () => {
    if (raf) return;
    last = performance.now();
    raf = requestAnimationFrame(frame);
  };
  try {
    init();
  } catch (err) {
    console.error("fox3d:", err);
    return;
  }
  wrap.classList.add("has-fox"); // the power icon gives way to the fox
  // Sized in device pixels, also anew on a display of another scale; a new size clears it, so it's drawn again at once
  const fit = () => {
    const [w, h] = [canvas.clientWidth, canvas.clientHeight].map((v) => Math.round(v * devicePixelRatio));
    if (w === canvas.width && h === canvas.height) return;
    [canvas.width, canvas.height] = [w, h];
    if (!raf) draw(t, 0);
  };
  new ResizeObserver(fit).observe(canvas);
  const rescaled = () => matchMedia(`(resolution: ${devicePixelRatio}dppx)`).addEventListener("change", () => (fit(), rescaled()), { once: true });
  rescaled();
  const notice = () => still.matches || wake(); // the pointer: nothing to follow when holding still
  document.addEventListener("pointermove", (e) => {
    const r = canvas.getBoundingClientRect();
    look.tx = Math.max(-1, Math.min(1, (e.clientX - (r.left + r.width / 2)) / 420));
    look.ty = Math.max(-1, Math.min(1, (e.clientY - (r.top + r.height / 2)) / 320));
    notice();
  });
  document.documentElement.addEventListener("pointerleave", () => ((look.tx = look.ty = 0), notice()));
  const orb = document.querySelector("#orb");
  orb.addEventListener("pointerenter", () => ((look.tperk = 1), notice()));
  orb.addEventListener("pointerleave", () => ((look.tperk = 0), notice()));
  still.addEventListener("change", wake);
  window.addEventListener("focus", () => ((focused = true), wake()));
  window.addEventListener("blur", () => (focused = false));
  new MutationObserver(wake).observe(document.body, { attributes: true, attributeFilter: ["data-phase"] });
  canvas.addEventListener("webglcontextlost", (e) => (e.preventDefault(), cancelAnimationFrame(raf), (raf = 0), wrap.classList.remove("has-fox")));
  canvas.addEventListener("webglcontextrestored", () => (init(), wrap.classList.add("has-fox"), wake()));
  wake();
})();
