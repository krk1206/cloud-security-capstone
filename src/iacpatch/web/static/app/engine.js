// IaCPatch Holo Engine — 이 화면 전용의 작은 WebGL2 렌더러 (외부 라이브러리·네트워크 없음).
// 하는 일: 반투명 유리 판·빛나는 모서리·흐르는 빛줄기(리본)·입자·바닥 격자·궤도 카메라·3D 위치에 붙는 HTML 라벨.

// ------------------------------------------------------------------ 수학 (열 우선 4x4, gl-matrix 와 같은 배치)
export const V3 = {
  add: (a, b) => [a[0] + b[0], a[1] + b[1], a[2] + b[2]],
  sub: (a, b) => [a[0] - b[0], a[1] - b[1], a[2] - b[2]],
  scale: (a, s) => [a[0] * s, a[1] * s, a[2] * s],
  lerp: (a, b, t) => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t],
  len: (a) => Math.hypot(a[0], a[1], a[2]),
  norm: (a) => { const l = Math.hypot(a[0], a[1], a[2]) || 1; return [a[0] / l, a[1] / l, a[2] / l]; },
  cross: (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]],
  dot: (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2],
};

export const M4 = {
  ident() { const m = new Float32Array(16); m[0] = m[5] = m[10] = m[15] = 1; return m; },
  mul(a, b) {
    const o = new Float32Array(16);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) {
      o[c * 4 + r] = a[r] * b[c * 4] + a[4 + r] * b[c * 4 + 1] + a[8 + r] * b[c * 4 + 2] + a[12 + r] * b[c * 4 + 3];
    }
    return o;
  },
  perspective(fovy, aspect, near, far) {
    const f = 1 / Math.tan(fovy / 2), nf = 1 / (near - far), o = new Float32Array(16);
    o[0] = f / aspect; o[5] = f; o[10] = (far + near) * nf; o[11] = -1; o[14] = 2 * far * near * nf;
    return o;
  },
  lookAt(eye, c, up) {
    const z = V3.norm(V3.sub(eye, c)), x = V3.norm(V3.cross(up, z)), y = V3.cross(z, x), o = new Float32Array(16);
    o[0] = x[0]; o[4] = x[1]; o[8] = x[2]; o[12] = -V3.dot(x, eye);
    o[1] = y[0]; o[5] = y[1]; o[9] = y[2]; o[13] = -V3.dot(y, eye);
    o[2] = z[0]; o[6] = z[1]; o[10] = z[2]; o[14] = -V3.dot(z, eye);
    o[15] = 1;
    return o;
  },
  // 위치·회전(오일러 XYZ, 라디안)·크기 → 모델 행렬
  compose(p = [0, 0, 0], r = [0, 0, 0], s = [1, 1, 1]) {
    const [cx, cy, cz] = [Math.cos(r[0]), Math.cos(r[1]), Math.cos(r[2])];
    const [sx, sy, sz] = [Math.sin(r[0]), Math.sin(r[1]), Math.sin(r[2])];
    // R = Rz * Ry * Rx
    const m00 = cz * cy, m01 = cz * sy * sx - sz * cx, m02 = cz * sy * cx + sz * sx;
    const m10 = sz * cy, m11 = sz * sy * sx + cz * cx, m12 = sz * sy * cx - cz * sx;
    const m20 = -sy, m21 = cy * sx, m22 = cy * cx;
    const o = new Float32Array(16);
    o[0] = m00 * s[0]; o[1] = m10 * s[0]; o[2] = m20 * s[0];
    o[4] = m01 * s[1]; o[5] = m11 * s[1]; o[6] = m21 * s[1];
    o[8] = m02 * s[2]; o[9] = m12 * s[2]; o[10] = m22 * s[2];
    o[12] = p[0]; o[13] = p[1]; o[14] = p[2]; o[15] = 1;
    return o;
  },
  apply(m, v) {
    const [x, y, z] = v;
    return [m[0] * x + m[4] * y + m[8] * z + m[12], m[1] * x + m[5] * y + m[9] * z + m[13],
      m[2] * x + m[6] * y + m[10] * z + m[14], m[3] * x + m[7] * y + m[11] * z + m[15]];
  },
};

export const ease = {
  inOut: (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2),
  out: (t) => 1 - Math.pow(1 - t, 3),
};

export function hex(c) {
  const v = parseInt(c.replace("#", ""), 16);
  return [((v >> 16) & 255) / 255, ((v >> 8) & 255) / 255, (v & 255) / 255];
}

// ------------------------------------------------------------------ 도형 (메시: pos/nor/idx, 선: pos 쌍)
export const Geo = {
  box(w, h, d) {
    const x = w / 2, y = h / 2, z = d / 2, P = [], N = [], I = [];
    const faces = [
      [[1, 0, 0], [[x, -y, -z], [x, y, -z], [x, y, z], [x, -y, z]]],
      [[-1, 0, 0], [[-x, -y, z], [-x, y, z], [-x, y, -z], [-x, -y, -z]]],
      [[0, 1, 0], [[-x, y, -z], [-x, y, z], [x, y, z], [x, y, -z]]],
      [[0, -1, 0], [[-x, -y, z], [-x, -y, -z], [x, -y, -z], [x, -y, z]]],
      [[0, 0, 1], [[-x, -y, z], [x, -y, z], [x, y, z], [-x, y, z]]],
      [[0, 0, -1], [[x, -y, -z], [-x, -y, -z], [-x, y, -z], [x, y, -z]]],
    ];
    faces.forEach(([n, vs], f) => {
      vs.forEach((v) => { P.push(...v); N.push(...n); });
      const b = f * 4; I.push(b, b + 1, b + 2, b, b + 2, b + 3);
    });
    return { pos: new Float32Array(P), nor: new Float32Array(N), idx: new Uint16Array(I) };
  },
  boxEdges(w, h, d) {
    const x = w / 2, y = h / 2, z = d / 2;
    const c = [[-x, -y, -z], [x, -y, -z], [x, -y, z], [-x, -y, z], [-x, y, -z], [x, y, -z], [x, y, z], [-x, y, z]];
    const e = [[0, 1], [1, 2], [2, 3], [3, 0], [4, 5], [5, 6], [6, 7], [7, 4], [0, 4], [1, 5], [2, 6], [3, 7]];
    const P = []; e.forEach(([a, b]) => P.push(...c[a], ...c[b]));
    return { pos: new Float32Array(P) };
  },
  // 옆면만 있는 n각 기둥 (방패·버킷). taper: 위 반지름 비율
  prism(r, h, n, taper = 1, caps = false) {
    const P = [], N = [], I = [];
    for (let i = 0; i <= n; i++) {
      const a = (i / n) * Math.PI * 2, ca = Math.cos(a), sa = Math.sin(a);
      P.push(ca * r, -h / 2, sa * r, ca * r * taper, h / 2, sa * r * taper);
      N.push(ca, 0, sa, ca, 0, sa);
    }
    for (let i = 0; i < n; i++) { const b = i * 2; I.push(b, b + 1, b + 3, b, b + 3, b + 2); }
    if (caps) {
      const top = P.length / 3; P.push(0, h / 2, 0); N.push(0, 1, 0);
      const bot = P.length / 3; P.push(0, -h / 2, 0); N.push(0, -1, 0);
      for (let i = 0; i < n; i++) {
        const b = i * 2;
        I.push(top, b + 3, b + 1, bot, b, b + 2);
      }
    }
    return { pos: new Float32Array(P), nor: new Float32Array(N), idx: new Uint16Array(I) };
  },
  prismEdges(r, h, n, taper = 1) {
    const P = [];
    const pt = (i, top) => { const a = (i / n) * Math.PI * 2, rr = top ? r * taper : r; return [Math.cos(a) * rr, top ? h / 2 : -h / 2, Math.sin(a) * rr]; };
    for (let i = 0; i < n; i++) { P.push(...pt(i, 0), ...pt(i + 1, 0), ...pt(i, 1), ...pt(i + 1, 1), ...pt(i, 0), ...pt(i, 1)); }
    return { pos: new Float32Array(P) };
  },
  circle(r, n = 64, y = 0) {
    const P = [];
    for (let i = 0; i < n; i++) {
      const a0 = (i / n) * Math.PI * 2, a1 = ((i + 1) / n) * Math.PI * 2;
      P.push(Math.cos(a0) * r, y, Math.sin(a0) * r, Math.cos(a1) * r, y, Math.sin(a1) * r);
    }
    return { pos: new Float32Array(P) };
  },
  torus(R, r, seg = 48, sides = 12) {
    const P = [], N = [], I = [];
    for (let i = 0; i <= seg; i++) {
      const u = (i / seg) * Math.PI * 2, cu = Math.cos(u), su = Math.sin(u);
      for (let j = 0; j <= sides; j++) {
        const v = (j / sides) * Math.PI * 2, cv = Math.cos(v), sv = Math.sin(v);
        P.push((R + r * cv) * cu, r * sv, (R + r * cv) * su);
        N.push(cv * cu, sv, cv * su);
      }
    }
    const w = sides + 1;
    for (let i = 0; i < seg; i++) for (let j = 0; j < sides; j++) {
      const a = i * w + j, b = (i + 1) * w + j;
      I.push(a, b, a + 1, b, b + 1, a + 1);
    }
    return { pos: new Float32Array(P), nor: new Float32Array(N), idx: new Uint16Array(I) };
  },
  sphere(r, lat = 16, lon = 24) {
    const P = [], N = [], I = [];
    for (let i = 0; i <= lat; i++) {
      const t = (i / lat) * Math.PI, st = Math.sin(t), ct = Math.cos(t);
      for (let j = 0; j <= lon; j++) {
        const p = (j / lon) * Math.PI * 2;
        const n = [st * Math.cos(p), ct, st * Math.sin(p)];
        P.push(n[0] * r, n[1] * r, n[2] * r); N.push(...n);
      }
    }
    const w = lon + 1;
    for (let i = 0; i < lat; i++) for (let j = 0; j < lon; j++) {
      const a = i * w + j, b = a + w;
      I.push(a, b, a + 1, b, b + 1, a + 1);
    }
    return { pos: new Float32Array(P), nor: new Float32Array(N), idx: new Uint16Array(I) };
  },
  sphereWire(r, lat = 9, lon = 14, seg = 48) {
    const P = [];
    for (let i = 1; i < lat; i++) {
      const t = (i / lat) * Math.PI, y = Math.cos(t) * r, rr = Math.sin(t) * r;
      for (let k = 0; k < seg; k++) {
        const a0 = (k / seg) * Math.PI * 2, a1 = ((k + 1) / seg) * Math.PI * 2;
        P.push(Math.cos(a0) * rr, y, Math.sin(a0) * rr, Math.cos(a1) * rr, y, Math.sin(a1) * rr);
      }
    }
    for (let j = 0; j < lon; j++) {
      const p = (j / lon) * Math.PI * 2;
      for (let k = 0; k < seg / 2; k++) {
        const t0 = (k / (seg / 2)) * Math.PI, t1 = ((k + 1) / (seg / 2)) * Math.PI;
        P.push(Math.sin(t0) * Math.cos(p) * r, Math.cos(t0) * r, Math.sin(t0) * Math.sin(p) * r,
          Math.sin(t1) * Math.cos(p) * r, Math.cos(t1) * r, Math.sin(t1) * Math.sin(p) * r);
      }
    }
    return { pos: new Float32Array(P) };
  },
  octa(r) {
    const v = [[r, 0, 0], [-r, 0, 0], [0, r * 1.4, 0], [0, -r * 1.4, 0], [0, 0, r], [0, 0, -r]];
    const f = [[0, 2, 4], [4, 2, 1], [1, 2, 5], [5, 2, 0], [4, 3, 0], [1, 3, 4], [5, 3, 1], [0, 3, 5]];
    const P = [], N = [], I = [];
    f.forEach((tri, k) => {
      const [a, b, c] = tri.map((i) => v[i]);
      const n = V3.norm(V3.cross(V3.sub(b, a), V3.sub(c, a)));
      [a, b, c].forEach((p) => { P.push(...p); N.push(...n); });
      I.push(k * 3, k * 3 + 1, k * 3 + 2);
    });
    return { pos: new Float32Array(P), nor: new Float32Array(N), idx: new Uint16Array(I) };
  },
  octaEdges(r) {
    const v = [[r, 0, 0], [-r, 0, 0], [0, r * 1.4, 0], [0, -r * 1.4, 0], [0, 0, r], [0, 0, -r]];
    const e = [[0, 2], [1, 2], [4, 2], [5, 2], [0, 3], [1, 3], [4, 3], [5, 3], [0, 4], [4, 1], [1, 5], [5, 0]];
    const P = []; e.forEach(([a, b]) => P.push(...v[a], ...v[b]));
    return { pos: new Float32Array(P) };
  },
  // 바닥에 놓인 직사각형 테두리 (y 높이)
  rect(x0, z0, x1, z1, y = 0) {
    return { pos: new Float32Array([x0, y, z0, x1, y, z0, x1, y, z0, x1, y, z1, x1, y, z1, x0, y, z1, x0, y, z1, x0, y, z0]) };
  },
};

// 3차 베지어 여러 개를 이은 곡선 → 촘촘한 점 + 접선 + 길이 비율
export function curve(points, samples = 120) {
  // Catmull-Rom 으로 제어점을 부드럽게 잇는다
  const pts = points.map((p) => p.slice());
  const out = [], tan = [];
  const n = pts.length - 1;
  for (let s = 0; s <= samples; s++) {
    const t = (s / samples) * n;
    let i = Math.min(Math.floor(t), n - 1);
    const u = t - i;
    const p0 = pts[Math.max(i - 1, 0)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(i + 2, n)];
    const u2 = u * u, u3 = u2 * u;
    const f = (k) => 0.5 * ((2 * p1[k]) + (-p0[k] + p2[k]) * u + (2 * p0[k] - 5 * p1[k] + 4 * p2[k] - p3[k]) * u2 + (-p0[k] + 3 * p1[k] - 3 * p2[k] + p3[k]) * u3);
    const d = (k) => 0.5 * ((-p0[k] + p2[k]) + 2 * (2 * p0[k] - 5 * p1[k] + 4 * p2[k] - p3[k]) * u + 3 * (-p0[k] + 3 * p1[k] - 3 * p2[k] + p3[k]) * u2);
    out.push([f(0), f(1), f(2)]);
    tan.push(V3.norm([d(0), d(1), d(2)]));
  }
  const acc = [0];
  for (let i = 1; i < out.length; i++) acc.push(acc[i - 1] + V3.len(V3.sub(out[i], out[i - 1])));
  const L = acc[acc.length - 1] || 1;
  return { pts: out, tan, u: acc.map((a) => a / L), length: L };
}

export function pointAt(cv, u) {
  const i = cv.u.findIndex((x) => x >= u);
  if (i <= 0) return cv.pts[0].slice();
  const a = cv.u[i - 1], b = cv.u[i], t = (u - a) / ((b - a) || 1);
  return V3.lerp(cv.pts[i - 1], cv.pts[i], t);
}

// ------------------------------------------------------------------ 셰이더
const SH = {
  mesh: [`#version 300 es
layout(location=0) in vec3 aPos; layout(location=1) in vec3 aNor;
uniform mat4 uVP; uniform mat4 uM;
out vec3 vN; out vec3 vW;
void main(){ vec4 w=uM*vec4(aPos,1.0); vW=w.xyz; vN=mat3(uM)*aNor; gl_Position=uVP*w; }`,
  `#version 300 es
precision highp float;
in vec3 vN; in vec3 vW;
uniform vec3 uColor; uniform float uAlpha; uniform float uRim; uniform vec3 uCam; uniform float uTime; uniform float uScan; uniform float uFlash;
out vec4 o;
void main(){
  vec3 N=normalize(vN); if(!gl_FrontFacing) N=-N;
  vec3 V=normalize(uCam-vW);
  float ndl=max(dot(N,normalize(vec3(0.35,1.0,0.25))),0.0);
  float rim=pow(1.0-abs(dot(N,V)),2.2);
  vec3 c=uColor*(0.30+0.55*ndl)+uColor*rim*uRim;
  float band=uScan*smoothstep(0.92,1.0,sin(vW.y*2.2-uTime*3.0)*0.5+0.5);
  c+=uColor*band*0.9+vec3(1.0)*uFlash*0.45;
  float vis=min(1.0,uAlpha*6.0);
  float a=clamp(uAlpha+(rim*uRim*0.22+band*0.25+uFlash*0.25)*vis,0.0,1.0);
  c*=mix(1.0,vis,0.5);
  o=vec4(c,a);
}`],
  line: [`#version 300 es
layout(location=0) in vec3 aPos;
uniform mat4 uVP; uniform mat4 uM; out vec3 vW;
void main(){ vec4 w=uM*vec4(aPos,1.0); vW=w.xyz; gl_Position=uVP*w; }`,
  `#version 300 es
precision highp float;
in vec3 vW; uniform vec3 uColor; uniform float uAlpha; uniform float uTime; uniform float uDash;
out vec4 o;
void main(){ float a=uAlpha; if(uDash>0.0){ float d=fract((vW.x+vW.z)*uDash-uTime*0.6); a*=step(0.42,d); } o=vec4(uColor*a,a); }`],
  ribbon: [`#version 300 es
layout(location=0) in vec3 aPos; layout(location=1) in vec3 aTan; layout(location=2) in vec2 aUV;
uniform mat4 uVP; uniform vec3 uCam; uniform float uWidth;
out vec2 vUV;
void main(){ vec3 V=normalize(uCam-aPos); vec3 S=normalize(cross(aTan,V)); vUV=aUV; gl_Position=uVP*vec4(aPos+S*aUV.y*uWidth,1.0); }`,
  `#version 300 es
precision highp float;
in vec2 vUV;
uniform vec3 uColor; uniform float uAlpha; uniform float uTime; uniform float uSpeed; uniform float uFreq; uniform float uEnd; uniform float uGlow;
out vec4 o;
void main(){
  if(vUV.x>uEnd) discard;
  float s=abs(vUV.y);
  float core=exp(-s*s*7.0);
  float edge=smoothstep(1.0,0.55,s);
  float k=vUV.x*uFreq-uTime*uSpeed;
  float pulse=pow(0.5+0.5*sin(k*6.2831853),10.0);
  float tail=smoothstep(uEnd,uEnd-0.035,vUV.x);
  float head=smoothstep(0.0,0.02,vUV.x);
  float a=uAlpha*(0.16*edge+0.5*core*uGlow+1.35*pulse*core)*tail*head;
  o=vec4(uColor*a,a);
}`],
  points: [`#version 300 es
layout(location=0) in vec3 aPos; layout(location=1) in vec4 aCol; layout(location=2) in float aSize;
uniform mat4 uVP; uniform float uPx; out vec4 vCol;
void main(){ vec4 c=uVP*vec4(aPos,1.0); gl_Position=c; gl_PointSize=clamp(aSize*uPx/max(c.w,0.001),1.0,90.0); vCol=aCol; }`,
  `#version 300 es
precision highp float;
in vec4 vCol; out vec4 o;
void main(){ vec2 d=gl_PointCoord-0.5; float r=length(d)*2.0; float a=1.0-smoothstep(0.0,1.0,r); a=a*a; o=vec4(vCol.rgb*vCol.a*a,vCol.a*a); }`],
  grid: [`#version 300 es
layout(location=0) in vec3 aPos; uniform mat4 uVP; out vec3 vW;
void main(){ vW=aPos; gl_Position=uVP*vec4(aPos,1.0); }`,
  `#version 300 es
precision highp float;
in vec3 vW; uniform float uTime; uniform vec3 uColor; uniform vec3 uWave; uniform float uWaveT; uniform vec3 uWaveC;
out vec4 o;
float gl(vec2 p,float s){ vec2 q=p/s; vec2 g=abs(fract(q-0.5)-0.5)/fwidth(q); return 1.0-min(min(g.x,g.y),1.0); }
void main(){
  vec2 p=vW.xz; float d=length(p);
  float fade=exp(-d*0.024);
  float a=(gl(p,1.0)*0.16+gl(p,5.0)*0.42)*fade;
  float ring=exp(-pow((d-mod(uTime*7.0,110.0))*0.5,2.0))*0.35*fade;
  vec3 c=uColor*(a+ring);
  if(uWaveT>=0.0){ float dw=length(p-uWave.xz); float rw=uWaveT*34.0; float w=exp(-pow((dw-rw)*0.8,2.0))*(1.0-uWaveT)*1.4; c+=uWaveC*w; a+=w; }
  o=vec4(c,max(a,0.0));
}`],
};

function compile(gl, vs, fs) {
  const mk = (type, src) => {
    const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s) || "shader");
    return s;
  };
  const p = gl.createProgram();
  gl.attachShader(p, mk(gl.VERTEX_SHADER, vs)); gl.attachShader(p, mk(gl.FRAGMENT_SHADER, fs)); gl.linkProgram(p);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p) || "link");
  const u = {}, n = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS);
  for (let i = 0; i < n; i++) { const info = gl.getActiveUniform(p, i); u[info.name] = gl.getUniformLocation(p, info.name); }
  return { p, u };
}

// 라벨 중요도 (클래스 이름으로): 강조 > 위반·끊김·판단 불가 > Trivy 표식 > 유령 버킷 > 흐름 > 주요 노드 > 구역 이름
function labelPrio(c) {
  if (/\bhl\b/.test(c)) return 120;
  if (/\bdim\b/.test(c)) return 15;
  if (/s-(violation|broken|unknown)/.test(c)) return 100;
  if (/\btrivy\b/.test(c)) return 90;
  if (/\bghost\b/.test(c)) return 85;
  if (/\bflow\b/.test(c)) return 60;
  if (/\b(ec2|net|iam|s3|igw)\b/.test(c)) return 50;
  if (/\b(sg|pub|priv|vpc)\b/.test(c)) return 40;
  return 20;
}

// ------------------------------------------------------------------ 엔진
export class Engine {
  constructor(canvas, labelLayer) {
    this.canvas = canvas;
    this.labelLayer = labelLayer;
    const gl = canvas.getContext("webgl2", { antialias: true, alpha: false, premultipliedAlpha: false, powerPreference: "high-performance" });
    if (!gl) throw new Error("WebGL2 를 쓸 수 없다");
    this.gl = gl;
    this.prog = {};
    for (const k of Object.keys(SH)) this.prog[k] = compile(gl, SH[k][0], SH[k][1]);
    this.meshes = []; this.lines = []; this.ribbons = []; this.pointSets = []; this.labels = [];
    this.time = 0; this.dt = 0; this.last = performance.now();
    this.cam = { target: [1.5, 1.2, 0], radius: 38, yaw: -0.72, pitch: 0.62, fov: 0.78 };
    this.camGoal = null; this.autoRotate = true; this.idleUntil = 0;
    this.viewShiftPx = 0;          // 3D 가 보이는 영역의 가운데로 화면 중심을 옮긴다 (양옆 패널)
    this.viewShiftPy = 0;          // 위아래도 같은 방법 (위 막대 · 아래 도크)
    this.safe = null;              // {l,t,r,b} 화면에서 3D 가 가려지지 않는 영역 — 라벨은 이 안에서만 보인다
    this.wave = { t: -1, pos: [0, 0, 0], color: [0.2, 0.9, 1] };
    this.onFrame = [];
    this._grid();
    this._stars();
    this._controls();
    this.resize();
    window.addEventListener("resize", () => this.resize());
  }

  // ---------------- 자원
  _vao(attribs, idx) {
    const gl = this.gl, vao = gl.createVertexArray(); gl.bindVertexArray(vao);
    const bufs = [];
    attribs.forEach(({ data, size, loc, dynamic }) => {
      const b = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, b);
      gl.bufferData(gl.ARRAY_BUFFER, data, dynamic ? gl.DYNAMIC_DRAW : gl.STATIC_DRAW);
      gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, size, gl.FLOAT, false, 0, 0);
      bufs.push(b);
    });
    let ib = null;
    if (idx) { ib = gl.createBuffer(); gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, ib); gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, idx, gl.STATIC_DRAW); }
    gl.bindVertexArray(null);
    return { vao, bufs, ib };
  }

  addMesh(g, o = {}) {
    const r = this._vao([{ data: g.pos, size: 3, loc: 0 }, { data: g.nor, size: 3, loc: 1 }], g.idx);
    const m = { kind: "mesh", ...r, count: g.idx.length, color: hex(o.color || "#4fd8ff"), alpha: o.alpha ?? 1, rim: o.rim ?? 1.2,
      pos: o.pos || [0, 0, 0], rot: o.rot || [0, 0, 0], scl: o.scl || [1, 1, 1], transparent: o.transparent ?? (o.alpha ?? 1) < 1,
      scan: 0, flash: 0, visible: true, name: o.name || "" };
    this.meshes.push(m);
    return m;
  }

  addLines(g, o = {}) {
    const r = this._vao([{ data: g.pos, size: 3, loc: 0 }]);
    const l = { kind: "line", ...r, count: g.pos.length / 3, color: hex(o.color || "#4fd8ff"), alpha: o.alpha ?? 0.8, dash: o.dash || 0,
      pos: o.pos || [0, 0, 0], rot: o.rot || [0, 0, 0], scl: o.scl || [1, 1, 1], visible: true, name: o.name || "" };
    this.lines.push(l);
    return l;
  }

  addRibbon(points, o = {}) {
    const cv = curve(points, o.samples || 140);
    const P = [], T = [], UV = [], I = [];
    cv.pts.forEach((p, i) => {
      P.push(...p, ...p); T.push(...cv.tan[i], ...cv.tan[i]); UV.push(cv.u[i], -1, cv.u[i], 1);
      if (i < cv.pts.length - 1) { const b = i * 2; I.push(b, b + 1, b + 3, b, b + 3, b + 2); }
    });
    const r = this._vao([{ data: new Float32Array(P), size: 3, loc: 0 }, { data: new Float32Array(T), size: 3, loc: 1 }, { data: new Float32Array(UV), size: 2, loc: 2 }], new Uint16Array(I));
    const rb = { kind: "ribbon", ...r, count: I.length, curve: cv, color: hex(o.color || "#4fd8ff"), alpha: o.alpha ?? 1, width: o.width ?? 0.22,
      speed: o.speed ?? 0.9, freq: o.freq ?? Math.max(3, cv.length / 3.2), end: o.end ?? 1, glow: o.glow ?? 1, visible: true, name: o.name || "",
      // 전환용 목표값 (색·알파·끝 위치·폭이 부드럽게 바뀐다)
      goal: null };
    this.ribbons.push(rb);
    return rb;
  }

  addPoints(cap) {
    const pos = new Float32Array(cap * 3), col = new Float32Array(cap * 4), size = new Float32Array(cap);
    const r = this._vao([{ data: pos, size: 3, loc: 0, dynamic: true }, { data: col, size: 4, loc: 1, dynamic: true }, { data: size, size: 1, loc: 2, dynamic: true }]);
    const ps = { kind: "points", ...r, cap, pos, col, size, count: 0, dirty: true, visible: true };
    this.pointSets.push(ps);
    return ps;
  }

  addLabel(el, world, o = {}) {
    this.labelLayer.appendChild(el);
    const lb = { el, world, dx: o.dx || 0, dy: o.dy || 0, visible: true, minScale: o.minScale ?? 0.75, follow: o.follow || null };
    this.labels.push(lb);
    return lb;
  }

  _grid() {
    const s = 160, P = new Float32Array([-s, 0, -s, s, 0, -s, s, 0, s, -s, 0, s]);
    this.gridVao = this._vao([{ data: P, size: 3, loc: 0 }], new Uint16Array([0, 1, 2, 0, 2, 3]));
    this.gridColor = hex("#2bb8ff");
  }

  _stars() {
    const n = 1400, ps = this.addPoints(n);
    let seed = 7;
    const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    for (let i = 0; i < n; i++) {
      const th = rnd() * Math.PI * 2, ph = Math.acos(rnd() * 1.6 - 0.6), r = 140 + rnd() * 40;
      ps.pos.set([Math.sin(ph) * Math.cos(th) * r, Math.cos(ph) * r * 0.9 + 10, Math.sin(ph) * Math.sin(th) * r], i * 3);
      const c = rnd() < 0.15 ? [0.6, 0.75, 1] : [0.75, 0.9, 1];
      ps.col.set([...c, 0.25 + rnd() * 0.55], i * 4);
      ps.size[i] = 0.22 + rnd() * 0.55;
    }
    ps.count = n; ps.dirty = true; ps.stars = true;
    this.stars = ps;
  }

  // ---------------- 카메라
  _controls() {
    const c = this.canvas; let drag = null;
    const stopAuto = () => { this.idleUntil = performance.now() + 9000; this.camGoal = null; };
    c.addEventListener("pointerdown", (e) => { drag = { x: e.clientX, y: e.clientY }; c.setPointerCapture(e.pointerId); stopAuto(); c.classList.add("drag"); });
    c.addEventListener("pointermove", (e) => {
      if (!drag) return;
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y; drag = { x: e.clientX, y: e.clientY };
      this.cam.yaw -= dx * 0.005; this.cam.pitch = Math.min(1.35, Math.max(0.12, this.cam.pitch + dy * 0.004));
    });
    const up = () => { drag = null; c.classList.remove("drag"); };
    c.addEventListener("pointerup", up); c.addEventListener("pointercancel", up);
    c.addEventListener("wheel", (e) => { e.preventDefault(); stopAuto(); this.cam.radius = Math.min(80, Math.max(12, this.cam.radius * (1 + Math.sign(e.deltaY) * 0.08))); }, { passive: false });
  }

  flyTo(goal, ms = 1400) {
    const from = { target: this.cam.target.slice(), radius: this.cam.radius, yaw: this.cam.yaw, pitch: this.cam.pitch };
    // 가까운 쪽으로 돈다
    let yaw = goal.yaw ?? from.yaw;
    while (yaw - from.yaw > Math.PI) yaw -= Math.PI * 2;
    while (yaw - from.yaw < -Math.PI) yaw += Math.PI * 2;
    this.camGoal = { from, to: { target: goal.target || from.target, radius: goal.radius ?? from.radius, yaw, pitch: goal.pitch ?? from.pitch }, t0: performance.now(), ms };
    this.idleUntil = performance.now() + ms + 7000;
  }

  waveAt(pos, color) { this.wave = { t: 0, pos, color: hex(color) }; }

  resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = this.canvas.clientWidth, h = this.canvas.clientHeight;
    this.canvas.width = Math.max(1, Math.floor(w * dpr)); this.canvas.height = Math.max(1, Math.floor(h * dpr));
    this.dpr = dpr; this.w = w; this.h = h;
  }

  // 카메라 자리 → 보기·투영 행렬 (화면 중심 이동 포함)
  _vp(t, r, yaw, pitch) {
    const eye = [t[0] + r * Math.cos(pitch) * Math.sin(yaw), t[1] + r * Math.sin(pitch), t[2] + r * Math.cos(pitch) * Math.cos(yaw)];
    const P = M4.perspective(this.cam.fov, this.w / Math.max(1, this.h), 0.5, 500);
    const sx = (2 * this.viewShiftPx) / Math.max(1, this.w), sy = (-2 * this.viewShiftPy) / Math.max(1, this.h);
    for (let c = 0; c < 4; c++) { P[c * 4] += sx * P[c * 4 + 3]; P[c * 4 + 1] += sy * P[c * 4 + 3]; }   // 클립 공간에서 옮긴다 (원근은 그대로)
    return { VP: M4.mul(P, M4.lookAt(eye, t, [0, 1, 0])), eye };
  }

  _camera() {
    const now = performance.now();
    if (this.camGoal) {
      const g = this.camGoal, t = Math.min(1, (now - g.t0) / g.ms), k = ease.inOut(t);
      this.cam.target = V3.lerp(g.from.target, g.to.target, k);
      this.cam.radius = g.from.radius + (g.to.radius - g.from.radius) * k;
      this.cam.yaw = g.from.yaw + (g.to.yaw - g.from.yaw) * k;
      this.cam.pitch = g.from.pitch + (g.to.pitch - g.from.pitch) * k;
      if (t >= 1) this.camGoal = null;
    } else if (this.autoRotate && now > this.idleUntil) {
      // 가만히 두면 잡힌 구도를 중심으로 천천히 좌우로 흔들린다 (계속 돌면 장면이 패널 밑으로 들어가므로)
      if (this.swayT0 == null) { this.swayT0 = now; this.swayBase = this.cam.yaw; }
      this.cam.yaw = this.swayBase + 0.1 * Math.sin(((now - this.swayT0) / 1000) * 0.17);
    } else {
      this.swayT0 = null;
    }
    const v = this._vp(this.cam.target, this.cam.radius, this.cam.yaw, this.cam.pitch);
    this.eye = v.eye; this.VP = v.VP;
  }

  // 주어진 점들이 보이는 영역(safe) 안에 꼭 맞게 들어오는 카메라 자리를 계산한다 (가운데 맞춤 + 반지름 이분 탐색)
  frame(pts, yaw, pitch, pad = 36) {
    const R = this.safe || { l: 0, t: 0, r: this.w, b: this.h };
    const box = (target, r) => {
      const { VP } = this._vp(target, r, yaw, pitch);
      let x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9;
      for (const p of pts) {
        const c = M4.apply(VP, p);
        if (c[3] <= 0.05) return null;
        const x = (c[0] / c[3] * 0.5 + 0.5) * this.w, y = (1 - (c[1] / c[3] * 0.5 + 0.5)) * this.h;
        x0 = Math.min(x0, x); x1 = Math.max(x1, x); y0 = Math.min(y0, y); y1 = Math.max(y1, y);
      }
      return { x0, y0, x1, y1 };
    };
    const fits = (target, r) => { const b = box(target, r); return b && b.x0 >= R.l + pad && b.x1 <= R.r - pad && b.y0 >= R.t + pad && b.y1 <= R.b - pad; };
    const fitR = (target) => { let lo = 6, hi = 220; if (!fits(target, hi)) return hi; for (let i = 0; i < 26; i++) { const m = (lo + hi) / 2; if (fits(target, m)) hi = m; else lo = m; } return hi; };
    // 처음 중심: 점들의 가운데
    let target = [0, 0, 0];
    pts.forEach((p) => { target = V3.add(target, p); });
    target = V3.scale(target, 1 / Math.max(1, pts.length));
    let r = fitR(target);
    for (let it = 0; it < 3; it++) {     // 화면에 비친 상자의 가운데를 보이는 영역 가운데로 옮긴다
      const b = box(target, r); if (!b) break;
      const dx = (b.x0 + b.x1) / 2 - (R.l + R.r) / 2, dy = (b.y0 + b.y1) / 2 - (R.t + R.b) / 2;
      const eye = this._vp(target, r, yaw, pitch).eye;
      const f = V3.norm(V3.sub(target, eye)), right = V3.norm(V3.cross(f, [0, 1, 0])), up = V3.cross(right, f);
      const wpp = (2 * r * Math.tan(this.cam.fov / 2)) / Math.max(1, this.h);
      target = V3.add(target, V3.add(V3.scale(right, dx * wpp), V3.scale(up, -dy * wpp)));
      r = fitR(target);
    }
    return { target, radius: r, yaw, pitch };
  }

  project(p) {
    const c = M4.apply(this.VP, p);
    if (c[3] <= 0.01) return null;
    return { x: (c[0] / c[3] * 0.5 + 0.5) * this.w, y: (1 - (c[1] / c[3] * 0.5 + 0.5)) * this.h, depth: c[3] };
  }

  // ---------------- 그리기
  start() {
    const loop = (now) => {
      this.dt = Math.min(0.05, (now - this.last) / 1000); this.last = now; this.time += this.dt;
      if (this.wave.t >= 0) { this.wave.t += this.dt / 2.4; if (this.wave.t > 1) this.wave.t = -1; }
      for (const f of this.onFrame) f(this.dt, this.time);
      this.render();
      requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  }

  render() {
    const gl = this.gl;
    this._camera();
    gl.viewport(0, 0, this.canvas.width, this.canvas.height);
    gl.clearColor(0.012, 0.022, 0.045, 1); gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
    gl.enable(gl.DEPTH_TEST); gl.depthFunc(gl.LEQUAL);

    // 1) 바닥 격자 (가산)
    let pr = this.prog.grid; gl.useProgram(pr.p);
    gl.enable(gl.BLEND); gl.blendFunc(gl.ONE, gl.ONE); gl.depthMask(false);
    gl.uniformMatrix4fv(pr.u.uVP, false, this.VP); gl.uniform1f(pr.u.uTime, this.time); gl.uniform3fv(pr.u.uColor, this.gridColor);
    gl.uniform3fv(pr.u.uWave, this.wave.pos); gl.uniform1f(pr.u.uWaveT, this.wave.t); gl.uniform3fv(pr.u.uWaveC, this.wave.color);
    gl.bindVertexArray(this.gridVao.vao); gl.drawElements(gl.TRIANGLES, 6, gl.UNSIGNED_SHORT, 0);

    // 2) 불투명 메시 → 3) 반투명 메시 (멀리 있는 것부터)
    pr = this.prog.mesh; gl.useProgram(pr.p);
    gl.uniformMatrix4fv(pr.u.uVP, false, this.VP); gl.uniform3fv(pr.u.uCam, this.eye); gl.uniform1f(pr.u.uTime, this.time);
    const opaque = this.meshes.filter((m) => m.visible && !m.transparent);
    const trans = this.meshes.filter((m) => m.visible && m.transparent)
      .map((m) => ({ m, d: V3.len(V3.sub(m.pos, this.eye)) })).sort((a, b) => b.d - a.d).map((x) => x.m);
    gl.disable(gl.BLEND); gl.depthMask(true); gl.enable(gl.CULL_FACE);
    opaque.forEach((m) => this._drawMesh(m));
    gl.disable(gl.CULL_FACE); gl.enable(gl.BLEND); gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA); gl.depthMask(false);
    trans.forEach((m) => this._drawMesh(m));

    // 4) 빛나는 선 (가산)
    gl.blendFunc(gl.ONE, gl.ONE);
    pr = this.prog.line; gl.useProgram(pr.p);
    gl.uniformMatrix4fv(pr.u.uVP, false, this.VP); gl.uniform1f(pr.u.uTime, this.time);
    this.lines.forEach((l) => {
      if (!l.visible || l.alpha <= 0.001) return;
      gl.uniformMatrix4fv(pr.u.uM, false, M4.compose(l.pos, l.rot, l.scl));
      gl.uniform3fv(pr.u.uColor, l.color); gl.uniform1f(pr.u.uAlpha, l.alpha); gl.uniform1f(pr.u.uDash, l.dash);
      gl.bindVertexArray(l.vao); gl.drawArrays(gl.LINES, 0, l.count);
    });

    // 5) 흐름 빛줄기
    pr = this.prog.ribbon; gl.useProgram(pr.p);
    gl.uniformMatrix4fv(pr.u.uVP, false, this.VP); gl.uniform3fv(pr.u.uCam, this.eye); gl.uniform1f(pr.u.uTime, this.time);
    this.ribbons.forEach((r) => {
      if (!r.visible || r.alpha <= 0.002) return;
      gl.uniform3fv(pr.u.uColor, r.color); gl.uniform1f(pr.u.uAlpha, r.alpha); gl.uniform1f(pr.u.uWidth, r.width);
      gl.uniform1f(pr.u.uSpeed, r.speed); gl.uniform1f(pr.u.uFreq, r.freq); gl.uniform1f(pr.u.uEnd, r.end); gl.uniform1f(pr.u.uGlow, r.glow);
      gl.bindVertexArray(r.vao); gl.drawElements(gl.TRIANGLES, r.count, gl.UNSIGNED_SHORT, 0);
    });

    // 6) 입자 (별은 깊이 무시)
    pr = this.prog.points; gl.useProgram(pr.p);
    gl.uniformMatrix4fv(pr.u.uVP, false, this.VP); gl.uniform1f(pr.u.uPx, this.canvas.height * 0.9);
    this.pointSets.forEach((ps) => {
      if (!ps.visible || ps.count <= 0) return;
      if (ps.dirty) {
        gl.bindBuffer(gl.ARRAY_BUFFER, ps.bufs[0]); gl.bufferSubData(gl.ARRAY_BUFFER, 0, ps.pos.subarray(0, ps.count * 3));
        gl.bindBuffer(gl.ARRAY_BUFFER, ps.bufs[1]); gl.bufferSubData(gl.ARRAY_BUFFER, 0, ps.col.subarray(0, ps.count * 4));
        gl.bindBuffer(gl.ARRAY_BUFFER, ps.bufs[2]); gl.bufferSubData(gl.ARRAY_BUFFER, 0, ps.size.subarray(0, ps.count));
        ps.dirty = false;
      }
      if (ps.stars) gl.disable(gl.DEPTH_TEST); else gl.enable(gl.DEPTH_TEST);
      gl.bindVertexArray(ps.vao); gl.drawArrays(gl.POINTS, 0, ps.count);
    });
    gl.enable(gl.DEPTH_TEST); gl.depthMask(true); gl.bindVertexArray(null);

    // 7) 라벨 — 겹치면 중요도가 낮은 쪽을 위아래로 비켜 놓고, 그래도 겹치면 덜 중요한 라벨은 숨긴다
    const R = this.safe, vis = [];
    const hide = (lb) => { if (lb.shown !== false) { lb.el.style.display = "none"; lb.shown = false; } };
    for (const lb of this.labels) {
      if (!lb.visible) { hide(lb); continue; }
      const op = lb.el.style.opacity;
      if (op !== "" && +op < 0.05) { hide(lb); continue; }
      const s = this.project(lb.follow ? lb.follow() : lb.world);
      if (!s || s.x < -200 || s.x > this.w + 200 || s.y < -100 || s.y > this.h + 100
        || (R && (s.x < R.l + 30 || s.x > R.r - 30 || s.y < R.t + 6 || s.y > R.b - 6))) { hide(lb); continue; }   // 패널 밑으로 들어간 라벨은 숨긴다
      if (lb.shown !== true) { lb.el.style.display = ""; lb.shown = true; }
      vis.push({ lb, x: s.x + lb.dx, y: s.y + lb.dy, sc: Math.max(lb.minScale, Math.min(1.15, 34 / s.depth)), depth: s.depth });
    }
    this._lt = (this._lt || 0) + 1;
    for (const v of vis) {
      const lb = v.lb, cls = lb.el.className;
      if (!lb.mw || lb.cls !== cls || this._lt % 45 === 0) { lb.mw = lb.el.offsetWidth; lb.mh = lb.el.offsetHeight; lb.cls = cls; lb.pr = labelPrio(cls); }
    }
    vis.sort((a, b) => b.lb.pr - a.lb.pr || a.depth - b.depth);
    const placed = [];
    const hit = (x, y, w, h) => placed.some((q) => Math.abs(q.x - x) * 2 < q.w + w + 6 && Math.abs(q.y - y) * 2 < q.h + h + 4);
    for (const v of vis) {
      const lb = v.lb, w = lb.mw * v.sc, h = lb.mh * v.sc;
      let k = null;
      for (const t of [lb.k || 0, 0, -1, 1, -2, 2]) if (!hit(v.x, v.y + t * (h + 3), w, h)) { k = t; break; }
      if (k === null) { if (lb.pr <= 40) { hide(lb); continue; } k = 0; }
      lb.k = k;
      const y = v.y + k * (h + 3);
      placed.push({ x: v.x, y, w, h });
      lb.el.style.transform = `translate(${v.x.toFixed(1)}px, ${y.toFixed(1)}px) translate(-50%, -50%) scale(${v.sc.toFixed(3)})`;
      lb.el.style.zIndex = String(Math.round(lb.pr * 100 + 1000 - v.depth * 10));
    }
  }

  _drawMesh(m) {
    if (m.alpha <= 0.004 && m.flash <= 0.004) return;
    const gl = this.gl, u = this.prog.mesh.u;
    gl.uniformMatrix4fv(u.uM, false, M4.compose(m.pos, m.rot, m.scl));
    gl.uniform3fv(u.uColor, m.color); gl.uniform1f(u.uAlpha, m.alpha); gl.uniform1f(u.uRim, m.rim);
    gl.uniform1f(u.uScan, m.scan); gl.uniform1f(u.uFlash, m.flash);
    gl.bindVertexArray(m.vao); gl.drawElements(gl.TRIANGLES, m.count, gl.UNSIGNED_SHORT, 0);
  }
}
