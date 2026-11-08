// 9차 버그 사냥: 모든 화면을 두 해상도로 돌며 (1) 화면 오류 (2) 가로 넘침 (3) 글자 · 칸 겹침 (4) 버튼 글자 잘림을 센다. 바꾸는 동작은 하지 않는다 (읽기 · 이동만)
const { chromium } = require('playwright');
const fs = require('fs');
const BASE = 'http://127.0.0.1:8897/';
const OUT = '/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e/shots_walk';
const REC = '20261023-124957-af6f0b';
const UPROJ = process.argv[2] || '';      // 연결한 프로젝트 id (있으면 그 화면도)
const results = [];
const check = (name, cond, extra) => { results.push(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra !== undefined ? '  — ' + (typeof extra === 'string' ? extra : JSON.stringify(extra)) : ''}`); };

// 겹침 · 넘침 · 잘림 검사 (화면 안에서)
const AUDIT = () => {
  const body = document.querySelector('#mbody'); const br = body.getBoundingClientRect();
  const out = { overflowX: body.scrollWidth > body.clientWidth + 1, wide: [], clipped: [], overlap: [] };
  const vis = (el) => { const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
  const txt = (el) => (el.textContent || '').trim().slice(0, 40);
  // 가로로 몸통 밖으로 나간 것 (svg 안 · 표 스크롤 안은 제외)
  for (const el of body.querySelectorAll('.mcard, .mbtn, .mchip, h1, h2, h3, p, li, .awsflow li, .nums > div')) {
    if (!vis(el) || el.closest('svg, .tscroll, .mlog, .amapwrap, .ilist')) continue;
    const r = el.getBoundingClientRect();
    if (r.right > br.right - 2 || r.left < br.left + 2) out.wide.push({ t: el.className || el.tagName, x: txt(el), l: Math.round(r.left - br.left), r: Math.round(r.right - br.right) });
  }
  // 자기 칸보다 넓은 표 — 칸 밖으로 그려져 옆 칸에 겹친다 (15차: '사람에게 넘김' 칸의 지금 값 표에서 발견, 칸 상자끼리는 안 겹쳐 위 검사로는 못 잡음)
  for (const el of body.querySelectorAll('table')) {
    if (!vis(el) || el.closest('svg, .tscroll, .mlog')) continue;
    const r = el.getBoundingClientRect(), pr = el.parentElement.getBoundingClientRect();
    if (r.right > pr.right + 2) out.wide.push({ t: `table in ${el.parentElement.className || el.parentElement.tagName}`, x: txt(el), l: Math.round(r.left - pr.left), r: Math.round(r.right - pr.right) });
  }
  // 글자 잘림: 한 줄 버튼 · 칩이 자기 폭보다 긴 글자
  for (const el of body.querySelectorAll('.mbtn, .mchip, .msev, .cchip, .vchip')) {
    if (!vis(el)) continue;
    if (el.scrollWidth > el.clientWidth + 2) out.clipped.push({ t: el.className, x: txt(el), sw: el.scrollWidth, cw: el.clientWidth });
  }
  // 겹침: 같은 부모 안의 형제 카드 · 버튼 · 칸이 서로 포개짐 (flex wrap 은 포개지지 않으므로 포개지면 버그)
  const sibs = new Map();
  for (const el of body.querySelectorAll('.mcard, .mbtn, .awsflow li, .nums > div, .dec, .qrow, .flist li, .trow, .cchip')) {
    if (!vis(el) || el.closest('svg')) continue;
    const k = el.parentElement; if (!sibs.has(k)) sibs.set(k, []); sibs.get(k).push(el);
  }
  for (const [, arr] of sibs) {
    for (let i = 0; i < arr.length; i++) for (let j = i + 1; j < arr.length; j++) {
      const a = arr[i].getBoundingClientRect(), b = arr[j].getBoundingClientRect();
      const ix = Math.min(a.right, b.right) - Math.max(a.left, b.left), iy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
      if (ix > 4 && iy > 4) out.overlap.push({ a: txt(arr[i]), b: txt(arr[j]), ix: Math.round(ix), iy: Math.round(iy) });
    }
  }
  return out;
};

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const b = await chromium.launch();
  const screens = [['s1', '#p=webapp-3tier&s=1'], ['s2', '#p=webapp-3tier&s=2'], ['s3', '#p=webapp-3tier&s=3'], ['s4', '#p=webapp-3tier&s=4'], ['s5', '#p=webapp-3tier&s=5'],
    ['s5r', `#p=webapp-3tier&s=5&rec=${REC}`], ['s6', `#p=webapp-3tier&s=6&rec=${REC}`], ['s7', `#p=webapp-3tier&s=7&rec=${REC}`], ['s8', `#p=webapp-3tier&s=8&rec=${REC}`], ['home', '']];
  if (UPROJ) for (const n of [2, 3, 4, 5]) screens.push([`u${n}`, `#p=${UPROJ}&s=${n}`]);
  for (const n of [2, 3, 4, 5]) screens.push([`b${n}`, `#p=three-tier-team&s=${n}`]);     // 팀 3계층 예제 (D-49) — ③ 설계 문서 칸 포함
  for (const n of [2, 3, 4, 5]) screens.push([`i${n}`, `#p=three-tier-team-iam&s=${n}`]);  // 팀 3계층 요청 3 (IAM, D-51) — 권한 그림 · IAM 요구사항
  for (const n of [2, 3, 4, 5]) screens.push([`h${n}`, `#p=three-tier-team-s3&s=${n}`]);   // 팀 3계층 요청 2 (S3, 정책 밖 — 사람에게 넘김)
  for (const n of [2, 3, 4, 5]) screens.push([`d${n}`, `#p=three-tier-team-dbsg&s=${n}`]);   // 요청 4 (DB 보안 그룹, D-52) — 아직 안 온 요청도 주소로는 열린다
  for (const n of [2, 3, 4, 5]) screens.push([`w${n}`, `#p=three-tier-team-upload&s=${n}`]); // 요청 6 (업로드 IAM, D-52)
  for (const id of ['dbpublic', 'imds', 'dbenc', 'deletion', 'flowlog', 'backup']) screens.push([`g-${id}`, `#p=three-tier-team-${id}&s=2`]);   // 사람에게 넘김 6건 (D-52)
  const BIG = process.argv[3] === 'big';
  for (const [w, h] of [[1366, 768], [1280, 720], [1920, 1080]]) {
    const p = await b.newPage({ viewport: { width: w, height: h } });
    if (BIG) await p.addInitScript(() => { try { localStorage.setItem('iacpatch.big', '1'); } catch (e) { /* */ } });
    const errs = [];
    p.on('pageerror', (e) => errs.push('pageerror: ' + e.message));
    p.on('console', (m) => { if (m.type() === 'error' && !/favicon/.test(m.text())) errs.push('console: ' + m.text()); });
    for (const [name, hash] of screens) {
      await p.goto('about:blank');
      await p.goto(BASE + hash, { waitUntil: 'networkidle' });
      await p.waitForTimeout(1200);
      const a = await p.evaluate(AUDIT);
      const bad = a.overflowX || a.wide.length || a.clipped.length || a.overlap.length;
      check(`${w}x${h}${BIG ? ' 크게' : ''} ${name} 넘침 · 잘림 · 겹침 없음`, !bad, bad ? { overflowX: a.overflowX, wide: a.wide.slice(0, 4), clipped: a.clipped.slice(0, 4), overlap: a.overlap.slice(0, 4) } : undefined);
      if (bad) await p.screenshot({ path: `${OUT}/${w}x${h}_${name}.png` });
      // 왼쪽 메뉴로 다음 단계로 넘어가 보기 (잠긴 단계는 잠긴 이유가 있어야 함)
    }
    // 메뉴 이동: 1→2→3→4→5 (기록 없이 6 은 잠김), 기록 열고 5→6→7→8
    await p.goto('about:blank'); await p.goto(BASE + '#p=webapp-3tier&s=2', { waitUntil: 'networkidle' }); await p.waitForTimeout(800);
    const seq = [];
    for (const n of [3, 4, 5, 6]) { await p.click(`#msteps button[data-go="${n}"]`).catch(() => {}); await p.waitForTimeout(500); seq.push(await p.evaluate(() => document.querySelector('#msteps button.cur em').textContent)); }
    check(`${w}x${h} 메뉴 이동 3→4→5, 기록 없이 6 은 잠김`, JSON.stringify(seq) === JSON.stringify(['3', '4', '5', '5']), seq);
    await p.goto('about:blank'); await p.goto(BASE + `#p=webapp-3tier&s=5&rec=${REC}`, { waitUntil: 'networkidle' }); await p.waitForTimeout(800);
    const seq2 = [];
    for (const n of [6, 7, 8, 2, 8]) { await p.click(`#msteps button[data-go="${n}"]`); await p.waitForTimeout(500); seq2.push(await p.evaluate(() => document.querySelector('#msteps button.cur em').textContent)); }
    check(`${w}x${h} 기록 열면 6→7→8, 2 로 돌아갔다 8 로`, JSON.stringify(seq2) === JSON.stringify(['6', '7', '8', '2', '8']), seq2);
    // 머리말 '다음 ▶' 로 끝까지
    await p.goto('about:blank'); await p.goto(BASE + `#p=webapp-3tier&s=2&rec=${REC}`, { waitUntil: 'networkidle' }); await p.waitForTimeout(800);
    const seq3 = [];
    for (let i = 0; i < 6; i++) { await p.click('.mh-nav .mbtn.primary'); await p.waitForTimeout(500); seq3.push(await p.evaluate(() => document.querySelector('#msteps button.cur em').textContent)); }
    check(`${w}x${h} 머리말 '다음 ▶' 로 2→8`, JSON.stringify(seq3) === JSON.stringify(['3', '4', '5', '6', '7', '8']), seq3);
    check(`${w}x${h} 화면 오류 없음`, errs.length === 0, errs.slice(0, 5));
    await p.close();
  }
  console.log(results.join('\n'));
  console.log(`\n${results.filter((x) => x.startsWith('PASS')).length}/${results.length} PASS`);
  await b.close();
})().catch((e) => { console.log(results.join('\n')); console.error('E2E ERROR:', e.message); process.exit(1); });
