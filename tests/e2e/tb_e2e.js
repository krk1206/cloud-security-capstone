// ⑦ AWS 시험 환경 (흐름 화면, 9차 D-43) E2E — 가짜 terraform · 가짜 aws (실제 AWS 없음). '다음 할 일' 칸의 버튼만 눌러 5단계를 처음부터 끝까지 간다.
// 전문가 화면 E2E(flow2e2e.js)와 같은 순서 · 같은 검사: 반영(apply · destroy)은 확인 창에서 사람이 체크 + [실행] 을 눌러야 하고, apply 는 plan 파일로만, 측정은 읽기만.
// 시간 흐름(apply 뒤 2~3분 대기)은 시험 환경 파일 · 상태 파일의 수정 시각을 과거로 옮겨 흉내 낸다.
const { chromium } = require('playwright');
const fs = require('fs');
const crypto = require('crypto');
const E = '/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad/e2e';
const ROOT = E + '/cap';
const TB = ROOT + '/scenarios/arch/webapp-3tier-testbed';
const OUT = E + '/shots_tb';
const BASE = 'http://127.0.0.1:8897/';
const REC_PASS = '20261022-185739-9c9b0f';   // 수정안 (배포 전 통과, plan 제자리 수정)
const REC_REPL = '20261022-185751-05ac43';   // 수정안 (배포 전 통과, plan 에서 교체 → 차단)
const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const ORIG_SHA = sha(ROOT + '/scenarios/arch/webapp-3tier/security_groups.tf');
const candSha = (rid) => sha(`${ROOT}/data/reviews/${rid}/candidate/security_groups.tf`);
const state = () => JSON.parse(fs.readFileSync(TB + '/terraform.tfstate', 'utf8'));
const calls = () => fs.existsSync(E + '/faketf_calls.jsonl') ? fs.readFileSync(E + '/faketf_calls.jsonl', 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : [];
const age = (sec) => { const t = Date.now() / 1000; fs.utimesSync(TB + '/security_groups.tf', t - sec - 200, t - sec - 200); fs.utimesSync(TB + '/terraform.tfstate', t - sec, t - sec); };
const results = [];
const check = (name, cond, extra) => { results.push(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra !== undefined ? '  — ' + (typeof extra === 'string' ? extra : JSON.stringify(extra)) : ''}`); };

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1366, height: 768 } });
  const errs = [], toasts = [], bodies = [];
  p.on('pageerror', (e) => errs.push('pageerror: ' + e.message));
  p.on('console', (m) => { if (m.type() === 'error') errs.push('console: ' + m.text()); });
  await p.exposeFunction('__toast', (t, c) => toasts.push({ t, c, at: Date.now() }));
  const waitToast = async (pred, from, ms = 90000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { const hit = toasts.slice(from).find(pred); if (hit) return hit; await p.waitForTimeout(150); } throw new Error('toast timeout; last: ' + JSON.stringify(toasts.slice(-4))); };
  const idle = async () => { await p.waitForFunction(() => !document.querySelector('.mcard.run'), null, { timeout: 120000 }); await p.waitForTimeout(700); };
  const guide = () => p.evaluate(() => {
    const c = document.querySelector('.mcard.guide'); if (!c) return null;
    const bs = [...c.querySelectorAll('.mnav .mbtn[data-tb]')];
    const li = [...document.querySelectorAll('.tbsteps li')];
    const cur = li.findIndex((x) => x.classList.contains('cur')) + 1;
    const past = li.filter((x) => x.classList.contains('past')).length;
    const marks = li.map((x) => (x.classList.contains('bad') ? 'X' : x.classList.contains('skip') ? '-' : x.classList.contains('past') ? 'v' : x.classList.contains('cur') ? 'o' : '.')).join('');
    return { marks, title: c.querySelector('h3').textContent, text: c.querySelector('h3 + p').textContent, cur, past, tone: c.className.replace('mcard', '').replace('guide', '').trim(),
      acts: bs.map((x) => `${x.dataset.tb}${x.dataset.kind ? ':' + x.dataset.kind : ''}${x.disabled ? '(off)' : ''}`), labels: bs.map((x) => x.textContent),
      wait: !!c.querySelector('.tbwait b'), waitTxt: (c.querySelector('.tbwait b') || {}).textContent || '', waitLine: (c.querySelector('.tbwait') || {}).textContent || '',
      meta: (c.querySelector('.tbmeta') || {}).textContent || '', body: document.querySelector('#mbody').innerText };
  });
  const waitGuide = async (pred, ms = 40000) => { const t0 = Date.now(); let g; while (Date.now() - t0 < ms) { g = await guide(); if (g) bodies.push(g.body); if (g && pred(g)) return g; await p.waitForTimeout(300); } throw new Error('guide timeout; last: ' + JSON.stringify(g && { ...g, body: undefined })); };
  const clickAct = async (act) => { await p.click(`.mcard.guide .mbtn[data-tb="${act}"]`); };
  const modalOpen = () => p.waitForFunction(() => document.querySelector('.mmodal #tbExec'), null, { timeout: 90000 });
  const execModal = async (name) => {
    await modalOpen();
    const title = await p.evaluate(() => document.querySelector('.mmodal .mm-h b').textContent);
    const txt = await p.evaluate(() => document.querySelector('.mmodal .mm-b').innerText);
    await (await p.$('.mmodal .mm-box')).screenshot({ path: `${OUT}/${name}_modal.png` });
    const off = await p.evaluate(() => document.querySelector('#tbExec').disabled);
    await p.check('#tbAck');
    const n = calls().length;
    await p.click('#tbExec');
    return { txt, title, off, n };
  };
  async function openRec(rid) {
    await p.goto('about:blank');      // 해시만 바뀌면 다시 읽지 않으므로(같은 문서 이동) 빈 페이지를 거쳐 새로 연다
    await p.goto(BASE + '#p=webapp-3tier&s=7&rec=' + rid, { waitUntil: 'networkidle' });
    await p.evaluate(() => new MutationObserver((ms) => ms.forEach((m) => m.addedNodes.forEach((n) => { if (n.classList && n.classList.contains('mtoast')) window.__toast(n.textContent, n.className.replace('mtoast', '').trim()); }))).observe(document.body, { childList: true }));
    await p.waitForSelector('.mcard.guide', { timeout: 30000 });
    await p.waitForTimeout(500);
  }
  let execs = 0;

  // A. 처음: 배포 없음, 시험 환경 파일 = correct-design (원본 아님) → 1단계 원본 반영 · 버튼 하나
  await openRec(REC_PASS);
  let g = await waitGuide((x) => x.cur === 1);
  await p.screenshot({ path: `${OUT}/a_step1.png`, fullPage: true });
  check('A 안내: 1단계 원본 반영 · 버튼 하나 (s2-deploy)', g.cur === 1 && g.acts.length === 1 && g.acts[0] === 's2-deploy' && /원본 반영/.test(g.title), { cur: g.cur, acts: g.acts, title: g.title });
  check('A 5칸 띠: 1칸 지금 · 사람 단계 3칸', g.marks === 'o....' && (await p.$$eval('.tbsteps li i.human', (x) => x.length)) === 3, g.marks);
  check('A 머리말 할 일: 버튼 순서 안내 (전문가 화면 아님)', /다음 할 일/.test(await p.evaluate(() => document.querySelector('#mhead, .mhead, header').innerText)) && !/전문가 화면에서 합니다/.test(await p.evaluate(() => document.body.innerText)));
  check('A 명령 보기는 접힌 상태', await p.evaluate(() => { const d = document.querySelector('details.tbcmd'); return !!d && !d.open; }));
  check('A 왼쪽 메뉴 링크 = 원본 증거 (전문가 화면)', (await p.evaluate(() => document.querySelector('#mexpert').textContent)) === '원본 증거 (전문가 화면)');

  // B. [원본 반영] → 파일을 원본으로 → plan → 확인 창(아직 반영 안 됨) → 사람이 체크하고 실행
  let k = toasts.length;
  await clickAct('s2-deploy');
  let r = await execModal('b_deploy'); execs++;
  check('B 원본 반영: 시험 환경 파일을 원본으로 바꿈', sha(TB + '/security_groups.tf') === ORIG_SHA);
  check('B 확인 창 제목: 실행 전 확인 (아직 반영 안 됨)', /실행 전 확인/.test(r.title) && /아직 반영 안 됨/.test(r.title), r.title);
  check('B 확인 창: [실행] 처음엔 꺼짐 · 생성 요약', r.off === true && /생성/.test(r.txt), r.txt.split('\n').slice(0, 3).join(' / '));
  await waitToast((t) => t.t.includes('원본 반영 완료') && t.c === 'good', k);
  await idle();
  check('B apply 뒤 리소스 > 0', state().resources.length > 0, state().resources.length);
  const apB = calls().slice(r.n).find((c) => c.argv[0] === 'apply');
  check('B apply 는 plan 파일로만 (-auto-approve 없음)', !!apB && /plan\.bin$/.test(apB.argv[apB.argv.length - 1]) && !apB.argv.includes('-auto-approve'), apB && apB.argv);

  // C. 수정 전 측정 대기 (apply 직후) — 측정 버튼 꺼짐 · 남은 시간 · 자동 측정 켜짐(반영 성공 뒤) · 끄기/켜기
  g = await waitGuide((x) => x.cur === 2);
  await p.screenshot({ path: `${OUT}/c_wait.png`, fullPage: true });
  check('C 안내: 2단계 수정 전 측정 대기 · 1칸 끝', g.cur === 2 && g.past === 1 && g.wait && /^\d:\d\d$/.test(g.waitTxt), { cur: g.cur, past: g.past, waitTxt: g.waitTxt });
  check('C 측정 버튼 꺼짐 (120초 전) · 이유 표시', g.acts[0] === 's2-measure:before(off)' && /경과 전 측정 불가/.test(g.body), g.acts);
  check('C 자동 측정 켜짐 (반영 성공 뒤)', /자동 측정/.test(g.waitLine) && /끄기/.test(g.waitLine), g.waitLine);
  await p.click('.mcard.guide [data-tb="tb-auto"]');
  g = await waitGuide((x) => /자동 측정 끔/.test(x.waitLine));
  check('C 자동 측정 끄기', /켜기/.test(g.waitLine), g.waitLine);
  await p.click('.mcard.guide [data-tb="tb-auto"]');
  g = await waitGuide((x) => /끄기/.test(x.waitLine));
  check('C 자동 측정 다시 켜기', /끄기/.test(g.waitLine));

  // D. 3분 지난 것으로 → 자동 측정(읽기 전용) 한 번 시작 → 끝나면 3단계 수정안 반영
  const nMeas = fs.readdirSync(ROOT + '/data/measurements').length;
  const nD = calls().length;
  k = toasts.length;
  age(200);
  await waitToast((t) => t.t.includes('자동 시작'), k, 30000);
  await waitToast((t) => t.t.includes('수정 전 측정 완료'), k, 90000);
  await idle();
  check('D 수정 전 측정 기록 생김', fs.readdirSync(ROOT + '/data/measurements').length === nMeas + 1);
  g = await waitGuide((x) => x.cur === 3);
  await p.screenshot({ path: `${OUT}/d_cand.png`, fullPage: true });
  check('D 안내: 3단계 수정안 반영 (s2-cand) · 2칸 끝', g.cur === 3 && g.past === 2 && g.acts[0] === 's2-cand' && /수정안 반영/.test(g.title), { cur: g.cur, acts: g.acts, title: g.title });
  check('D 자동 측정은 반영 한 번당 한 번', toasts.filter((t) => t.t.includes('자동 시작')).length === 1);
  check('D 측정 중 apply · plan 명령 없음', !calls().slice(nD).some((c) => ['apply', 'plan'].includes(c.argv[0])), calls().slice(nD).map((c) => c.argv[0]));

  // E. [수정안 반영 시작] → 수정안 파일 넣기 → plan 확인(CLEAN) → 확인 창이 바로 열림 → 사람이 실행
  const nE = calls().length;
  k = toasts.length;
  await clickAct('s2-cand');
  r = await execModal('e_cand'); execs++;
  check('E 수정안 파일을 시험 환경에 넣음', sha(TB + '/security_groups.tf') === candSha(REC_PASS));
  check('E 확인 창: 수정안 반영 · 제자리 수정', /수정안 반영/.test(r.title) && /제자리 수정/.test(r.txt), r.title);
  check('E plan 확인은 plan · show 만 (apply 없음)', JSON.stringify(calls().slice(nE, r.n).map((c) => c.argv[0])) === JSON.stringify(['plan', 'show']), calls().slice(nE, r.n).map((c) => c.argv[0]));
  await waitToast((t) => t.t.includes('수정안 반영 완료') && t.c === 'good', k);
  await idle();
  const apE = calls().slice(r.n).filter((c) => c.argv[0] !== 'show');
  check('E 수정안 apply = plan 확인 때 만든 plan 파일 그대로', apE.length === 1 && apE[0].argv[0] === 'apply' && /plan\.bin$/.test(apE[0].argv[apE[0].argv.length - 1]), apE.map((c) => c.argv.join(' ')));

  // F. 수정 후 측정 대기 → 2분 지난 것으로 → 자동 측정 → 5단계 삭제
  g = await waitGuide((x) => x.cur === 4);
  check('F 안내: 4단계 수정 후 측정 대기 · 3칸 끝', g.cur === 4 && g.past === 3 && g.wait && g.acts[0] === 's2-measure:after(off)', { cur: g.cur, past: g.past, acts: g.acts });
  k = toasts.length;
  age(140);
  await waitToast((t) => t.t.includes('수정 후 측정 완료'), k, 90000);
  await idle();
  check('F 기록에 수정 후 측정 폴더', fs.existsSync(`${ROOT}/data/reviews/${REC_PASS}/postdeploy`) && fs.readdirSync(`${ROOT}/data/reviews/${REC_PASS}/postdeploy`).length === 1);
  g = await waitGuide((x) => x.cur === 5);
  await p.screenshot({ path: `${OUT}/f_destroy.png`, fullPage: true });
  check('F 안내: 5단계 시험 환경 삭제 (s2-destroy, 4칸 끝)', g.cur === 5 && g.past === 4 && g.acts[0] === 's2-destroy', { cur: g.cur, past: g.past, acts: g.acts });
  // 가짜 aws 는 자격증명 오류를 내므로 측정 결과는 '판정 불가'(UNVERIFIED) — 결과 칸은 기록의 상태를 그대로 보여야 한다 (숨기지 않음)
  const pdF = JSON.parse(fs.readFileSync(`${ROOT}/data/reviews/${REC_PASS}/state.json`, 'utf8')).post_deploy || {};
  check('F 결과 칸 = 기록의 시험 환경 상태 그대로 (가짜 aws → 판정 불가)', pdF.status === 'UNVERIFIED' && /AWS 시험 환경 판정 불가/.test(g.body) && (await p.$$eval('.tbresult .flist li', (x) => x.length)) === 2, pdF.status);

  // G0. destroy plan 만 만들고 확인 창을 닫음 → '취소' 알림, 상태 그대로 (10-27 실제 사례)
  const nG0 = calls().length;
  k = toasts.length;
  await clickAct('s2-destroy');
  await modalOpen();
  const g0 = await p.evaluate(() => ({ title: document.querySelector('.mmodal .mm-h b').textContent, txt: document.querySelector('.mmodal .mm-b').innerText }));
  check('G0 확인 창: 삭제 예정 · 아직 반영 안 됨 (완료로 읽히지 않게)', /아직 반영 안 됨/.test(g0.title) && /삭제 예정/.test(g0.txt) && /아직 아무것도 바뀌지 않았습니다/.test(g0.txt), g0.title);
  await p.click('.mmodal [data-close].mbtn');
  await waitToast((t) => t.t.includes('취소 — 반영하지 않음'), k, 10000);
  await idle();
  check('G0 취소: apply 없음 · 리소스 그대로', !calls().slice(nG0).some((c) => c.argv[0] === 'apply') && state().resources.length > 0, calls().slice(nG0).map((c) => c.argv[0]));
  g = await waitGuide((x) => x.cur === 5);
  check('G0 취소 뒤 안내: 여전히 5단계 시험 환경 삭제', g.acts[0] === 's2-destroy', g.acts);

  // G. [시험 환경 삭제] → plan -destroy → 확인 창(빨강 버튼) → 실행 → 파일 원본 복원 → 완료 표시
  const nG = calls().length;
  k = toasts.length;
  await clickAct('s2-destroy');
  const danger = await p.evaluate(async () => { await new Promise((r2) => { const t = setInterval(() => { if (document.querySelector('.mmodal #tbExec')) { clearInterval(t); r2(); } }, 100); }); return document.querySelector('#tbExec').classList.contains('danger'); });
  r = await execModal('g_destroy'); execs++;
  check('G 확인 창: 삭제 요약 · 빨간 [destroy 실행]', /삭제|destroy/.test(r.txt) && danger && /시험 환경 삭제/.test(r.title), r.title);
  await waitToast((t) => t.t.includes('시험 환경 삭제 완료') && t.t.includes('원본으로 복원'), k);
  await idle();
  check('G 리소스 0 · 파일 원본', state().resources.length === 0 && sha(TB + '/security_groups.tf') === ORIG_SHA);
  const cG = calls().slice(nG).map((c) => c.argv[0]);
  check('G plan -destroy → show → apply <plan 파일>', JSON.stringify(cG) === JSON.stringify(['plan', 'show', 'apply']) && calls().slice(nG)[0].argv.includes('-destroy'), cG);
  g = await waitGuide((x) => x.past === 5);
  await p.screenshot({ path: `${OUT}/g_done.png`, fullPage: true });
  check('G 안내: 검사 끝 — 판정 불가 (5칸 끝 · ⑤ 다른 수정안 · 원본 다시 반영; 확인됨이면 ⑧ 결정 버튼)', g.past === 5 && /검사 끝/.test(g.title) && /판정 불가/.test(g.title) && g.acts[0] === 's2-pick' && g.acts.includes('s2-deploy'), { title: g.title, acts: g.acts });

  // H. 교체가 나오는 수정안: 원본 반영 → (측정은 이미 한 것으로) → 수정안 반영 → plan 차단 → 확인 창 안 열림 → 삭제
  await openRec(REC_REPL);
  g = await waitGuide((x) => x.cur === 1);
  k = toasts.length;
  await clickAct('s2-deploy');
  r = await execModal('h_deploy'); execs++;
  await waitToast((t) => t.t.includes('원본 반영 완료') && t.c === 'good', k);
  await idle();
  age(200);
  g = await waitGuide((x) => x.cur === 3, 90000);
  const nH = calls().length;
  const nT = toasts.length;
  await clickAct('s2-cand');
  const tb = await waitToast((t) => t.t.includes('반영하지 않음') || t.t.includes('계획 확인'), nT);
  await idle();
  check('H plan 확인 = 교체 → 차단 (bad 알림)', tb.c === 'bad' && /교체/.test(tb.t), tb.t);
  check('H 확인 창 안 열림', !(await p.$('.mmodal')));
  check('H apply 없음 (plan · show 만)', JSON.stringify(calls().slice(nH).map((c) => c.argv[0])) === JSON.stringify(['plan', 'show']), calls().slice(nH).map((c) => c.argv[0]));
  g = await waitGuide((x) => x.cur === 5);
  await p.screenshot({ path: `${OUT}/h_blocked.png`, fullPage: true });
  check('H 안내: 수정안 반영 차단 → 삭제 + 다른 수정안 (⑤)', g.tone === 'bad' && g.acts[0] === 's2-destroy' && g.acts.includes('s2-pick') && /차단/.test(g.title), { tone: g.tone, acts: g.acts, title: g.title });
  check('H 진행 표시: 반영 ✕ · 수정 후 측정 안 함 (끝 아님)', g.marks === 'vvX-o', g.marks);
  check('H 결과 칸: 반영 전 차단', /반영 전 차단/.test(g.body));
  k = toasts.length;
  await clickAct('s2-destroy');
  r = await execModal('h_destroy'); execs++;
  await waitToast((t) => t.t.includes('시험 환경 삭제 완료'), k);
  await idle();
  g = await waitGuide((x) => x.past === 5 || x.marks.includes('X'));
  check('H 삭제 뒤 안내: 검사 끝 — 차단 (⑤ 다른 수정안)', /검사 끝/.test(g.title) && /차단/.test(g.title) && g.acts[0] === 's2-pick', { title: g.title, acts: g.acts });

  // I. 전체: apply 수 = 사람이 [실행] 을 누른 수, terraform destroy 명령 없음, 화면 오류 없음, 말(D-39): 후보 · 배포 라는 말 없음
  const applies = calls().filter((c) => c.argv[0] === 'apply').length;
  check('I apply 명령 수 = 사람이 확인 창에서 실행한 수', applies === execs, `${applies} / ${execs}`);
  check('I terraform destroy 명령은 쓰지 않음 (plan -destroy + apply)', !calls().some((c) => c.argv[0] === 'destroy'));
  check('I 남은 plan 파일 없음', !fs.existsSync('/tmp/iacpatch-plans') || fs.readdirSync('/tmp/iacpatch-plans').length === 0);
  check('I 화면 오류 없음', errs.length === 0, errs);
  const leak = bodies.map((t) => (t.match(/후보|원본 배포|후보 반영/g) || []).length).reduce((a, c) => a + c, 0);
  check('I ⑦ 화면에 전문가 화면 말(후보 · 배포) 없음 (D-39)', leak === 0, leak);
  fs.writeFileSync(`${OUT}/toasts.json`, JSON.stringify(toasts, null, 1));
  console.log(results.join('\n'));
  console.log(`\n${results.filter((x) => x.startsWith('PASS')).length}/${results.length} PASS`);
  await b.close();
})().catch((e) => { console.log(results.join('\n')); console.error('E2E ERROR:', e.message); process.exit(1); });
