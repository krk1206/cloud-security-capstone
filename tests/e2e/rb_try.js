// D-45 설계도대로 자동 수정 (규칙 기반): 연습 저장소(board_repo) 연결 → ④ SSH 공개 고르기 → ⑤ v1(자동 초안, SSH 화살표 없음) 에서 누르면 '막힘 + 이유'
// → ③ 이 IP만 허용 → v2 저장 → 확정 → ⑤ 다시 누르면 통과 → ⑥ 결론. 실제 trivy · tofu(오프라인), AWS · AI 없음.
const { chromium } = require('playwright');
const SP = '/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad';
const BASE = 'http://127.0.0.1:8897/';
const UP = `${SP}/board_repo`;
const SHOTS = `${SP}/e2e/shots_rb`;
let pass = 0, fail = 0;
const check = (name, cond, info = '') => { if (cond) { pass++; console.log('PASS', name); } else { fail++; console.log('FAIL', name, '|', String(info).slice(0, 500)); } };
(async () => {
  require('fs').mkdirSync(SHOTS, { recursive: true });
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = [];
  p.on('pageerror', (e) => errs.push('pageerror: ' + e.message + ' @ ' + String(e.stack || '').split('\n').slice(0, 3).join(' / ')));
  p.on('console', (m) => { if (m.type() === 'error' && !/status of (400|403)/.test(m.text())) errs.push('console: ' + m.text()); });
  const txt = async (sel) => (await p.$(sel)) ? (await p.innerText(sel)) : '';
  const shot = async (n) => { await p.waitForTimeout(300); await p.screenshot({ path: `${SHOTS}/${n}.png`, fullPage: true }); };
  const waitRun = () => p.waitForFunction(() => !document.querySelector('.mcard.run') && document.querySelector('.cmp-line, .mcard.guide.ok, .mcard.guide.bad, .mcard.guide.warn'), null, { timeout: 300000 });

  // 연결 → 점검
  await p.goto(BASE, { waitUntil: 'networkidle' });
  await p.click('[data-act="np-open"]');
  await p.fill('#npName', '게시판 인프라');
  await p.fill('#npPath', UP);
  await p.click('[data-act="np-check"]');
  await p.waitForFunction(() => ((document.querySelector('.np-info') || {}).textContent || '').includes('연결할 수 있음'), null, { timeout: 8000 }).catch(() => {});
  await p.click('[data-act="np-create"]');
  await p.waitForSelector('#tInfra [data-node]', { timeout: 240000 });
  await p.waitForTimeout(800);
  const pid = (await p.evaluate(() => location.hash)).match(/p=([^&]+)/)[1];
  console.log('pid', pid);

  // ④ SSH 공개 → 이 문제 고치기
  await p.click('#msteps button[data-go="4"]'); await p.waitForTimeout(900);
  let hit = false;
  for (const it of await p.$$('.iitem')) { if ((await it.innerText()).includes('SSH · RDP 를 모든 IP')) { await it.click(); hit = true; break; } }
  check('R1 ④ SSH 공개 문제 있음', hit);
  await p.waitForTimeout(400);
  await p.click('[data-fix]'); await p.waitForTimeout(900);

  // ⑤ v1(자동 초안) 기준: 버튼 · 안내 있음 → 누르면 막힘 + 이유 (SSH 화살표가 설계도에 없음)
  const g0 = await txt('.mh-todo');
  check('R2 ⑤ 할 일에 [설계도대로 자동 수정] + 아래 다른 방법 줄에 그 단추 (17차: 같은 단추를 되풀이하던 \'다음 할 일\' 칸은 뺌)', !!(await p.$('.cg.rb [data-act="run-rb"]')) && g0.includes('설계도대로 자동 수정') && !(await p.$('#mbody .mcard.guide')), g0.slice(0, 300));
  const row0 = await txt('.cg.rb');
  check('R3 ⑤ 수정안 줄에 "설계도대로 자동 수정 · 규칙 기반 · AI 아님" · 아직 없음', row0.includes('규칙 기반') && row0.includes('AI 아님') && row0.includes('아직 없음'), row0);
  await shot('r-s5-before');
  await p.click('.cg.rb [data-act="run-rb"]');
  await p.waitForSelector('.mcard.run', { timeout: 10000 });
  const runLabel = await txt('.mcard.run h3');
  check('R4 실행 칸: "설계도 v1 대로 자동 수정 (규칙 기반)"', runLabel.includes('설계도 v1 대로 자동 수정 (규칙 기반)'), runLabel);
  await waitRun(); await p.waitForTimeout(800);
  const g1 = await txt('.mcard.guide');
  const head1 = await txt('.cmp-line');
  check('R5 v1 기준 결과 한 줄: 규칙 기반 자동 수정 — 수정안 없음 · 고칠 수 없음 (17차: 결과는 한 줄, \'다음 할 일\' 칸 없음)', head1.includes('규칙 기반 자동 수정') && head1.includes('고칠 수 없습니다') && head1.includes('수정안 없음') && !g1, (g1 + ' || ' + head1).slice(0, 500));
  const row1 = await txt('.cg.rb');
  check('R6 수정안 줄: 최근 결과 ? 수정안 없음', row1.includes('최근 결과') && row1.includes('수정안 없음'), row1);
  await p.click('#msteps button[data-go="6"]'); await p.waitForSelector('.verdict', { timeout: 20000 });
  const v1 = await txt('.verdict');
  const why1 = await txt('#mbody');
  check('R7 ⑥ 결론 "규칙 기반으로는 이 문제를 고칠 수 없습니다" + 이유 포트 22 · 다음 할 일 ③', v1.includes('규칙 기반으로는 이 문제를 고칠 수 없습니다') && why1.includes('포트 22') && why1.includes('규칙 기반은 규칙을 지우지 않음') && why1.includes('③ 설계도에 이 계층으로 들어오는 통신(출처 IP)을 그리고 다시 누르거나'), (v1 + ' || ' + why1).slice(0, 700));
  await shot('r-s6-blocked');

  // ③ 이 IP만 허용 (관리자 사무실) → v2 → 확정
  await p.click('#msteps button[data-go="3"]'); await p.waitForSelector('#tMap [data-node]', { timeout: 20000 });
  const row = 'li.frow.fix:has([data-fr="ip"])';
  await p.click(`${row} [data-fr="ip"]`);
  await p.fill(`${row} [data-i="cidr"]`, '203.0.113.0/24');
  await p.fill(`${row} [data-i="label"]`, '관리자 사무실');
  await p.click(`${row} [data-fr="ip-ok"]`);
  await p.waitForFunction(() => document.querySelector('.ssave') && !document.querySelector('.ssave [data-act="s-save"]').disabled, null, { timeout: 15000 });
  await p.fill('#sNote', '점프 서버 SSH 는 관리자 사무실에서만');
  await p.click('.mcard.guide [data-act="s-save"]');
  await p.waitForSelector('.mtoast'); check('R8 ③ 저장 → v2', (await txt('.mtoast')).includes('v2'), await txt('.mtoast'));
  await p.waitForTimeout(1000);
  await p.click('.mcard.guide [data-act="s-confirm"]');
  await p.fill('#cfBy', '홍길동'); await p.click('#cfGo');
  await p.waitForFunction(() => (document.querySelector('.mtoast') || {}).textContent?.includes('확정'), null, { timeout: 15000 });
  check('R9 ③ v2 확정', (await txt('.mtoast')).includes('확정'), await txt('.mtoast'));
  await p.waitForTimeout(800);

  // ⑤ v2 기준: 다시 누르면 통과
  await p.click('#msteps button[data-go="5"]'); await p.waitForTimeout(900);
  const row2 = await txt('.cg.rb');
  check('R10 ⑤ 이전 결과 칩에 "이전 설계도 기준" 표시', row2.includes('이전 설계도 기준'), row2);
  await p.click('.cg.rb [data-act="run-rb"]');
  await p.waitForSelector('.mcard.run', { timeout: 10000 });
  check('R11 실행 칸: v2', (await txt('.mcard.run h3')).includes('설계도 v2 대로'), await txt('.mcard.run h3'));
  await waitRun(); await p.waitForTimeout(800);
  const g2 = await txt('.cmp-line');
  check('R12 v2 기준 결과 한 줄: 규칙 기반 자동 수정 · 배포 전 검사를 모두 통과', g2.includes('규칙 기반 자동 수정') && g2.includes('배포 전 검사를 모두 통과'), g2.slice(0, 300));
  const pd = await txt('.pdiff');
  check('R13 그림(적용 후): 설계도와 같음', pd.includes('설계도와 같음') && (await p.$$('#tPic .a-x')).length === 0, pd);
  const det = await txt('.cmp-grid');
  check('R14 해결: Trivy AVD-AWS-0107', det.includes('해결 · Trivy'), det.slice(0, 400));
  const row3 = await txt('.cg.rb');
  check('R15 수정안 줄: 최근 결과 ✓ 통과', row3.includes('통과') && !row3.includes('이전 설계도 기준'), row3);
  await shot('r-s5-pass');
  // 기록의 출처 글: 규칙 기반 · 설계도 화살표
  await p.click('#msteps button[data-go="6"]'); await p.waitForSelector('.verdict', { timeout: 20000 });
  const v2 = await txt('.verdict');
  check('R16 ⑥ 결론 good', (await p.$eval('.verdict', (x) => x.className)).includes('good'), v2.slice(0, 200));
  await p.click('#msteps button[data-go="8"]'); await p.waitForSelector('.final-grid', { timeout: 20000 });
  const f8 = await txt('#mbody');
  check('R17 ⑧ 결정 칸 \'대상:\' = 규칙 기반 자동 수정 (17차: 결론 칸을 빼면서 옮김)', /규칙 기반/.test(await txt('.dec-target')) && /규칙 기반/.test(f8), (await txt('.dec-target')) + ' | ' + f8.slice(0, 300));
  await shot('r-s8');
  check('R18 화면 오류 없음', errs.length === 0, errs.slice(0, 5));
  console.log(`\n${pass}/${pass + fail} PASS`);
  await b.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
