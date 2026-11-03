// 업무 시나리오 E2E — 실패 갈래 (2026-11-02, 검토 문서 대응 7단계): AI 가 끝내 못 고침(GAVE_UP) → 사람이 고친 파일 제출 / 같은 수정안 반복(REPEATED) /
// AI 오류(AI_ERROR) / 실행 오류(TOOL_ERROR, AI 에게 다시 묻지 않음) / 검증 불가(UNDECIDABLE, 외부 prefix list) / ⑧ 끝맺음 세 줄 / PR 본문 맨 위 끝맺음.
// 3계층 예제 · 시험용 대역 claude(fakeclaude/mode.txt 로 갈래 선택) · 가짜 terraform 의 TF_FAIL 스위치. AWS 없음 · PR 실행 없음.
// 실행 전: e2e_restart.sh (AI 실행 기록 초기화)
const { chromium } = require('playwright');
const fs = require('fs');
const SP = '/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad';
const E = `${SP}/e2e`;
const SHOTS = process.argv[2] || `${E}/shots_scen`;
const BASE = 'http://127.0.0.1:8897/';
const MODE = `${E}/fakeclaude/mode.txt`;
const TF_FAIL = `${E}/bin/TF_FAIL`;
let pass = 0, fail = 0;
const check = (name, cond, info = '') => { if (cond) { pass++; console.log('PASS', name); } else { fail++; console.log('FAIL', name, '|', String(info).slice(0, 500)); } };
const setMode = (m) => { if (m) fs.writeFileSync(MODE, m); else if (fs.existsSync(MODE)) fs.unlinkSync(MODE); };

(async () => {
  fs.mkdirSync(SHOTS, { recursive: true });
  setMode(''); if (fs.existsSync(TF_FAIL)) fs.unlinkSync(TF_FAIL);
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = [];
  p.on('pageerror', (e) => errs.push('pageerror: ' + e.message));
  p.on('console', (m) => { if (m.type() === 'error' && !m.text().includes('status of 400')) errs.push('console: ' + m.text()); });
  p.on('response', (r) => { if (r.status() >= 400 && !r.url().includes('/api/decision')) errs.push(`http ${r.status()} ${r.url()}`); });
  const txt = async (sel) => (await p.$(sel)) ? (await p.innerText(sel)) : '';
  const shot = async (n) => { await p.waitForTimeout(300); await p.screenshot({ path: `${SHOTS}/${n}.png` }); };
  const open5 = async () => { await p.goto(BASE + '#p=webapp-3tier&s=5', { waitUntil: 'networkidle' }); await p.reload({ waitUntil: 'networkidle' }); await p.waitForSelector('.cands', { timeout: 30000 }); };
  const runAi = async () => {
    if (!(await p.$('[data-act="ai-run"]'))) await p.click('[data-src="ai"]');
    await p.waitForSelector('[data-act="ai-run"]:not([disabled])', { timeout: 15000 });
    await p.click('[data-act="ai-run"]');
    await p.waitForSelector('.mcard.run', { timeout: 10000 });
    await p.waitForFunction(() => !document.querySelector('.mcard.run'), null, { timeout: 400000 });
    await p.waitForTimeout(1200);
  };
  const airesult = async () => (await p.$('.airesult')) ? await p.$eval('.airesult', (x) => x.textContent) : '';

  // S5. AI 가 최대 시도까지 못 고침 (GAVE_UP) → 원본 그대로 · 사람이 고친 파일 제출 → 같은 검사 → 통과
  await open5();
  setMode('bad');
  await runAi();
  const r5 = await airesult();
  check('S5a GAVE_UP: 시도 3개 모두 막힘 · 결과 한 줄 = 수정안 부적합 + 다음: 고친 파일 올리기', (await p.$$('.cands [data-aiatt]')).length === 3 && r5.includes('수정안 부적합') && r5.includes('최대 시도') && r5.includes('고친 파일 올리기'), r5);
  check('S5b ⑤ 마지막 시도의 결과 = 막힘 (적용 승인 불가)', (await txt('.cmp-head')).includes('시도 3') && /승인 불가|차단|막힘/.test(await txt('.cmp-head')), await txt('.cmp-head'));
  await p.click('[data-go="8"]'); await p.waitForSelector('.closing', { timeout: 20000 });
  const cl5 = await txt('.closing');
  check('S5c ⑧ 끝맺음 세 줄: 확인한 것 · 결정(아직 없음) · 남은 것', cl5.includes('확인한 것') && cl5.includes('아직 결정 없음') && cl5.includes('남은 것') && (await p.$eval('[data-dec="APPROVED"]', (x) => x.disabled)), cl5);
  await shot('s5-gaveup');
  // 사람이 고친 파일 (팀 평가용 수정안 correct-design 의 내용) 을 원본 파일 이름으로 제출
  const fixed = `${SHOTS}/security_groups.tf`;
  fs.copyFileSync(`${E}/cap/experiments/candidate-sets/arch-3tier-sg/candidates/correct-design.tf`, fixed);
  await p.click('[data-go="5"]'); await p.waitForSelector('.cands', { timeout: 20000 });
  await p.click('[data-src="upload"]');
  await p.waitForSelector('#upFiles', { state: 'attached' });
  await p.setInputFiles('#upFiles', fixed);
  await p.waitForSelector('[data-act="run-upload"]:not([disabled])', { timeout: 30000 });
  check('S5d 제출 확인: security_groups.tf 가 원본과 달라 검사 대상', (await txt('.srcpanel')).includes('security_groups.tf'), await txt('.srcpanel'));
  await p.click('[data-act="run-upload"]');
  await p.waitForSelector('.mcard.run', { timeout: 10000 });
  await p.waitForFunction(() => !document.querySelector('.mcard.run'), null, { timeout: 400000 });
  await p.waitForTimeout(1200);
  const h5 = await txt('.cmp-head');
  check('S5e 직접 제출본 = 같은 8개 관문 → 배포 전 검사 통과 (다음: AWS 시험 환경 검사)', h5.includes('직접 제출') && h5.includes('배포 전 검사를 모두 통과') && h5.includes('AWS 시험 환경 검사'), h5);
  await p.click('[data-go="8"]'); await p.waitForSelector('.closing', { timeout: 20000 });
  const cl5b = await txt('.closing');
  check('S5f ⑧ 끝맺음: 확인한 것 = 배포 전 통과 · AWS 시험 환경 미실행, 승인 버튼은 시험 환경 검사 전이라 막힘', cl5b.includes('배포 전 검사(V1~V6)') && cl5b.includes('미검증') && (await p.$eval('[data-dec="APPROVED"]', (x) => x.disabled)) && (await txt('.lay8')).includes('AWS 시험 환경 검사'), [cl5b, (await txt('.lay8')).slice(0, 300)]);
  await shot('s5-manual');

  // S6. 같은 수정안 반복 (REPEATED): 시도 2 가 시도 1 과 같은 파일 → 검사 없이 중단
  await open5();
  setMode('repeat');
  await runAi();
  const r6 = await airesult();
  check('S6 REPEATED: 시도 2개 · 결과 = 같은 수정안 되풀이 → 중단 (검사 안 함)', r6.includes('같은 수정안') && r6.includes('되풀이') && (await txt('.cands')).includes('반복'), [r6, (await txt('.cands')).slice(0, 300)]);
  await shot('s6-repeated');

  // S7. AI 오류 (응답 없음) — 검사할 수정안 없음, 원본 그대로, 결과 한 줄은 그대로 보임
  await open5();
  setMode('error');
  await runAi();
  const r7 = await airesult();
  check('S7 AI_ERROR: 수정안 없음 · 결과 한 줄 = AI 오류 + 다음(설치 · 로그인 확인 / 고친 파일 제출) · 그림은 원본', !!(await p.$('.mcard.airun')) && r7.includes('AI 오류') && r7.includes('다음:') && !(await p.$('.cmp-head')), r7);
  await shot('s7-aierror');

  // S8. 실행 오류 (TOOL_ERROR): provider 를 못 받은 것처럼 terraform 이 실패 → 검사 계층 ERROR → AI 에게 다시 묻지 않고 중단
  await open5();
  setMode('');
  fs.writeFileSync(TF_FAIL, '1');
  const callsBefore = fs.existsSync(`${E}/fakeclaude/calls.jsonl`) ? fs.readFileSync(`${E}/fakeclaude/calls.jsonl`, 'utf8').split('\n').filter(Boolean).length : 0;
  await runAi();
  fs.unlinkSync(TF_FAIL);
  const callsAfter = fs.readFileSync(`${E}/fakeclaude/calls.jsonl`, 'utf8').split('\n').filter(Boolean).length;
  const r8 = await airesult();
  check('S8 TOOL_ERROR: 결과 = 실행 오류 · AI 호출 1번만(다시 묻지 않음) · 다음 = 환경 확인 후 같은 수정안 재검사', r8.includes('실행 오류') && r8.includes('AI 에게 다시 묻지 않음') && callsAfter - callsBefore === 1, [r8, callsAfter - callsBefore]);
  await shot('s8-toolerror');

  // S9. 검증 불가 (UNDECIDABLE): 출처가 외부 managed prefix list → plan 에서 펼칠 수 없음 → 사람 검토, AI 재요청 없음
  await open5();
  setMode('unknown');
  const calls9 = fs.readFileSync(`${E}/fakeclaude/calls.jsonl`, 'utf8').split('\n').filter(Boolean).length;
  await runAi();
  setMode('');
  const calls9b = fs.readFileSync(`${E}/fakeclaude/calls.jsonl`, 'utf8').split('\n').filter(Boolean).length;
  const r9 = await airesult();
  check('S9a UNDECIDABLE: 결과 = 검증 불가 · AI 호출 1번 · 다음 = 사람이 값 확인', r9.includes('검증 불가') && calls9b - calls9 === 1 && r9.includes('사람'), [r9, calls9b - calls9]);
  await p.click('[data-go="6"]'); await p.waitForSelector('.verdict', { timeout: 20000 });
  const v9 = await txt('#mbody');
  check('S9b ⑥ 고객 설계 질문 = 판정 불가 (prefix list 펼칠 수 없음) · 승인 불가', /판정 불가|알 수 없|확정할 수 없/.test(v9) && /pl-0123456789abcdef0|prefix/.test(v9), v9.slice(0, 600));
  await p.click('[data-go="8"]'); await p.waitForSelector('.closing', { timeout: 20000 });
  check('S9c ⑧ 승인 막힘 + 끝맺음 세 줄', (await p.$eval('[data-dec="APPROVED"]', (x) => x.disabled)) && (await txt('.closing')).includes('남은 것'), await txt('.closing'));
  await shot('s9-undecidable');

  // S10. 승인된 기록(시험 환경 확인까지 된 3계층 기록)의 PR 미리보기 본문 맨 위 = 끝맺음 세 줄 (실행 안 함)
  await p.goto(BASE + '#p=webapp-3tier&s=8&rec=20261023-124957-af6f0b', { waitUntil: 'networkidle' });
  await p.reload({ waitUntil: 'networkidle' });
  await p.waitForSelector('.final-grid', { timeout: 20000 });
  const cl10 = await txt('.closing');
  check('S10a ⑧ 시험 환경 확인된 기록의 끝맺음: 확인한 것에 AWS 시험 환경 확인됨 · 운영 반영 후 확인 아님', cl10.includes('AWS 시험 환경에서 확인됨') && cl10.includes('운영 반영 후 확인 아님'), cl10);
  if (!(await txt('.lay8')).includes('기록됨')) {
    await p.click('[data-dec="APPROVED"]'); await p.fill('#decReason', 'E2E 시나리오: 설계 일치 · 시험 환경 확인'); await p.fill('#decBy', '시나리오'); await p.click('[data-act="decide"]');
    await p.waitForSelector('.mtoast'); await p.waitForSelector('[data-act="pr-check"]', { timeout: 15000 });
  }
  await p.fill('#prBase', 'e2e-base');
  await p.click('[data-act="pr-check"]');
  await p.waitForFunction(() => document.querySelectorAll('.prchk li.ok').length >= 5 && !document.querySelector('.prchk li.bad'), null, { timeout: 20000 }).catch(() => {});
  if (await p.$('[data-act="pr-preview"]')) { await p.click('[data-act="pr-preview"]'); await p.waitForSelector('.prbody', { timeout: 60000 }); }
  const body10 = (await p.$('.prbody pre')) ? await p.$eval('.prbody pre', (x) => x.textContent) : '';
  check('S10b PR 본문 미리보기 맨 위 = 끝맺음 (확인한 것 · 결정 · 남은 것 · 병합 · apply 안 함)', body10.includes('끝맺음') && body10.includes('확인한 것') && body10.includes('결정:') && body10.includes('병합 · apply 는 하지 않았습니다'), body10.slice(0, 500));
  const cl10b = await txt('.closing');
  check('S10c ⑧ 끝맺음 결정 줄 = 승인 · 이름 · 시각, 남은 것 = PR → 병합 → 운영 반영은 프로그램 밖', cl10b.includes('승인') && cl10b.includes('운영 반영은 이 프로그램 밖'), cl10b);
  await shot('s10-pr-body');

  check('Z 화면 오류 없음', errs.length === 0, errs.slice(0, 5).join(' ; '));
  console.log(`\n${pass} PASS / ${fail} FAIL`);
  setMode('');
  await b.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { setMode(''); if (fs.existsSync(TF_FAIL)) fs.unlinkSync(TF_FAIL); console.error(e); process.exit(2); });
