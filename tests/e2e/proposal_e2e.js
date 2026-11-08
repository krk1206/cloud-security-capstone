// D-46 고객 제안서 예제: ① '고객 제안서로 해 보기' → ② 점검(실제 tofu 오프라인 plan · trivy) → ③ 제안서 원문 + 설계도 v1 초안 → 담당자 확정
// → ④ SSH 공개 → ⑤ 설계도대로 자동 수정(규칙 기반) → 통과 → ⑥ good → ⑧ 승인(실제 AWS 미검증 확인) → PR 준비 확인 (예제 = 시연용 PR 줄) → 미리보기. AWS · AI 없음.
const { chromium } = require('playwright');
const SP = '/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad';
const BASE = 'http://127.0.0.1:8897/';
const SHOTS = `${SP}/e2e/shots_proposal`;
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
  const waitRun = () => p.waitForFunction(() => !document.querySelector('.mcard.run') && document.querySelector('.cmp-line, .mcard.airun, .mcard.guide.warn'), null, { timeout: 300000 });

  // ① 시작 카드
  await p.goto(BASE, { waitUntil: 'networkidle' });
  const cards = await txt('.pgrid');
  check('P1 ① 시작 = 고객 요청 3줄 + 다른 예제 카드 1개 · 게시판 카드는 숨김 (13차 D-49 · 15차 D-51 · 16차 D-52 요청함)', (await p.$$('.ibrow')).length === 3 && (await p.$$('.pcard')).length === 1 && !(await p.$('[data-open="board-saas"]')) && !(await p.$('.mstart')), cards.slice(0, 300));
  const hid = await p.evaluate(async () => (await (await fetch('/api/p/projects?all=1')).json()).projects.find((x) => x.id === 'board-saas'));
  check('P2 숨긴 게시판 예제: 목록(?all=1) 에는 있고 이름표 = 고객 제안서', !!hid && hid.proposal_label === '고객 제안서', JSON.stringify(hid || {}).slice(0, 300));
  await shot('p-start');
  await p.goto(BASE + '#p=board-saas&s=2', { waitUntil: 'networkidle' });
  await p.reload({ waitUntil: 'networkidle' });          // 주소(#p=…)는 처음 열 때만 읽는다 — 숨긴 예제는 ?all=1 목록에서 찾아 연다
  await p.waitForTimeout(1200);
  // ② 점검 (처음이라 plan 없음)
  const s2 = await txt('#mbody');
  if (s2.includes('점검 실행')) { await p.click('[data-act="scan"]'); }
  await p.waitForSelector('#tInfra [data-node]', { timeout: 300000 });
  await p.waitForTimeout(800);
  check('P3 ② 리소스 16 · 위험 1 (왼쪽 메뉴 ② 밑 — 17차: 그림 아래 숫자 칸 뺌)', (await txt('#msteps button[data-go="2"]')).includes('리소스 16개') && /위험 1/.test(await txt('#msteps button[data-go="2"]')), await txt('#msteps button[data-go="2"]'));

  // ③ 제안서 + 초안 확정
  await p.click('#msteps button[data-go="3"]'); await p.waitForSelector('#tMap [data-node]', { timeout: 30000 }); await p.waitForTimeout(600);
  const g3 = await txt('.mcard.guide');
  check('P4 ③ 다음 할 일: 고객 제안서에서 옮긴 설계도 v1 초안 — 확인하고 확정', g3.includes('고객 제안서에서 옮긴 설계도 v1 초안') && !!(await p.$('.mcard.guide [data-act="s-confirm"]')), g3.slice(0, 300));
  const pr = await txt('.mcard.proposal');
  check('P5 ③ 고객 제안서 원문 칸: 보안 조건 1~5 · 본사 사무실 203.0.113.0/24', pr.includes('고객 제안서') && pr.includes('본사 사무실(203.0.113.0/24)') && pr.includes('데이터베이스(3306)는 웹 서버에서만') && pr.includes('사람이 검토 · 승인한 뒤에만'), pr.slice(0, 500));
  const cb = await txt('.mcard.confirm');
  check('P6 ③ 확정 칸: 초안 · 제안서를 옮긴 초안 문구', cb.includes('초안 — 아직 확정 전') && cb.includes('고객 제안서의 허용 통신을 옮긴 초안'), cb);
  const sd = await txt('.sdiff');
  check('P7 ③ 지금 코드와 다른 곳 1개 (인터넷 → 점프 서버 :22)', sd.includes('1개') && (await p.$$eval('li.frow.fix .fr-path', (xs) => xs.map((x) => x.innerText))).some((t) => t.includes(':22')), sd);
  check('P8 ③ 머리말 태그: 원하는 구조 v1 · 초안', (await txt('.mh-ver')).includes('초안'), await txt('.mh-ver'));
  await shot('p-s3');
  await p.click('.mcard.guide [data-act="s-confirm"]');
  await p.fill('#cfBy', '김담당'); await p.click('#cfGo');
  await p.waitForFunction(() => (document.querySelector('.mtoast') || {}).textContent?.includes('확정'), null, { timeout: 15000 });
  await p.waitForTimeout(900);
  const g3b = await txt('.mcard.confirm');
  check('P9 ③ 확정 → 확정된 설계도 v1 · 김담당 확정 · \'다음 할 일\' 칸 없음 · 제안서 원문 접힘 (17차)', g3b.includes('확정된 설계도 v1') && g3b.includes('김담당') && !(await p.$('.mcard.guide')) && !(await p.$eval('details.proposal', (x) => x.open)), g3b.slice(0, 200));
  check('P10 ③ 머리말 태그: 확정', (await txt('.mh-ver')).includes('확정'), await txt('.mh-ver'));
  // 확정하면 수정안 4개를 미리 분석하기 시작한다 (배경, D-47) — ④ 를 보는 동안 돈다. ⑤ 에서는 끝날 때까지 기다린 뒤 확인

  // ④ → ⑤ 규칙 기반
  await p.click('#msteps button[data-go="4"]'); await p.waitForTimeout(900);
  let hit = false;
  for (const it of await p.$$('.iitem')) { if ((await it.innerText()).includes('SSH · RDP 를 모든 IP')) { await it.click(); hit = true; break; } }
  check('P11 ④ SSH 공개 문제 있음', hit);
  const viol = await txt('#mbody');
  check('P12 ④ 설계 위반 1 (제안서 조건 밖 통신)', /설계 위반/.test(viol), viol.slice(0, 300));
  await p.waitForTimeout(400);
  await p.click('[data-fix]'); await p.waitForTimeout(900);
  check('P13 ⑤ 고칠 문제 = bastion · 기준 = 원하는 구조 v1', (await txt('.target')).includes('aws_security_group.bastion') && (await txt('.target')).includes('v1'), await txt('.target'));
  check('P14 ⑤ 수정안 4개 큰 버튼 · 설계도대로 자동 수정 줄 있음 · 팀 평가용 목록 없음', (await p.$$('.tbig .cbig')).length === 4 && !!(await p.$('.cg.rb [data-act="run-rb"]')) && !(await p.$('.tlist')), await txt('.cands'));
  await p.waitForFunction(() => !document.querySelector('.pfx.run'), null, { timeout: 420000 });
  await p.waitForTimeout(600);
  const bigs = await p.$$eval('.tbig .cbig', (xs) => xs.map((x) => x.innerText.replace(/\s+/g, ' ')));
  check('P14b ⑤ 미리 분석 끝: 4개 모두 결과 있음 — 통과 1 (설계도대로) · 막힘 3', bigs.every((t) => !t.includes('분석 전')) && bigs.filter((t) => t.includes('통과')).length === 1 && bigs.filter((t) => t.includes('막힘')).length === 3, bigs);
  check('P14b2 ⑤ 고르기 전: 그림 하나 = 고객 설계도 (12차 D-48) · 나란히 그림 없음', (await txt('.mc-head b')).includes('고객 설계도') && !(await p.$('.pair')) && (await p.$$('#tPic [data-node]')).length >= 4, await txt('.mc-head'));
  await p.click('[data-cand="fix-office"]');
  await p.waitForFunction(() => (document.querySelector('.mc-head b') || {}).textContent?.includes('수정안 3 적용 후'), null, { timeout: 20000 });
  await p.waitForSelector('#tPic [data-node]', { timeout: 20000 });
  check('P14c ⑤ 수정안 3 (본사 사무실만) 누르면 같은 그림이 적용 후로 · 설계도와 같음 · 빨강 없음', (await txt('.pdiff')).includes('설계도와 같음') && (await p.$$('#tPic .a-x')).length === 0 && (await p.$$('#tPic .al.fl.st-excess')).length === 0, await txt('.pdiff'));
  await p.click('[data-cand="remove-rule"]');
  await p.waitForFunction(() => (document.querySelector('.pdiff') || {}).textContent && document.querySelector('.pdiff').textContent.includes('설계도에 있는데 막힘'), null, { timeout: 15000 });
  check('P14d ⑤ 수정안 4 (규칙 삭제) 누르면 그림이 바뀜 — 본사 사무실 → bastion 이 설계도에 있는데 막힘 (빨간 점선 · 상자 점선)', (await txt('.pdiff')).includes('설계도에 있는데 막힘') && /bastion :22/.test(await txt('.pdiff')) && (await txt('.mc-head b')).includes('수정안 4 적용 후') && (await p.$$('#tPic .al.fl.ghost.st-missing')).length >= 1 && (await p.$$('#tPic .fnode.ghost')).length >= 1, await txt('.pdiff'));
  await p.click('[data-cand="fix-and-db-open"]');
  await p.waitForFunction(() => (document.querySelector('.pdiff') || {}).textContent && document.querySelector('.pdiff').textContent.includes(':3306'), null, { timeout: 15000 });
  check('P14e ⑤ 수정안 2 (DB 공개 추가) — 설계도에 없는 통신 :3306 빨강 ✕', (await txt('.pdiff')).includes('설계도에 없는 통신') && (await p.$$('#tPic .a-x')).length >= 1 && (await txt('.mc-head b')).includes('수정안 2 적용 후'), await txt('.pdiff'));
  await p.click('[data-pv="design"]'); await p.waitForTimeout(400);
  check('P14f ⑤ [고객 설계도] → 같은 자리에서 설계도 (빨강 없음) · 다시 [적용 후]', (await txt('.mc-head b')).includes('고객 설계도') && (await p.$$('#tPic .a-x')).length === 0, await txt('.mc-head'));
  await p.click('[data-pv="after"]'); await p.waitForTimeout(300);
  await p.click('[data-cand="fix-office"]');
  await p.waitForFunction(() => (document.querySelector('.mc-head b') || {}).textContent?.includes('수정안 3 적용 후'), null, { timeout: 20000 });
  check('P14g ⑤ 다른 번호를 누르면 그림은 다시 적용 후 (설계도 보기 상태가 남지 않음)', (await txt('.mc-head b')).includes('수정안 3 적용 후'), await txt('.mc-head'));
  await p.click('[data-cand="fix-and-db-open"]');
  await p.waitForFunction(() => (document.querySelector('.pdiff') || {}).textContent && document.querySelector('.pdiff').textContent.includes(':3306'), null, { timeout: 15000 });
  await p.click('.cg.rb [data-act="run-rb"]');
  await p.waitForSelector('.mcard.run', { timeout: 10000 });
  await waitRun(); await p.waitForTimeout(800);
  const g5 = await txt('.cmp-line');
  check('P15 ⑤ 규칙 기반 자동 수정 — 배포 전 검사 통과 (결과 한 줄)', g5.includes('규칙 기반') && g5.includes('배포 전 검사를 모두 통과'), g5.slice(0, 300));
  check('P16 ⑤ 설계도와 같음 · 기준은 머리말 \'원하는 구조 v1 · 확정\' (17차: 같은 말을 하던 \'기준\' 칸 뺌)', (await txt('.pdiff')).includes('설계도와 같음') && !(await p.$('.basis')) && (await txt('.mh-ver')).includes('확정'), (await txt('.pdiff')) + ' | ' + (await txt('.mh-ver')));
  await shot('p-s5');
  // ⑥ ⑧
  await p.click('#msteps button[data-go="6"]'); await p.waitForSelector('.verdict', { timeout: 20000 });
  check('P17 ⑥ 결론 good · 질문 5 = 예, 지킴', (await p.$eval('.verdict', (x) => x.className)).includes('good') && (await p.$$eval('.qrow .qh', (xs) => xs.map((x) => x.innerText))).some((t) => t.includes('고객이 원하는 통신 구조') && t.includes('예, 지킴')), await p.$$eval('.qrow .qh', (xs) => xs.map((x) => x.innerText.replace(/\n/g, ' '))));
  await p.click('#msteps button[data-go="8"]'); await p.waitForSelector('.final-grid', { timeout: 20000 });
  check('P18 ⑧ 승인 버튼 열림 (실제 AWS 미검증 확인 후 승인)', !(await p.$eval('[data-dec="APPROVED"]', (x) => x.disabled)) && (await txt('[data-dec="APPROVED"]')).includes('미검증 확인 후 승인'), await txt('.decs'));
  await p.click('[data-dec="APPROVED"]');
  await p.waitForSelector('#decAck');
  await p.fill('#decReason', 'E2E: 제안서 조건 2 대로 — 점프 서버 SSH 본사만');
  await p.fill('#decBy', '김담당');
  await p.check('#decAck');
  await p.click('[data-act="decide"]');
  await p.waitForFunction(() => [...document.querySelectorAll('.mtoast')].some((x) => x.textContent.includes('결정을 기록함')), null, { timeout: 10000 }).catch(() => {});
  check('P19 ⑧ 승인 기록', (await p.$$eval('.mtoast', (xs) => xs.map((x) => x.textContent).join(' '))).includes('결정을 기록함'));
  await p.waitForFunction(() => document.querySelectorAll('.prchk li').length >= 6, null, { timeout: 20000 }).catch(() => {});
  const chk = await txt('.prchk');
  check('P20 ⑧ PR 준비 확인: 예제 프로젝트 — 시연용 PR 줄 (D-44)', chk.includes('예제 프로젝트 — 시연용 PR'), chk.slice(0, 600));
  // 작업 환경의 시험 저장소에는 이 예제 폴더가 기준 브랜치에 없다 → 준비 확인이 막힌다 (팀 PC 에서는 커밋 뒤 통과). 막혔으면 그 이유를, 열렸으면 미리보기 본문을 확인
  if (await p.$('[data-act="pr-preview"]')) {
    await p.click('[data-act="pr-preview"]');
    await p.waitForFunction(() => /시연용 PR/.test((document.querySelector('.lay8') || {}).textContent || ''), null, { timeout: 15000 }).catch(() => {});
    const prv = await txt('.lay8');
    check('P21 ⑧ PR 미리보기 본문 맨 위 "시연용 PR (예제 폴더) — 병합하지 않습니다"', prv.includes('시연용 PR (예제 폴더) — 병합하지 않습니다'), prv.slice(-800));
  } else {
    check('P21 ⑧ PR 준비 확인 막힘 = 기준 브랜치에 예제 폴더 없음 (시험 저장소) + 할 일', chk.includes('scenarios/arch/board-saas 가 없음') && chk.includes('할 일:'), chk.slice(0, 900));
  }
  await shot('p-s8');
  check('P22 화면 오류 없음', errs.length === 0, errs.slice(0, 5));
  console.log(`\n${pass}/${pass + fail} PASS`);
  await b.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
