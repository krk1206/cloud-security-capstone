// 16차 (D-52) 고객 요청함 — B 11-06 "고객 요청을 실시간으로 들어오게 … 시간 지나면 진짜 새로 들어온 거마냥, 실제 기반처럼".
// 17차 (D-53) — B 11-07 "발표용 타이머 같은 쓸데없는 내용 빼라 · 버그 · 글자 겹친 것도" → 타이머 · [지금 받기] · [처음부터] · 방식 고르기 없음, [고객 역할로 요청 넣기]만.
// ① 요청함(받은 요청만 · 최근 것 위 · 조작 줄 없음) → 다른 화면(②)에 있는 동안 새 요청 도착(다른 사람이 넣음 = API) → 알림 · 왼쪽 숫자 · 창 제목
// → [고객 역할로 요청 넣기] → 요청 5 (DB 공개 · 사람에게 넘김: 두 칸 + 이유는 접힘) → 요청 11 (넣은 사람 · 메모)
// → 요청 4 (DB 보안 그룹: ④ 한 줄 · 'Trivy 는 못 봄' 0 · ⑤ 겹치는 칸 없음 · 포트 글자와 ✕ 안 겹침 · ⑥ 그림 없음 · ⑦ 할 일 · ⑧ 반복 없음 · 승인 → ① '승인됨')
// → 요청 6 (업로드 IAM: ② 넓은 권한 빨강 · ⑥ V5 '바뀐 리소스 없음').
// 실제 tofu 오프라인 plan · trivy. AWS · AI · PR 실행 없음. 시작 상태는 reset.sh (요청 1 ~ 3 도착 · 읽음), 서버의 '지금' = start.sh 의 IACPATCH_INBOX_NOW (11-06 21:00).
const { chromium } = require('playwright');
const SP = '/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad';
const BASE = 'http://127.0.0.1:8897/';
const SHOTS = process.argv[2] || `${SP}/e2e/shots_inbox`;
let pass = 0, fail = 0;
const check = (name, cond, info = '') => { if (cond) { pass++; console.log('PASS', name); } else { fail++; console.log('FAIL', name, '|', String(info).slice(0, 500)); } };
(async () => {
  require('fs').mkdirSync(SHOTS, { recursive: true });
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = [];
  p.on('pageerror', (e) => errs.push('pageerror: ' + e.message + ' @ ' + String(e.stack || '').split('\n').slice(0, 3).join(' / ')));
  p.on('console', (m) => { if (m.type() === 'error' && !/status of (400|403|404)/.test(m.text())) errs.push('console: ' + m.text()); });
  const txt = async (sel) => (await p.$(sel)) ? (await p.innerText(sel)) : '';
  const all = async (sel) => (await p.$(sel)) ? (await p.$eval(sel, (x) => x.textContent)) : '';     // 접힌 칸(<details>)의 글자까지
  const one = (s) => String(s).replace(/\s+/g, ' ');
  const shot = async (n) => { await p.waitForTimeout(300); await p.screenshot({ path: `${SHOTS}/${n}.png`, fullPage: true }); };
  const ins = (body) => p.evaluate(async (bd) => { const r = await fetch('/api/inbox/insert', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(bd) }); return { st: r.status, ...(await r.json()) }; }, body);
  const post = (url, body) => p.evaluate(async ([u, bd]) => (await fetch(u, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(bd) })).status, [url, body]);
  const seqs = () => p.$$eval('.ibrow .ib-seq', (xs) => xs.map((x) => x.textContent));
  const row = async (id) => one(await p.$eval(`.ibrow[data-rid="${id}"]`, (x) => x.innerText).catch(() => ''));
  const toast = (word, ms = 25000) => p.waitForFunction((w) => [...document.querySelectorAll('.ibtoast')].some((x) => x.textContent.includes(w)), word, { timeout: ms }).then(() => true).catch(() => false);
  const home = async () => { await p.click('#mproj'); await p.waitForSelector('#ibox .iblist', { timeout: 10000 }); await p.waitForTimeout(400); };
  const side = (n) => txt(`#msteps button[data-go="${n}"]`);
  const openReq = async (id) => {
    await home();
    await p.click(`.ibrow[data-rid="${id}"] [data-open]`); await p.waitForTimeout(1200);
    if ((await txt('#mbody')).includes('점검 실행')) await p.click('[data-act="scan"]');
    await p.waitForSelector('#tInfra [data-node]', { timeout: 400000 }); await p.waitForTimeout(800);
  };
  const confirm3 = async (act) => {
    await p.click('#msteps button[data-go="3"]'); await p.waitForTimeout(1500);
    const g = one(await txt('.mcard.guide'));
    await p.click(`.mcard.guide [data-act="${act}"]`);
    await p.fill('#cfBy', '김담당'); await p.click('#cfGo');
    await p.waitForFunction(() => (document.querySelector('.mtoast') || {}).textContent?.includes('확정'), null, { timeout: 15000 }).catch(() => {});
    await p.waitForTimeout(900);
    return g;
  };
  const toFix = async () => {
    await p.click('#msteps button[data-go="4"]'); await p.waitForTimeout(900);
    await p.click('.ilist .fixable .iitem'); await p.waitForTimeout(400);
    await p.click('[data-fix]'); await p.waitForTimeout(900);
    await p.waitForFunction(() => !document.querySelector('.pfx.run'), null, { timeout: 600000 });
    await p.waitForTimeout(800);
    return p.$$eval('.tbig .cbig', (xs) => xs.map((x) => x.innerText.replace(/\s+/g, ' ')));
  };
  const pick = async (i) => {
    await p.click(`.cbig >> nth=${i}`);
    await p.waitForFunction((k) => (document.querySelector('.mc-head b') || {}).textContent?.includes(`수정안 ${k} 적용 후`), i + 1, { timeout: 60000 }).catch(() => {});
    await p.waitForTimeout(800);
    await p.waitForSelector('.reqrow .rqchip', { timeout: 20000 }).catch(() => {});
    return p.$$eval('.reqrow .rqchip', (xs) => xs.map((x) => ['good', 'bad', 'unknown', 'wait', 'dim'].find((k) => x.classList.contains(k))));
  };
  // 그림의 포트 글자가 ✕ 표시 · 다른 포트 글자와 겹치는지 (실제 그린 크기로)
  const overlaps = (svgSel) => p.evaluate((sel) => {
    const svg = document.querySelector(sel);
    if (!svg) return ['그림 없음'];
    const box = (el) => { const r = el.getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height, t: el.textContent }; };
    const hit = (a, c) => a.x < c.x + c.w && c.x < a.x + a.w && a.y < c.y + c.h && c.y < a.y + a.h;
    const labs = [...svg.querySelectorAll('text.alab')].map(box).filter((r) => r.w > 0);
    const xs = [...svg.querySelectorAll('.a-x')].map(box);
    const out = [];
    labs.forEach((l, i) => { xs.forEach((x) => { if (hit(l, x)) out.push(`${l.t} × ✕`); }); labs.slice(i + 1).forEach((m) => { if (hit(l, m)) out.push(`${l.t} × ${m.t}`); }); });
    return out;
  }, svgSel);

  // ---------------------------------------------------------------- I1 처음 상태 — 조작 줄 없음
  await p.goto(BASE, { waitUntil: 'networkidle' });
  await p.waitForSelector('#ibox .iblist');
  const head = one(await txt('.ib-h'));
  check('I1 ① 고객 요청함: (가상) 운영팀 · 받은 요청 3건 · 안 읽음 없음 · 최근 것 위 (요청 3 · 2 · 1) · 창 제목 숫자 없음', head.includes('(가상) 3계층 웹 서비스 운영팀') && head.includes('받은 요청 3건')
    && !head.includes('/ 11') && !head.includes('안 읽음') && (await seqs()).join(',') === '요청 3,요청 2,요청 1' && (await p.title()) === 'IaCPatch' && !(await p.$('#mproj .mbadge')), head);
  const gone = await p.evaluate(() => ['.ibctl', '[data-act="ib-mode"]', '[data-act="ib-start"]', '[data-act="ib-stop"]', '[data-act="ib-next"]', '[data-act="ib-reset"]', '#ibInterval', '#ibCount', '.ib-facts', '.ib-next']
    .filter((s) => document.querySelector(s)));
  const boxTxt = one(await txt('#ibox'));
  check('I1b 17차: 발표용 타이머 · 간격 · 남은 시간 · [다음 요청 지금 받기] · [처음부터] · 방식 고르기 · 다음 도착 줄 · 숫자 칩 · 받은 방식 글 없음 · [고객 역할로 요청 넣기] 는 있음',
    !gone.length && !/발표용 타이머|실제 날짜 기준|지금 받기|처음부터|도착 예정|정해진 날짜에 도착|Terraform 파일/.test(boxTxt) && !!(await p.$('[data-act="ib-insert"]')), `${gone} | ${boxTxt.slice(0, 300)}`);
  check('I1c ① 할 일 = 요청함에서 열기 · 다른 예제(3계층 실측) 카드는 아래 · 예제 카드에 숫자 칸 · 폴더 경로 없음', (await txt('.mh-todo')).includes('[열기 ▶]') && (await p.$$('.pcard')).length === 1
    && await p.evaluate(() => document.querySelector('#ibox').getBoundingClientRect().bottom <= document.querySelector('.pcard').getBoundingClientRect().top)
    && !(await p.$('.pcard dl')) && !(await txt('.pcard')).includes('scenarios/arch'), await txt('.mh-todo'));
  check('I1d 글자: 한글 낱말 중간에서 줄을 바꾸지 않음 (word-break: keep-all)', (await p.evaluate(() => getComputedStyle(document.body).wordBreak)) === 'keep-all');
  await shot('i1');

  // ---------------------------------------------------------------- I2 다른 화면(②)에 있는 동안 새 요청이 들어옴 (다른 사람이 넣음 = API)
  await p.click('.ibrow[data-rid="three-tier-team"] [data-open]');
  await p.waitForSelector('#tInfra [data-node]', { timeout: 400000 });
  const r2 = await ins({ id: 'three-tier-team-dbsg', by: '김판종' });
  const t2 = await toast('요청 4');
  check('I2 ② 화면에 있어도 새 요청 알림: 요청 4 (DB 보안 그룹) · [열기 ▶] · 왼쪽 \'새 고객 요청 1\' · 창 제목 (1)', r2.st === 200 && t2 && (await txt('.ibtoast')).includes('DB 보안 그룹 전체 개방')
    && !!(await p.$('.ibtoast [data-open="three-tier-team-dbsg"]')) && (await txt('#mproj .mbadge')) === '새 고객 요청 1' && (await p.title()) === '(1) IaCPatch', `${await txt('.ibtoast')} | ${await txt('#mproj')}`);
  check('I2b ② 그림 상자 이름이 잘리지 않음 (전: \'Auto Scal…\' · 요청 4 의 \'203.0.113.10…\')', await p.$$eval('#tInfra .fname, #tInfra .fsub', (xs) => xs.every((x) => !x.textContent.endsWith('…')) && xs.some((x) => x.textContent === '서버 묶음 (Auto Scaling)')),
    await p.$$eval('#tInfra .fname, #tInfra .fsub', (xs) => xs.map((x) => x.textContent).join(' | ')));
  check('I2c ② 그림 아래 숫자 네 칸 없음 — 같은 숫자는 왼쪽 메뉴 ② 밑 (리소스 · 허용 · 위험)', !(await p.$('.mpanel .nums')) && /리소스 \d+개 · 허용 \d+개/.test(await side(2)), await side(2));
  check('I2d ② 요청 칸: 받은 방식 글 없음 · 받은 시각 있음', !/(정해진 날짜에 도착|지금 받기|발표용 타이머)/.test(await txt('.reqbar')) && (await txt('.reqbar')).includes('받은 시각 2026-11-05 09:10'), await txt('.reqbar'));
  await shot('i2-toast');
  await home();
  const r4 = await row('three-tier-team-dbsg');
  check('I2e ① 맨 위 요청 4 · 안 읽음 · 새 요청 · 긴급 · 넣은 사람 김판종 · 방금', (await seqs())[0] === '요청 4' && r4.includes('새 요청') && r4.includes('긴급') && r4.includes('방금')
    && r4.includes('고객 역할로 넣은 사람 김판종') && (await p.$eval('.ibrow[data-rid="three-tier-team-dbsg"]', (x) => x.classList.contains('unread'))) && (await txt('.ib-h')).includes('안 읽음 1'), r4);

  // ---------------------------------------------------------------- I3 [고객 역할로 요청 넣기]
  await p.click('[data-act="ib-insert"]'); await p.waitForSelector('#ibPick');
  const opts = await p.$$eval('#ibPick option', (xs) => xs.map((x) => x.value));
  check('I3 넣기 창: 아직 안 온 요청만 고를 수 있음 (5 ~ 11)', JSON.stringify(opts) === JSON.stringify(['three-tier-team-dbpublic', 'three-tier-team-upload', 'three-tier-team-imds', 'three-tier-team-dbenc', 'three-tier-team-deletion', 'three-tier-team-flowlog', 'three-tier-team-backup']), opts);
  await p.selectOption('#ibPick', 'three-tier-team-backup');
  await p.click('#ibSend'); await p.waitForTimeout(300);
  check('I3b 이름 없이 보내기 → 거절 (이름을 적어 주세요)', (await txt('#ibErr')).includes('이름을 적어 주세요') && !!(await p.$('#ibPick')), await txt('#ibErr'));
  await p.fill('#ibBy', '김판종'); await p.fill('#ibMemo', '발표 중 질문 받고 넣음');
  await p.click('#ibSend');
  const t3 = await toast('요청 11');
  await p.waitForTimeout(500);
  const r11 = await row('three-tier-team-backup');
  check('I3c 보냄 → 맨 위 요청 11 (DB 백업) · 고객 역할로 넣은 사람 김판종 · 메모 · 알림에 넣은 사람', t3 && (await seqs())[0] === '요청 11' && r11.includes('고객 역할로 넣은 사람 김판종')
    && r11.includes('발표 중 질문 받고 넣음') && !r11.includes('직접 넣음') && (await txt('.ibtoast')).includes('고객 역할 김판종'), r11);
  check('I3d 지금 받기 · 처음부터 · 타이머 길은 서버에도 없음 (POST /api/inbox/control → 404)', (await post('/api/inbox/control', { action: 'next' })) === 404);
  await shot('i3');

  // ---------------------------------------------------------------- I4 요청 5 — 사람에게 넘김 (DB 공개 접속)
  await ins({ id: 'three-tier-team-dbpublic', by: '이보안' });
  await openReq('three-tier-team-dbpublic');
  const rb5 = one(await txt('.reqbar'));
  check('I4 ② 요청 5 맨 위 칸: 가상 · 받은 시각 · 개발팀 리드 · 메신저 · 높음 · 기한 내일까지 · 넣은 사람', rb5.includes('고객 요청 5 · 가상') && rb5.includes('받은 시각 2026-11-06 21:00')
    && rb5.includes('개발팀 리드 · 메신저') && rb5.includes('높음 · 기한 내일까지') && rb5.includes('고객 역할로 넣은 사람 이보안'), rb5);
  const ho = one(await txt('.mcard.handoff'));
  const hoAll = one(await all('.mcard.handoff'));
  const hrow = await p.$$eval('.handoff .hotab tbody tr', (xs) => xs.map((x) => [...x.children].map((c) => c.textContent).join('|')));
  check('I4b ② 사람에게 넘김: 두 칸(무엇이 문제 · 사람이 할 일) · AWS-0180 · 지금 값 표(요청한 값) true → false', (await p.$$('.handoff .ho-grid.two > section')).length === 2 && ho.includes('AWS-0180')
    && (await txt('.handoff .hotab thead')).includes('요청한 값') && JSON.stringify(hrow) === JSON.stringify(['publicly_accessible|true|false']) && ho.includes('사람이 할 일') && ho.includes('고친 뒤 확인'), `${JSON.stringify(hrow)} | ${ho.slice(0, 300)}`);
  check('I4c ② \'왜 자동으로 고치지 않나\' 는 접혀 있음 · 펼치면 정책 이유(규칙 · 리소스 종류 · V6) 그대로', !(await p.$eval('.handoff .ho-why', (x) => x.open)) && !ho.includes('allowed_change_resource_types')
    && hoAll.includes('자동 수정 대상 규칙에 없음') && hoAll.includes('allowed_change_resource_types') && hoAll.includes('V6'), hoAll.slice(0, 400));
  await shot('i4-2');
  await home();
  const r5 = await row('three-tier-team-dbpublic');
  check('I4d ① 요청 5 줄: 읽음 · 상태 = 사람에게 넘김 · 칩 정책 범위 밖 → 사람에게', r5.includes('사람에게 넘김') && r5.includes('예제 · 정책 범위 밖 → 사람에게')
    && !(await p.$eval('.ibrow[data-rid="three-tier-team-dbpublic"]', (x) => x.classList.contains('unread'))), r5);

  // ---------------------------------------------------------------- I5 요청 11 — 고객 역할로 넣은 요청 (DB 백업)
  await openReq('three-tier-team-backup');
  const rb11 = one(await txt('.reqbar'));
  const hrow11 = await p.$$eval('.handoff .hotab tbody tr', (xs) => xs.map((x) => [...x.children].map((c) => c.textContent).join('|')));
  check('I5 ② 요청 11: 고객 역할로 넣은 사람 김판종 · 메모 · 지금 값 backup_retention_period 1 → 7', rb11.includes('고객 역할로 넣은 사람 김판종') && rb11.includes('발표 중 질문 받고 넣음')
    && JSON.stringify(hrow11) === JSON.stringify(['backup_retention_period|1|7']), `${rb11} | ${JSON.stringify(hrow11)}`);

  // ---------------------------------------------------------------- I6 요청 4 — DB 보안 그룹 (끝까지)
  await openReq('three-tier-team-dbsg');
  check('I6 ② 요청 4: 인터넷 → MySQL 빨간 선 · 왼쪽 메뉴 \'위험 1\' · 조건 5개 · 운영자 IP 상자 이름 그대로(203.0.113.10/32)', /위험 1/.test(await side(2)) && !!(await p.$('#tInfra .a-link[data-link="l:x:internet>n:aws_db_instance.mysql>main"] .al.risk'))
    && (await p.$$('.reqbar .rq-c')).length === 5 && (await p.$$eval('#tInfra .fname', (xs) => xs.some((x) => x.textContent === '203.0.113.10/32'))), await side(2));
  await shot('i6-2');
  const g6 = await confirm3('s-confirm');
  const toastPos = await p.evaluate(() => { const t = document.querySelector('.mtoast'); const h = document.querySelector('#mhead'); return t ? t.getBoundingClientRect().top >= h.getBoundingClientRect().bottom : null; });
  check('I6b ③ 팀 설계 문서에서 옮긴 설계도 v1 초안 → 김담당 확정 · 알림이 머리말(제목 · 할 일)을 가리지 않음', g6.includes('팀 설계 문서에서 옮긴 설계도 v1 초안') && (await txt('.mcard.confirm')).includes('확정된 설계도 v1') && toastPos === true, `${g6} | ${toastPos}`);
  check('I6c ③ 확정 뒤: \'다음 할 일\' 칸 없음 (오른쪽 위 [다음] 과 같음) · 팀 설계 문서 원문은 접힘 · 막은 줄의 \':\' 에 취소선 없음', !(await p.$('.mcard.guide')) && !(await p.$eval('details.proposal', (x) => x.open))
    && (await p.$$eval('.frow.off .fr-path b .c', (xs) => xs.length > 0 && xs.every((x) => getComputedStyle(x).display === 'inline-block'))), await txt('#mbody').then((t) => t.slice(0, 200)));
  await p.click('#msteps button[data-go="4"]'); await p.waitForTimeout(900);
  const fx4 = await p.$$eval('.ilist .fixable .iitem', (xs) => xs.map((x) => x.innerText.replace(/\s+/g, ' ')));
  check('I6d ④ 같은 규칙 하나 = 한 줄 (Trivy · 자체 검사 · 설계 위반) · \'Trivy 는 못 보고\' 칸 없음 · 왼쪽 메뉴 \'Trivy 못 본 것 0\'', fx4.length === 1 && fx4[0].includes('모든 포트가 인터넷 전체에 열림')
    && ['Trivy', '자체 검사', '설계 위반'].every((w) => fx4[0].includes(w)) && !fx4[0].includes('Trivy 는 못 봄') && !(await p.$('.isum-hl')) && /문제 6개 · Trivy 못 본 것 0/.test(await side(4)), `${JSON.stringify(fx4)} | ${await side(4)}`);
  const b6 = await toFix();
  check('I6e ⑤ 수정안 4개 분석됨 · 통과 1 (3번 = Bastion 보안 그룹으로 되돌림) · 막힘 3', b6.length === 4 && b6[2].includes('통과') && b6.filter((t) => t.includes('막힘')).length === 3, b6);
  const rq6 = [];
  for (let i = 0; i < 4; i++) rq6.push(await pick(i));
  check('I6f ⑤ 수정안마다 조건 5칸: 1 ✕ (인터넷 3306) · 1 ✕ (쪼갠 대역) · 모두 ✓ · 1 ✕ (VPC 전체), 5번 = 아직', JSON.stringify(rq6) === JSON.stringify([['bad', 'good', 'good', 'good', 'wait'], ['bad', 'good', 'good', 'good', 'wait'], ['good', 'good', 'good', 'good', 'wait'], ['bad', 'good', 'good', 'good', 'wait']]), JSON.stringify(rq6));
  await pick(0);
  const ov1 = await overlaps('#tPic');
  check('I6g ⑤ 수정안 1 그림: 포트 글자가 ✕ · 다른 포트 글자와 겹치지 않음 (전: \':330⊗\')', ov1.length === 0 && (await p.$$('#tPic .a-x')).length >= 1, JSON.stringify(ov1));
  await pick(2);
  check('I6h ⑤ 겹치던 칸 없음: \'다음 할 일\' · \'고른 수정안\'(⑥ 단추) · \'기준: 설계도\' — 결과 한 줄만 · ⑥ 가기 단추는 오른쪽 위 하나', !(await p.$('.mcard.guide')) && !(await p.$('.cmp-head')) && !(await p.$('.basis'))
    && (await txt('.cmp-line')).includes('수정안 3') && (await p.$$('#mbody [data-go="6"]')).length === 0, await txt('.cmp-line'));
  await p.click('#msteps button[data-go="6"]'); await p.waitForSelector('.verdict', { timeout: 20000 }); await p.waitForTimeout(600);
  const rq = await all('.reqcheck');
  check('I6i ⑥ 결론 good · 조건 5개 — 지킴 4 · 아직 1 · 지킨 조건의 근거는 접힘(4개) · 아래 그림 없음', (await p.$eval('.verdict', (x) => x.className)).includes('good') && rq.includes('고객 요청 조건 5개 — 지킴 4 · 아직 1')
    && (await p.$$('.reqcheck details.rq-more')).length === 4 && (await p.$$eval('.reqcheck details.rq-more', (xs) => xs.every((x) => !x.open))) && !(await p.$('#tVerdict')) && rq.includes('확인 방법'), rq.slice(0, 300));
  check('I6j ⑥ 다섯째 질문 설명: \'설계도 v1 — 확정한 사람 김담당\' (전: \'김담당 가 확정한\')', (await txt('.qcol')).includes('비교 기준 = 설계도 v1 — 확정한 사람 김담당') && !(await txt('.qcol')).includes('가 확정한'), (await txt('.qcol')).slice(-300));
  await shot('i6-6');
  await p.click('#msteps button[data-go="7"]'); await p.waitForTimeout(900);
  check('I6k ⑦ 시험 환경 없음: 할 일 = 할 것 없음 → 다음 (전: \'버튼을 순서대로\') · 세 단계 띠 없음 · 미검증 칸', (await txt('.mh-todo')).includes('할 것이 없습니다') && !(await txt('.mh-todo')).includes('순서대로')
    && !(await p.$('#mbody .stages3')) && (await txt('#mbody')).includes('미검증'), await txt('.mh-todo'));
  await p.click('#msteps button[data-go="8"]'); await p.waitForSelector('.final-grid', { timeout: 20000 }); await p.waitForTimeout(600);
  const sums = await p.$$eval('.final-grid .mcard.sum h4', (xs) => xs.map((x) => x.childNodes[0].textContent.trim()));
  check('I6l ⑧ ⑥ 과 같은 결론 칸 · 세 단계 띠 없음 · 정리 칸 5개(\'검증하지 못한 부분\' 은 끝맺음의 \'남은 것\' 으로) · PR 단계 목록 없음', !(await p.$('#mbody .verdict')) && !(await p.$('#mbody .stages3'))
    && JSON.stringify(sums) === JSON.stringify(['해결된 문제', '남아 있는 문제', '새로 생긴 문제', '고객 설계 위반', 'AWS 시험 환경 검사']) && !(await p.$('.prsteps')) && (await txt('.closing')).includes('남은 것')
    && !(await txt('.closing')).split('남은 것')[1].split('\n').some((l) => l.trim() === '수정 요청'), JSON.stringify(sums));
  await p.click('[data-dec="APPROVED"]'); await p.waitForSelector('#decAck');
  await p.fill('#decReason', 'E2E: 팀 설계 문서대로 DB 는 Bastion · 웹 서버 보안 그룹에서 3306 만');
  await p.fill('#decBy', '김담당'); await p.check('#decAck');
  await p.click('[data-act="decide"]');
  await p.waitForFunction(() => [...document.querySelectorAll('.mtoast')].some((x) => x.textContent.includes('결정을 기록함')), null, { timeout: 10000 }).catch(() => {});
  await p.waitForTimeout(800);
  await shot('i6-8');
  await home();
  await p.waitForFunction(() => (document.querySelector('.ibrow[data-rid="three-tier-team-dbsg"]') || {}).textContent?.includes('승인됨'), null, { timeout: 5000 }).catch(() => {});
  check('I6m ① 로 돌아오면 바로 새로: 요청 4 줄 상태 = 승인됨 (⑧ 결정 기록을 읽음)', (await row('three-tier-team-dbsg')).includes('승인됨'), await row('three-tier-team-dbsg'));

  // ---------------------------------------------------------------- I7 요청 6 — 업로드 권한 (IAM)
  await ins({ id: 'three-tier-team-upload', by: '김판종' });
  const t7 = await toast('요청 6');
  check('I7 요청 6 (업로드 권한) 도착 알림', t7 && (await seqs())[0] === '요청 6', await seqs());
  await openReq('three-tier-team-upload');
  check('I7b ② 요청 6 권한 그림: 넓은 권한 1 (역할 → assets s3:* 빨강) · 조건 4개', /넓음 1/.test(await side(2)) && !!(await p.$('#tInfra .a-link[data-link^="l:n:aws_iam_role.web>n:aws_s3_bucket.assets>perm"] .al.risk'))
    && (await p.$$('.reqbar .rq-c')).length === 4, await side(2));
  await shot('i7-2');
  const g7 = await confirm3('r-confirm');
  check('I7c ③ 팀 설계 문서 + 고객 요청 6 에서 옮긴 IAM 요구사항 v1 초안 → 확정 · 확정 뒤 \'다음 할 일\' 칸 없음', g7.includes('팀 설계 문서 + 고객 요청 6에서 옮긴 IAM 요구사항 v1 초안') && (await txt('.mcard.confirm')).includes('확정된 IAM 요구사항 v1') && !(await p.$('.mcard.guide')), g7);
  const b7 = await toFix();
  check('I7d ⑤ 수정안 4개 · 통과 1 (2번 = PutObject 만) · 막힘 3', b7.length === 4 && b7[1].includes('통과') && b7.filter((t) => t.includes('막힘')).length === 3, b7);
  const rq7 = [];
  for (let i = 0; i < 4; i++) rq7.push(await pick(i));
  check('I7e ⑤ 조건 4칸: 1 ✕ (Put*) · 모두 ✓ · 2 ✕ (올리기 지움) · 1 ✕ (Delete 까지)', JSON.stringify(rq7) === JSON.stringify([['bad', 'good', 'good', 'wait'], ['good', 'good', 'good', 'wait'], ['good', 'bad', 'good', 'wait'], ['bad', 'good', 'good', 'wait']]), JSON.stringify(rq7));
  await pick(1);
  await p.click('#msteps button[data-go="6"]'); await p.waitForSelector('.verdict', { timeout: 20000 }); await p.waitForTimeout(600);
  const q4 = one(await p.$$eval('.qrow', (xs) => (xs[3] || {}).innerText || ''));
  check('I7f ⑥ 질문 4 = \'아니오 — plan 에서 바뀐 리소스 없음\' · 조건 지킴 3 · 아직 1 · 근거(읽기 · 목록 · 올리기)는 접힌 칸에', q4.includes('아니오 — plan 에서 바뀐 리소스 없음') && q4.includes('적용 후 결정')
    && (await all('.reqcheck')).includes('고객 요청 조건 4개 — 지킴 3 · 아직 1') && (await all('.reqcheck')).includes('읽기 · 목록 · 올리기'), `${q4} | ${(await all('.reqcheck')).slice(0, 200)}`);
  check('I7g ⑥ 다섯째 질문 설명: \'IAM 요구사항 v1 — 확정한 사람 김담당\'', (await txt('.qcol')).includes('비교 기준 = IAM 요구사항 v1 — 확정한 사람 김담당'), (await txt('.qcol')).slice(-200));
  await shot('i7-6');

  check('I99 콘솔 · 페이지 오류 없음', errs.length === 0, errs.join(' || '));
  console.log(`\n=== inbox E2E: ${pass} PASS / ${fail} FAIL ===`);
  await b.close();
  process.exit(fail ? 1 : 0);
})();
