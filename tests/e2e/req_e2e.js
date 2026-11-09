// 15차 (D-51) 팀 3계층 요청 3 (IAM) 끝까지 · 요청 2 (S3, 정책 밖 → 사람에게): 실제 tofu 오프라인 plan · trivy. AWS · AI 없음.
// 요청 3: ① 카드 → ② 권한 그림(웹 서버 → 역할 → 모든 리소스 빨강) → ③ IAM 요구사항 초안(팀 설계 문서) → 김담당 확정 → ④ 한 줄(Trivy + 자체 IAM) · 그림 강조
//         → ⑤ 수정안 1~4 (1 * · 2 정답 · 3 읽기 지움 · 4 나열) 그림 · 요구사항과 다른 곳 · 조건 4칸 → ⑥ good → ⑧ 승인 · 조건 모두 지킴 · PR 본문
// 요청 2: ① 카드 칩 → ② 사람에게 넘김 칸(Trivy 4건 · 지금 값 false 4 · 정책 이유) → ③ 해당 없음 → ④ 4건 탐지만 · 고치기 없음 → ⑤ 수정안 없음
const { chromium } = require('playwright');
const SP = '/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad';
const BASE = 'http://127.0.0.1:8897/';
const SHOTS = process.argv[2] || `${SP}/e2e/shots_req`;
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
  const open = async (id) => {
    await p.goto(BASE, { waitUntil: 'networkidle' });
    await p.click(`[data-open="${id}"]`); await p.waitForTimeout(1200);
    if ((await txt('#mbody')).includes('점검 실행')) await p.click('[data-act="scan"]');
    await p.waitForSelector('#tInfra [data-node]', { timeout: 400000 }); await p.waitForTimeout(800);
  };

  // ① 카드
  await p.goto(BASE, { waitUntil: 'networkidle' });
  // 16차 (D-52): ① 고객 요청함의 줄 (전에는 카드)
  const row = async (id) => (await p.$eval(`.ibrow[data-rid="${id}"]`, (x) => x.innerText)).replace(/\s+/g, ' ');
  const c2 = await row('three-tier-team-s3'), c3 = await row('three-tier-team-iam');
  check('R1 ① 요청 2 줄: 칩 \'정책 범위 밖 → 사람에게\' · 요청 2 · 숫자 칸 없음 (17차) · 상태 = 사람에게 넘김', c2.includes('예제 · 정책 범위 밖 → 사람에게') && c2.includes('요청 2') && c2.includes('자산 버킷 공개 차단 꺼짐') && !/리소스\s*\d/.test(c2) && !c2.includes('초안부터') && c2.includes('사람에게 넘김'), c2);
  check('R2 ① 요청 3 줄: 칩 \'팀 설계 문서 → 권한 요구사항\' · 요청 3 · 숫자 칸 없음 (17차)', c3.includes('예제 · 팀 설계 문서 → 권한 요구사항') && c3.includes('요청 3') && c3.includes('웹 서버 역할 권한 과다') && !/리소스\s*\d/.test(c3) && !c3.includes('초안부터'), c3);

  // ---------------------------------------------------------------- 요청 3 (IAM)
  await open('three-tier-team-iam');
  const ids = await p.$$eval('#tInfra [data-node]', (xs) => xs.map((x) => x.dataset.node).sort());
  check('R3 ② 권한 그림 = 웹 서버(ASG) · IAM 역할 · 모든 리소스(*) 만 (통신 상자 없음)', JSON.stringify(ids) === JSON.stringify(['n:aws_autoscaling_group.web', 'n:aws_iam_role.web', 'x:allres']), ids);
  check('R4 ② 넓은 권한 1 (역할 → 모든 리소스 s3:* 빨강) · 숫자는 왼쪽 메뉴 ② 밑 (권한 · 넓음 — 17차: 그림 아래 숫자 칸 뺌)', /넓음 1/.test(await txt('#msteps button[data-go="2"]')) && /권한 \d+개/.test(await txt('#msteps button[data-go="2"]'))
    && !(await p.$('.mpanel .nums')) && !!(await p.$('#tInfra .a-link[data-link="l:n:aws_iam_role.web>x:allres>perm>e8"] .al.risk')), await txt('#msteps button[data-go="2"]'));
  check('R5 ② 맨 위 고객 요청 3 · 조건 4개 · 할 일 = 권한 그림', (await txt('.reqbar')).includes('고객 요청 3 · 가상') && (await p.$$('.reqbar .rq-c')).length === 4 && (await txt('.mh-todo')).includes('권한 그림'), await txt('.reqbar'));
  await shot('r-i2');

  // ③ IAM 요구사항 초안 → 확정
  await p.click('#msteps button[data-go="3"]'); await p.waitForSelector('#tMap [data-node]', { timeout: 30000 }); await p.waitForTimeout(600);
  check('R6 ③ 머리말 = 허용하는 권한 · 다음 할 일 = 팀 설계 문서에서 옮긴 IAM 요구사항 v1 초안', (await txt('#mhead h1')).includes('허용하는 권한') && (await txt('.mcard.guide')).includes('팀 설계 문서에서 옮긴 IAM 요구사항 v1 초안'), await txt('.mcard.guide'));
  const dl = await p.$$eval('#tMap .a-link', (xs) => xs.map((x) => x.textContent.replace(/\s+/g, ' ')));
  check('R7 ③ 요구사항 그림: 역할 → assets 버킷 s3:GetObject · s3:ListBucket', (await p.$$('#tMap [data-node="n:aws_s3_bucket.assets"]')).length === 1 && dl.some((t) => t.includes('s3:GetObject') && t.includes('s3:ListBucket')), dl);
  check('R8 ③ 지금 코드와 다른 곳: 요구사항 밖 권한 s3:* → 모든 리소스(*) · 원문 칸(1.12절)', (await txt('#mbody')).includes('요구사항 밖 권한: s3:* → 모든 리소스(*)') && (await txt('.mcard.proposal')).includes('1.12절 IAM'), (await txt('.s3-list')).slice(0, 400));
  await p.click('[data-ipv="now"]'); await p.waitForTimeout(500);
  check('R9 ③ [지금 코드와 비교] = 역할 → 모든 리소스 선에 ✕', (await p.$$('#tMap .a-x')).length === 1 && (await txt('.mc-head b')).includes('지금 코드의 권한'), await txt('.mc-head'));
  await shot('r-i3');
  await p.click('.mcard.guide [data-act="r-confirm"]');
  await p.fill('#cfBy', '김담당'); await p.click('#cfGo');
  await p.waitForFunction(() => (document.querySelector('.mtoast') || {}).textContent?.includes('확정'), null, { timeout: 15000 });
  await p.waitForTimeout(900);
  check('R10 ③ 확정 → 확정된 IAM 요구사항 v1 · 김담당 · 머리말 표시 확정 · \'다음 할 일\' 칸 없음 (17차)', (await txt('.mcard.confirm')).includes('확정된 IAM 요구사항 v1') && (await txt('.mcard.confirm')).includes('김담당') && (await txt('.mh-tags')).includes('IAM 요구사항 v1 · 확정') && !(await p.$('.mcard.guide')), await txt('.mcard.confirm'));

  // ④ 한 줄 (Trivy + 자체 IAM 검사) · 그림 강조
  await p.click('#msteps button[data-go="4"]'); await p.waitForTimeout(900);
  const iss = await p.evaluate(async () => (await (await fetch('/api/p/issues?id=three-tier-team-iam')).json()));
  const s3all = iss.issues.filter((x) => x.rule === 'AVD-AWS-0345');
  check('R11 ④ s3:* 문제 = 한 줄 (Trivy + 자체 IAM) · 문제 6개', s3all.length === 1 && ['trivy', 'iam'].every((k) => s3all[0].sources.includes(k)) && iss.issues.length === 6, JSON.stringify(iss.issues.map((x) => [x.rule, x.sources])));
  for (const it of await p.$$('.iitem')) { if ((await it.innerText()).includes('s3:*')) { await it.click(); break; } }
  await p.waitForTimeout(500);
  check('R12 ④ 그림 위치: 강조됨 (선 포함) · 역할 상자 강조', (await txt('.col.sticky')).includes('아래 그림에서 강조됨 (선 포함)') && !!(await p.$('#tIssue .anode.hl[data-node="n:aws_iam_role.web"]')), (await txt('.col.sticky')).slice(0, 300));
  await p.click('[data-fix]'); await p.waitForTimeout(900);
  check('R13 ⑤ 고칠 문제 = data.aws_iam_policy_document.web_s3_read · AVD-AWS-0345 · IAM 요구사항 v1', (await txt('.target')).includes('data.aws_iam_policy_document.web_s3_read') && (await txt('.target')).includes('AVD-AWS-0345'), await txt('.target'));

  // ⑤ 수정안 1~4
  await p.waitForFunction(() => !document.querySelector('.pfx.run'), null, { timeout: 600000 });
  await p.waitForTimeout(800);
  const bigs = await p.$$eval('.tbig .cbig', (xs) => xs.map((x) => x.innerText.replace(/\s+/g, ' ')));
  check('R14 ⑤ 수정안 4개 · 분석됨 · 통과 1 (2번) · 막힘 3 · 이름 = IAM 정책 문서', bigs.length === 4 && bigs.every((t) => !t.includes('분석 전') && t.includes('IAM 정책 문서 web_s3_read')) && bigs[1].includes('통과') && bigs.filter((t) => t.includes('막힘')).length === 3, bigs);
  const want = [
    ['R15 ⑤ 수정안 1 (* 로): 역할 → 모든 리소스 * 요구사항 밖 ✕ · 조건 1 어김 (Trivy 는 통과)', (d, x) => /web 역할 → 모든 리소스 \(\*\) : \* 요구사항 밖 권한/.test(d) && x === 1],
    ['R16 ⑤ 수정안 2 (팀 원본): 요구사항과 같음 · 빨강 없음', (d, x) => d.includes('요구사항과 같음') && x === 0],
    ['R17 ⑤ 수정안 3 (읽기 지움): 역할 → assets s3:GetObject 꼭 필요한데 없음', (d, x) => /web 역할 → assets : s3:GetObject 꼭 필요한데 없음/.test(d)],
    ['R18 ⑤ 수정안 4 (나열 + *): 모든 리소스에 Get · List · Put · Delete — 요구사항 밖 ✕', (d, x) => /모든 리소스 \(\*\) : /.test(d) && ['s3:GetObject', 's3:ListBucket', 's3:PutObject', 's3:DeleteObject'].every((a) => d.includes(a)) && d.includes('요구사항 밖 권한') && x === 1],
  ];
  const reqWant = [['bad', 'good', 'good', 'wait'], ['good', 'good', 'good', 'wait'], ['good', 'bad', 'good', 'wait'], ['bad', 'good', 'good', 'wait']];
  const reqSeen = [];
  for (let i = 0; i < 4; i++) {
    await p.click(`.cbig >> nth=${i}`);
    await p.waitForFunction((k) => (document.querySelector('.mc-head b') || {}).textContent?.includes(`수정안 ${k} 적용 후`), i + 1, { timeout: 60000 }).catch(() => {});
    await p.waitForTimeout(700);
    const d = (await txt('.pdiff')).replace(/\s+/g, ' ');
    const x = (await p.$$('#tPic .a-x')).length;
    check(want[i][0], want[i][1](d, x), `${d} | x=${x}`);
    await p.waitForSelector('.reqrow .rqchip', { timeout: 20000 }).catch(() => {});
    reqSeen.push(await p.$$eval('.reqrow .rqchip', (xs) => xs.map((x) => ['good', 'bad', 'unknown', 'wait', 'dim'].find((k) => x.classList.contains(k)))));
    if (i === 0) {
      const t1 = await p.$eval('.reqrow .rqchip', (x) => x.title);
      check('R15b ⑤ 수정안 1 조건 1 근거: 요구사항 밖 권한 + Trivy 지적이 없어짐 (Trivy 통과 ≠ 요청 충족) · 바꾼 권한 s3:* → *', t1.includes('요구사항 밖 권한: * → 모든 리소스(*)') && t1.includes('AVD-AWS-0345 지적이 없어짐')
        && (await txt('.cmp-grid')).includes('이 수정안이 바꾼 권한'), t1);
    }
    await shot(`r-i5-${i + 1}`);
  }
  check('R19 ⑤ 수정안마다 고객 요청 조건 4칸: 1 ✕ · 모두 ✓ · 2 ✕(읽기) · 1 ✕, 4번 = 아직', JSON.stringify(reqSeen) === JSON.stringify(reqWant), JSON.stringify(reqSeen));
  await p.click('[data-pv="design"]'); await p.waitForTimeout(400);
  check('R20 ⑤ [IAM 요구사항 v1] 단추 → 요구사항 그림 (빨강 없음)', (await txt('.mc-head b')).includes('IAM 요구사항 v1') && (await p.$$('#tPic .a-x')).length === 0, await txt('.mc-head'));
  await p.click('[data-pv="after"]'); await p.waitForTimeout(300);

  // 2번(정답) → ⑥ → ⑧
  await p.click('.cbig >> nth=1'); await p.waitForTimeout(1500);
  await p.click('#msteps button[data-go="6"]'); await p.waitForSelector('.verdict', { timeout: 20000 }); await p.waitForTimeout(600);
  const v6t = await txt('#mbody');
  check('R21 ⑥ 결론 good · 질문 5 = 고객이 허용한 권한만 남았나요? · 아래 그림 없음 (17차: ⑤ 와 같은 그림)', (await p.$eval('.verdict', (x) => x.className)).includes('good') && v6t.includes('고객이 허용한 권한만 남았나요?')
    && !(await p.$('#tVerdict')), (await txt('.verdict')).slice(0, 300));
  const rc6 = await p.$eval('.reqcheck', (x) => x.textContent.replace(/\s+/g, ' '));      // 지킨 조건의 근거 · 확인 방법은 접힌 칸 (17차)
  check('R22 ⑥ 고객 요청을 지켰나요? — 지킴 3 · 아직 1 · 확인 방법에 V6 IAM (정책은 코드에서 읽음)', rc6.includes('고객 요청 조건 4개 — 지킴 3 · 아직 1') && rc6.includes('V6 IAM 요구사항 검사 (정책은 코드에서 읽음)'), rc6.slice(0, 600));
  await shot('r-i6');
  await p.click('#msteps button[data-go="8"]'); await p.waitForSelector('.final-grid', { timeout: 20000 }); await p.waitForTimeout(600);
  await p.click('[data-dec="APPROVED"]');
  await p.waitForSelector('#decAck');
  await p.fill('#decReason', 'E2E: 팀 설계 문서 1.12절대로 — 웹 서버 역할은 assets 읽기 · 목록만');
  await p.fill('#decBy', '김담당');
  await p.check('#decAck');
  await p.click('[data-act="decide"]');
  await p.waitForFunction(() => [...document.querySelectorAll('.mtoast')].some((x) => x.textContent.includes('결정을 기록함')), null, { timeout: 10000 }).catch(() => {});
  await p.waitForSelector('.reqcheck', { timeout: 20000 }).catch(() => {});
  await p.waitForTimeout(800);
  check('R23 ⑧ 승인 뒤 고객 요청 조건 4개 모두 지킴', (await txt('.reqcheck.compact')).includes('고객 요청 조건 4개 — 지킴 4') && (await p.$$('.reqcheck.compact .rqchip.good')).length === 4, (await txt('.reqcheck.compact')).slice(0, 300));
  const rec8 = await p.evaluate(() => new URLSearchParams(location.hash.slice(1)).get('rec'));
  const pv = await p.evaluate(async (rid) => (await (await fetch('/api/week5/pr_preview', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ record_id: rid, base_branch: 'main' }) })).json()), rec8);
  const body = String(pv.pr_body || '');
  check('R24 PR 미리보기 본문: 고객 요청 (가상 · 예제) — 웹 서버 역할 권한 과다 · 조건 1 지킴 (실행 안 함)', body.includes('## 고객 요청 (가상 · 예제) — 웹 서버 역할 권한 과다 — 점검 지적 조치 요청')
    && body.includes('1. 웹 서버 역할은 자산 버킷(assets)의 파일 읽기와 목록 보기만 할 수 있게 해 주세요. 다른 버킷 · 다른 서비스의 권한은 없어야 합니다. — **지킴**'), body.slice(0, 1600));
  await shot('r-i8');

  // ---------------------------------------------------------------- 요청 2 (S3, 정책 밖)
  await open('three-tier-team-s3');
  const ho = await txt('.mcard.handoff');
  const why = (await p.$('.handoff details.ho-why')) ? await p.$eval('.handoff details.ho-why', (x) => ({ t: x.textContent, open: x.open })) : { t: '', open: true };
  check('R25 ② 사람에게 넘김 칸: Trivy 4건 · 지금 값 false 4 · 할 일 · 확인 + 정책 이유(대상 규칙 · 바꿀 수 있는 리소스)는 접힘 (17차)', ['AWS-0086', 'AWS-0087', 'AWS-0091', 'AWS-0093'].every((r) => ho.includes(r))
    && (await p.$$('.handoff .hotab td.bad')).length === 4 && why.t.includes('자동 수정 대상 규칙에 없음') && why.t.includes('allowed_change_resource_types') && !why.open && ho.includes('사람이 할 일') && ho.includes('고친 뒤 확인'), [ho.slice(0, 400), why.open, why.t.slice(0, 200)]);
  check('R26 ② 고객 요청 2 · 칸이 그림보다 위 · 할 일 = 사람에게 넘김', (await txt('.reqbar')).includes('고객 요청 2 · 가상') && (await txt('.mh-todo')).includes('사람에게 넘김')
    && await p.evaluate(() => document.querySelector('.mcard.handoff').getBoundingClientRect().bottom <= document.querySelector('#tInfra').getBoundingClientRect().top), await txt('.mh-todo'));
  await shot('r-s2');
  await p.click('#msteps button[data-go="3"]'); await p.waitForTimeout(800);
  check('R27 ③ 설계도 · 요구사항으로 검사하지 않음 (자동 초안 없음)', (await txt('#mbody')).includes('설계도 · 요구사항으로 검사하지 않습니다') && !(await p.$('#tMap')) && (await txt('#msteps')).includes('해당 없음'), (await txt('#mbody')).slice(0, 300));
  await p.click('#msteps button[data-go="4"]'); await p.waitForTimeout(900);
  const is2 = await p.evaluate(async () => (await (await fetch('/api/p/issues?id=three-tier-team-s3')).json()));
  const pab = is2.issues.filter((x) => x.resource === 'aws_s3_bucket_public_access_block.assets');
  check('R28 ④ S3 공개 차단 4건 = 탐지만 · 고치기 없음 · 이유 = 사람에게 넘김 · 맨 위 짧은 칸', pab.length === 4 && pab.every((x) => !x.fix.set_id && !x.fix.auto && x.fix.how.includes('사람에게 넘김')) && !!(await p.$('.mcard.handoff.compact')) && (await p.$$('.ilist .fixable .iitem')).length === 0, JSON.stringify(pab.map((x) => x.fix)));
  await p.click('#msteps button[data-go="5"]'); await p.waitForTimeout(800);
  check('R29 ⑤ 수정안 없음 — 자동 수정 범위 밖 (② 로)', (await txt('#mbody')).includes('이 요청은 수정안을 만들지 않습니다') && !!(await p.$('#mbody [data-go="2"]')), (await txt('#mbody')).slice(0, 300));
  await shot('r-s5');
  check('R30 화면 오류 없음', errs.length === 0, errs.slice(0, 5));
  console.log(`\n${pass}/${pass + fail} PASS`);
  await b.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
