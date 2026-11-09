// 새 프로그램(8단계 스토리 화면) E2E — 2026-11-01 갈아엎기 3차. 실제 trivy · tofu(오프라인 plan), 시험용 대역 claude. AWS 없음 · PR 실행 없음.
// 실행 전: sync.py → reset.sh → start.sh
const { chromium } = require('playwright');
const SHOTS = process.argv[2] || '/tmp/main_e2e';
const SP = '/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad';
const BASE = 'http://127.0.0.1:8897/';
let pass = 0, fail = 0;
const check = (name, cond, info = '') => { if (cond) { pass++; console.log('PASS', name); } else { fail++; console.log('FAIL', name, '|', String(info).slice(0, 300)); } };

(async () => {
  require('fs').mkdirSync(SHOTS, { recursive: true });
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = [];
  p.on('pageerror', (e) => errs.push('pageerror: ' + e.message));
  // 400 = 입력 검증 거절(의도한 시험: R2 다른 요구사항 파일) — 그 URL 만 뺀다
  p.on('console', (m) => { if (m.type() === 'error' && !m.text().includes('status of 400')) errs.push('console: ' + m.text()); });
  p.on('response', (r) => { if (r.status() >= 400 && !(r.status() === 400 && r.url().includes('/api/design/req/import'))) errs.push(`http ${r.status()} ${r.url()}`); });
  const txt = async (sel) => (await p.$(sel)) ? (await p.innerText(sel)) : '';
  const shot = async (n) => { await p.waitForTimeout(400); await p.screenshot({ path: `${SHOTS}/${n}.png` }); };
  const next = async () => { await p.click('.mh-nav .primary'); await p.waitForTimeout(500); };
  const nodes = async (id) => p.$$eval(`#${id} [data-node]`, (xs) => xs.length).catch(() => 0);

  // A. 시작 화면
  await p.goto(BASE, { waitUntil: 'networkidle' });
  const body = await txt('#mbody');
  check('A1 시작: 핵심 질문 머리말', (await txt('#mhead h1')).includes('AI가 수정한 클라우드 인프라, 그대로 적용해도 될까요?'));
  check('N1 시작: 준비 상태 = 준비됨 (검사 도구 버전)', (await txt('.ready.ok')).includes('준비됨') && (await txt('.ready.ok')).includes('Trivy 0.74.0'), await txt('.ready'));
  const grps = await p.$$eval('#msteps .sgrp', (xs) => xs.map((x) => x.textContent.trim()));
  check('N2 왼쪽 메뉴 = 8단계 그대로 + 보기 · 고치기 · 확인 · 결정 묶음', grps.join(',') === '보기,고치기,확인,결정' && (await p.$$('#msteps button[data-go]')).length === 8, grps);
  check('N3 머리말 = 할 일 한 줄 (화면 안내 버튼 없음 — 11차)', (await txt('#mhead .mh-todo')).includes('할 일') && !(await p.$('#mhead [data-act="tour"]')), await txt('#mhead'));
  check('N3b 시작 = 준비 상태 + 예제 카드만 (설명 글 · 시작하기 카드 없음), 폴더 연결은 버튼으로 접힘', !(await p.$('.mstart')) && !(await p.$('.hero')) && !!(await p.$('[data-act="np-open"]')) && !(await p.$('.pnew')), body.slice(0, 300));
  check('N3c 왼쪽 아래 = 용어 풀이 · 크게 보기만 (화면 안내 · 검사 범위 표 · 전문가 화면 링크 없음)', (await p.$$('.mside-help button')).length === 2 && !(await p.$('#mexpert')) && !(await p.$('[data-act="coverage"]')), await txt('.mside-foot'));
  await p.click('.mside-foot [data-act="glossary"]');
  await p.fill('#glq', 'CIDR');
  check('N5 용어 풀이: 찾기 (CIDR → IP 대역 · 0.0.0.0/0 = 인터넷 전체)', (await txt('#glb')).includes('0.0.0.0/0 = 인터넷 전체'), await txt('#glb'));
  await p.click('.mm-x');
  await p.click('#mbig');
  const bigOn = await p.evaluate(() => document.body.classList.contains('big'));
  await p.click('#mbig');
  check('N6 크게 보기 켜기 · 끄기', bigOn && !(await p.evaluate(() => document.body.classList.contains('big'))));
  // 16차 (D-52): ① 맨 위 = 고객 요청함 (받은 요청만, 최근 것이 위) · 그 아래 다른 예제 카드
  const ibRows = await p.$$eval('.ibrow', (xs) => xs.map((x) => `${x.querySelector('.ib-seq').textContent}>${x.querySelector('[data-open]').dataset.open}`));
  check('A2 시작: 고객 요청함 = 받은 요청 3건 (요청 3 · 2 · 1, 최근 것 위) + 다른 예제 카드 1개 (3계층 AWS 실측) — 게시판 · 2계층은 화면에서 숨김 (16차 D-52)',
    ibRows.join('|') === '요청 3>three-tier-team-iam|요청 2>three-tier-team-s3|요청 1>three-tier-team' && (await p.$$eval('.pcard .pc-top b', (xs) => xs.map((x) => x.textContent))).join('|') === '3계층 웹 서비스 — AWS 시험 환경 실측', ibRows);
  check('A2b 게시판 예제는 주소로는 열림 (숨김)', (await p.evaluate(async () => (await (await fetch('/api/p/design?id=board-saas')).json()).ok)) === true);
  check('A3 시작: V 번호 없음', !/\bV[1-8]\b/.test(body), body.match(/\bV[1-8]\b/));
  check('A4 2계층은 주소로는 열림 (실험용 id 유지)', (await p.evaluate(async () => (await (await fetch('/api/p/design?id=webapp-2tier')).json()).ok)) === true);

  // B. 3계층 열기 → ② 현재 인프라 (코드에서 그림)
  await p.click('[data-open="webapp-3tier"]');
  await p.waitForSelector('#tInfra [data-node]', { timeout: 20000 });
  check('B1 ② 코드 그림 노드 7개 이상', (await nodes('tInfra')) >= 7, await nodes('tInfra'));
  const nums2 = await txt('#msteps button[data-go="2"]');          // 17차 (D-53): 그림 아래 숫자 네 칸은 뺐다 — 같은 숫자는 왼쪽 메뉴 ② 밑
  check('B2 ② 리소스 62 · 위험 1 (왼쪽 메뉴 ② 밑)', nums2.includes('리소스 62개') && /위험 1/.test(nums2), nums2);
  check('B2b ② 맨 위 가상 고객 요청 (14차 D-50): 접근 통제 점검 · 시험 환경 확인 요청 · 조건 5개', (await txt('.reqbar')).includes('고객 요청 · 가상') && (await txt('.reqbar')).includes('접근 통제 점검 지적 조치 · 시험 환경 확인 요청') && (await p.$$('.reqbar .rq-c')).length === 5, await txt('.reqbar'));
  check('N9a 왼쪽 메뉴 ⑧ 밑 PR 만들기 = 후보 분석 전엔 잠김', await p.$eval('[data-act="goto-pr"]', (x) => x.disabled));
  check('B3 ② 리소스 목록 · 그림 읽는 법 카드 없음 (11차) · 숫자 네 칸도 없음 (17차) — 그림만', !(await p.$('.dcard')) && !(await p.$('.howto')) && !(await p.$('.mpanel .nums')), await txt('#mbody'));
  const vb = await p.$eval('#tInfra', (s) => [s.getBoundingClientRect().width, s.getBoundingClientRect().height]);
  check('B4 ② 그림이 비율대로 (빈 칸 없음)', vb[1] < vb[0] * 0.75 && vb[1] > 150, vb);
  // 12차 (D-48): 그림은 흐름 그림 — VPC · 서브넷 틀 없음, 상자 = 출발지 · 보안 그룹 묶음, 선 = 허용 포트. 13차 (D-49): [전체 보기] 단추도 없음
  const flow = await p.$eval('#tInfra', (s) => [s.querySelectorAll('.a-vpc, .a-band, .a-out').length, s.querySelectorAll('.fnode .fbox').length, s.querySelectorAll('.abadge').length, s.querySelectorAll('.al.fl.sg').length, s.querySelectorAll('.al.fl.risk').length]);
  check('B6 ② 기본 = 흐름 그림: VPC · 서브넷 틀 없음 · 상자 7개 이상 · 문제 수 · 허용 선 · 위험한 허용 1', flow[0] === 0 && flow[1] >= 7 && flow[2] >= 3 && flow[3] >= 6 && flow[4] === 1, flow);
  const kindsFlow = await p.$$eval('#tInfra [data-node]', (xs) => xs.map((x) => x.dataset.node));
  check('B6b ② 흐름 그림에는 통신과 무관한 S3 · IAM · CloudFront 상자 없음', !kindsFlow.some((x) => /s3_bucket|iam_role|cloudfront/.test(x)) && ['aws_lb.alb', 'autoscaling_group.web', 'db_instance.primary'].every((k) => kindsFlow.some((x) => x.includes(k))), kindsFlow);
  check('B6c ② [전체 보기] 단추 없음 (13차 D-49) — 화면 어디에도', !(await p.$('[data-mapfull]')), '');
  const infAll = await p.evaluate(async () => (await (await fetch('/api/p/infra?id=webapp-3tier')).json()).arch.nodes.map((n) => n.id));
  check('B7 ② 서버 모델에는 리소스 전부 그대로 (그림만 통신만): CloudFront · ALB · NLB · ASG · RDS · 캐시 · S3 · IAM 역할', ['cloudfront_distribution', 'aws_lb.alb', 'aws_lb.nlb', 'autoscaling_group.web', 'db_instance.primary', 'elasticache', 's3_bucket', 'iam_role'].every((k) => infAll.some((x) => x.includes(k))), infAll);
  await p.click('#tInfra [data-node="n:aws_autoscaling_group.api"]');
  await p.waitForSelector('.apop');
  check('B5 ② 상자 누르면 들어오는 것 · 나가는 것', (await txt('.apop')).includes('들어오는 것') && (await txt('.apop')).includes('나가는 것'), await txt('.apop'));
  await shot('b-infra');
  await p.keyboard.press('Escape');

  // C. ③ 원하는 구조 (6차 · D-34): 왼쪽 = 설계도만 그린 그림 · 오른쪽 = 통신 목록 [허용]/[막기]
  await next();
  await p.waitForSelector('#tMap [data-node]', { timeout: 20000 });
  check('C1 ③ 머리말 · 원하는 구조 v1', (await txt('#mhead')).includes('우리 회사가 원하는 구조는 이거다') && (await txt('#mhead')).includes('원하는 구조 v1'));
  const rows3 = await p.$$eval('li.frow', (xs) => xs.map((x) => ({ t: x.querySelector('.fr-path').innerText.replace(/\s+/g, ' '), off: x.classList.contains('off'), fix: x.classList.contains('fix') })));
  const fix3 = rows3.filter((r) => r.fix).map((r) => r.t).sort();
  check('C2 ③ 통신 목록: 지금 코드와 다른 줄 2개 (인터넷 → bastion 22 · web → primary · replica 3306)', fix3.length === 2 && fix3.some((t) => t.includes('bastion') && t.includes(':22')) && fix3.some((t) => t.includes('primary · replica') && t.includes(':3306')), JSON.stringify(rows3));
  check('C2b ③ 다른 곳 수 = ④ 설계 위반 수 (2)', (await txt('.sdiff')).includes('2개'), await txt('.sdiff'));
  check('C3 ③ 설계도 그림: 겹쳐 그리지 않음(✕ 없음) · 설계도의 출처(관리자 대역) · 막은 통신은 선 없음', (await p.$$('#tMap .a-x')).length === 0 && (await p.$$('#tMap [data-node^="g:ext:"]')).length === 1
    && !(await p.$('#tMap .a-link[data-link="l:x:internet>n:aws_instance.bastion>main"]')), [(await p.$$('#tMap .a-x')).length, (await p.$$('#tMap [data-node^="g:ext:"]')).length]);
  check('C4 ③ 설계도 그림 = 흐름 그림 · [전체 보기] 없음', !(await p.$('[data-mapfull]')) && (await p.$$('#tMap .fnode')).length >= 8 && (await p.$$('#tMap .a-vpc, #tMap .a-band')).length === 0, await nodes('tMap'));
  const brow = await p.$('li.frow.fix');
  check('C5 ③ 줄마다 [허용] [막기] · 인터넷 출처는 이 IP만 허용', !!(await brow.$('[data-fr="allow"]')) && !!(await brow.$('[data-fr="block"]')) && (await brow.innerText()).includes('이 IP만 허용'), await brow.innerText());
  await shot('c-design');

  // D. ④ 보안 문제
  await next();
  const top4 = await txt('.issues-top');
  check('D1 ④ 문제 20개 · 고칠 수 있는 문제 2 · 탐지만 18 · 우리만 1 (거름 버튼 · 검사 범위 표 없음)', /문제 20개/.test(top4) && /고칠 수 있는 문제 2/.test(top4) && /탐지만 18/.test(top4) && /1\s*Trivy 는 못 보고/.test(top4) && !(await p.$('[data-ifilter]')) && !(await p.$('[data-act="coverage"]')), top4);
  check('D1b ④ 고칠 수 있는 문제 2개가 먼저, 탐지만 되는 18개는 접힘', (await p.$$('.ilist section.fixable .iitem')).length === 2 && !(await p.$eval('.irest', (d) => d.open)) && (await txt('.irest > summary')).includes('18'), await txt('.ilist'));
  const first = await txt('.iitem');
  check('D2 ④ 첫 문제 = SSH 관리 포트 (Trivy+자체+설계 합침)', first.includes('보안 그룹이 SSH · RDP 를 모든 IP 에서 받음') && first.includes('자체 검사') && first.includes('설계 위반'), first);
  await p.click('.iitem');
  await p.waitForTimeout(300);
  const det = await txt('.lay4 .col .mcard');
  check('D3 ④ 상세: 무엇 · 왜 · 어떻게 · 코드 위치 · CIS 근거', ['무엇', '왜 문제', '어떻게', 'security_groups.tf:', 'CIS AWS 1.2: 4.1, 4.2'].every((k) => det.includes(k)), det);
  check('D4 ④ 그림(아래)에서 강조', await p.$eval('#tIssue', (s) => s.classList.contains('focus')));
  check('D5 ④ 두 번째 고칠 수 있는 문제 = 웹 서버 → MySQL (Trivy 는 못 봄)', (await p.$$eval('.ilist section.fixable .iitem', (xs) => xs.map((x) => x.innerText)))[1].includes('웹 서버 → MySQL'));
  await p.click('.irest > summary'); await p.waitForTimeout(200);
  check('D5b ④ 탐지만 되는 문제 펼치기 → 18개', (await p.$$('.irest .iitem')).length === 18);
  // S3 문제를 고른 채로 ⑤ 로 가도 고칠 문제 제목은 묶음의 대상 지적이어야 한다
  const s3 = await p.$$('.iitem');
  for (const it of s3) { if ((await it.innerText()).includes('S3 버킷 접근 기록')) { await it.click(); break; } }
  await p.waitForTimeout(200);
  await shot('d-issues');
  await next();
  check('D6 ⑤ 고칠 문제 = 0107 (S3 문제를 골랐어도)', (await txt('.target')).includes('보안 그룹이 SSH · RDP 를 모든 IP 에서 받음'), await txt('.target'));

  // E. ⑤ 수정안 (11차 D-47): 수정안 1~4 큰 버튼 — 미리 분석해 두어 누르면 바로 오른쪽 그림. AI 버튼 맨 위 · '후보' 낱말 없음 · 팀 평가용 25개 목록 없음
  await p.waitForFunction(() => !document.querySelector('.pfx.run'), null, { timeout: 420000 });   // 프로젝트를 열 때 시작한 미리 분석이 끝날 때까지 (처음 한 번)
  await p.waitForTimeout(600);
  const bigs = await p.$$eval('.tbig .cbig', (xs) => xs.map((x) => x.innerText.replace(/\s+/g, ' ')));
  check('N7 ⑤ 수정안 4개 큰 버튼 (번호 · 바꾼 곳 · 결과) · 모두 분석됨 · "후보" 낱말 없음 · 25개 목록 없음', bigs.length === 4 && bigs.every((t) => !t.includes('분석 전')) && !(await p.$('.tlist')) && !(await p.$('[data-act="team-toggle"]')) && !(await txt('.cands')).includes('후보'), bigs);
  // 12차 (D-48): 번호 줄 → 그림 → 결과 → '다른 방법'(AI · 설계도대로 자동 수정 · 내 파일) 순서 — 번호와 그림이 붙어 있다
  const order5 = await p.$$eval('.tbig, .pic1, .cands.other .cg.ai [data-src="ai"], .cg.rb', (xs) => xs.map((x) => x.className.split(' ')[0] || x.tagName));
  check('N7b ⑤ 순서: 수정안 번호 → 그림 → 다른 방법(AI · 규칙 기반)', order5[0] === 'tbig' && order5[1] === 'pic1' && order5.length === 4, order5);
  check('E1 ⑤ 수정안마다 무엇을 바꿨나 한 줄 (정답 이름 없음) · 결과는 통과 1 · 막힘 3', bigs.filter((t) => t.includes('통과')).length === 1 && bigs.filter((t) => t.includes('막힘')).length === 3 && !/correct|deceptive|정답/.test(await txt('.tbig')), bigs);
  check('E1b ⑤ 고르기 전: 그림 = 고객 설계도 · 아래 안내 (12차: 그림 하나)', (await nodes('tPic')) >= 8 && (await txt('.mc-head')).includes('고객 설계도 v1') && (await txt('.picnote')).includes('위에서 수정안 번호를 누르세요') && !(await p.$('.pair')), await txt('.picnote'));
  await p.click('[data-cand="correct-design"]');
  await p.waitForFunction(() => (document.querySelector('.mc-head b') || {}).textContent?.includes('적용 후'), null, { timeout: 20000 });
  await p.waitForSelector('#tPic [data-node]', { timeout: 20000 });
  check('E2 ⑤ 수정안 3 (설계도대로) 누르면 같은 그림이 적용 후로 바뀜 · 설계도와 같음', (await nodes('tPic')) >= 8 && (await txt('.mc-head b')).includes('수정안 3 적용 후') && (await txt('.pdiff')).includes('설계도와 같음') && (await p.$$('#tPic .a-x')).length === 0, await txt('.pdiff'));
  const afterNames = await p.$eval('#tPic', (s) => s.textContent);
  await p.click('[data-pv="design"]'); await p.waitForTimeout(400);
  check('E2b ⑤ [고객 설계도] 단추 → 같은 자리에 설계도 · 같은 출처는 같은 이름 (관리자 접속 허용 목록)', (await txt('.mc-head b')).includes('고객 설계도') && afterNames.includes('관리자 접속 허용 목록') && (await p.$eval('#tPic', (s) => s.textContent)).includes('관리자 접속 허용 목록') && (await p.$$('#tPic .a-x')).length === 0);
  await p.click('[data-pv="after"]'); await p.waitForTimeout(400);
  const grid = await txt('.cmp-grid');
  check('E3 ⑤ 이 수정안이 바꾼 통신 ＋/－ · 해결된 문제 · 자세히 접힘 칸 없음', grid.includes('＋') && grid.includes('－') && grid.includes('해결 · Trivy') && !(await p.$('.mdetails')), grid);
  check('E5 ⑤ 실제 AWS 기록 안내 (같은 후보 파일)', (await txt('.cmpwrap')).includes('AWS 시험 환경 검사까지 한 기록'), await txt('.cmpwrap'));
  await p.screenshot({ path: `${SHOTS}/e-compare.png` });
  await p.click('[data-mzoom="tPic"]');
  await p.waitForSelector('#zoomMap [data-node]');
  check('E6 ⑤ 크게 보기 (그림 하나)', (await p.$$('#zoomMap [data-node]')).length >= 8 && !(await p.$('#zDesign')));
  await p.click('.mm-x');
  // 다른 번호 → 그림이 바로 바뀐다 (기다림 없이): 수정안 1 = 지목된 줄만 고침 → 웹 → MySQL 이 남아 빨강
  await p.click('[data-cand="flagged-only-fix"]');
  await p.waitForFunction(() => (document.querySelector('.pdiff') || {}).textContent && document.querySelector('.pdiff').textContent.includes('설계도와 다른 곳'), null, { timeout: 15000 });
  check('E6b ⑤ 수정안 1 누르면 그림이 그 수정안으로 — 빨강 ✕ (웹 서버 → MySQL 설계도에 없는 통신)', (await p.$$('#tPic .a-x')).length >= 1 && (await txt('.mc-head b')).includes('수정안 1 적용 후') && /primary :3306/.test(await txt('.pdiff')), await txt('.pdiff'));
  check('E6c ⑤ 머리말 할 일 = 막힘 + 이유', (await txt('.mh-todo')).includes('막혔습니다'), await txt('.mh-todo'));
  await p.click('[data-cand="redis-from-web"]');
  await p.waitForFunction(() => (document.querySelector('.pdiff') || {}).textContent && document.querySelector('.pdiff').textContent.includes(':6379'), null, { timeout: 15000 });
  check('E7 ⑤ 수정안 4 누르면 그림이 그 수정안으로 (redis 에 설계도에 없는 통신 :6379)', /redis :6379/.test(await txt('.pdiff')) && (await p.$$('#tPic .a-x')).length >= 1 && (await txt('.mc-head b')).includes('수정안 4 적용 후'), await txt('.pdiff'));
  await p.click('[data-cand="flagged-only-fix"]');
  await p.waitForFunction(() => (document.querySelector('.pdiff') || {}).textContent && document.querySelector('.pdiff').textContent.includes(':3306'), null, { timeout: 15000 });
  check('E8 ⑤ 수정안 1 로 돌아오기 — 기록을 다시 쓰므로 바로 (고른 버튼 표시)', !!(await p.$('.cbig.on[data-cand="flagged-only-fix"]')) && (await txt('.pdiff')).includes('설계도와 다른 곳'), await txt('.cmp-line'));

  // F. ⑥ · ⑧ 막힌 후보
  await next();
  check('F1 ⑥ 결론 배너 = 승인 불가 (설계 위반)', (await txt('.verdict')).includes('승인 불가'), await txt('.verdict'));
  check('F2 ⑥ 질문 5개 (질문 글에 V 번호 없음 · 자세히 접힘 · 전문가 화면 버튼 없음)', (await p.$$('.qrow')).length === 5 && !/\bV[1-8]\b/.test(await p.$$eval('.qh b', (xs) => xs.map((x) => x.textContent).join(' '))) && !(await p.$('.qrow details')) && !(await p.$('a[href^="/work"]')));
  await next(); await next();
  await p.waitForSelector('.final-grid');
  const fin = await txt('#mbody');
  // 17차 (D-53): ⑧ 위의 결론 배너 · 세 단계 띠는 ⑥ 과 같아서 뺐다 — 승인 불가 이유는 '다음 할 일' · 결정 칸 · 고객 요청 칸(어김)에
  check('F3 ⑧ 승인 불가 (수정안 1: 웹 → MySQL 남음 — 고객 요청 조건 어김) · 결론 배너 · 버전 카드 없음', fin.includes('승인 불가') && fin.includes('어김') && !(await p.$('#mbody .verdict')) && !(await p.$('#mbody .stages3')) && !(await p.$('.vers')), fin.slice(0, 600));
  check('F4 ⑧ 승인 버튼 막힘 + 이유', await p.$eval('[data-dec="APPROVED"]', (b) => b.disabled) && fin.includes('승인 불가:'), fin.slice(-800));
  await shot('f-final-blocked');

  // G. 실제 AWS 까지 확인된 기록 → 승인 → PR 미리보기 (실행 안 함)
  await p.goto(BASE + '#p=webapp-3tier&s=8&rec=20261023-124957-af6f0b', { waitUntil: 'networkidle' });
  await p.reload({ waitUntil: 'networkidle' });
  await p.waitForSelector('.final-grid', { timeout: 20000 });
  check('G1 ⑧ AWS 시험 환경에서 확인됨 — 운영 반영 후 확인 아님 (세 단계 띠는 ⑥ 에만)', (await txt('.final-grid')).includes('AWS 시험 환경에서 확인됨 — 운영 반영 후 확인 아님') && !(await p.$('#mbody .stages3')), await txt('.final-grid'));
  check('G2 ⑧ 승인 가능', !(await p.$eval('[data-dec="APPROVED"]', (b) => b.disabled)));
  await p.click('[data-dec="APPROVED"]');
  await p.fill('#decReason', 'E2E: 설계 일치 · 실제 AWS 확인');
  await p.fill('#decBy', 'e2e');
  await p.click('[data-act="decide"]');
  await p.waitForSelector('.mtoast');
  check('G3 승인 기록', (await txt('.mtoast')).includes('결정을 기록함'), await txt('.mtoast'));
  await p.waitForSelector('[data-act="pr-check"]', { timeout: 10000 });
  check('G4 PR 만들기: 준비 확인 전에는 막힘', await p.$eval('[data-act="pr-create"]', (b) => b.disabled));
  await p.click('[data-act="pr-check"]');
  await p.waitForFunction(() => document.querySelectorAll('.prchk li').length >= 5, null, { timeout: 15000 });
  const chkTxt = await txt('.prchk');
  // 기준 브랜치 main 에는 3계층 폴더가 없음 → 막히고 할 일을 보여 줘야 함
  check('G5 PR 준비 확인(main): 막히는 이유 · 사람이 할 일', chkTxt.includes('사람의 승인') && chkTxt.includes('프로젝트 폴더 scenarios/arch/webapp-3tier 가 없음') && chkTxt.includes('할 일: 원본 코드가 올라간 브랜치를 기준으로'), chkTxt.slice(0, 900));
  check('G6 PR 만들기: 준비가 안 됐으면 막힘', await p.$eval('[data-act="pr-create"]', (b) => b.disabled));
  await shot('g-pr-blocked');
  // 시험 복사본에만 만든 기준(origin/e2e-base = 원본 커밋) → 통과 → 미리보기 → 확인 창 (실행 안 함)
  await p.fill('#prBase', 'e2e-base');
  await p.click('[data-act="pr-check"]');
  await p.waitForFunction(() => document.querySelectorAll('.prchk li.ok').length >= 5 && !document.querySelector('.prchk li.bad'), null, { timeout: 15000 }).catch(() => {});
  check('G7 PR 준비 확인(e2e-base): 모두 통과', !(await p.$('.prchk li.bad')), await txt('.prchk'));
  await p.click('[data-act="pr-preview"]');
  await p.waitForTimeout(1500);
  const prv = await txt('.lay8 .mcard:last-child');
  check('G8 PR 미리보기: 기준 브랜치 · 후보 id 없는 브랜치 이름', prv.includes('git checkout -b iacpatch/arch-3tier-sg-20261023-124957-af6f0b origin/e2e-base') && !prv.includes('correct-design-2026'), prv.slice(0, 900));
  check('G9 PR 만들기 버튼 열림', !(await p.$eval('[data-act="pr-create"]', (b) => b.disabled)));
  await p.click('[data-act="pr-create"]');
  await p.waitForSelector('#prConfirm');
  check('G10 PR 만들기: 확인 문구 입력창 (여기서 취소 — 실행 안 함)', true);
  await shot('g-pr');
  await p.click('.mmodal [data-close]');

  // H. 2계층: 설계도 없음 → 자동 기준 v1 (지금 코드 − 위험한 통신) → 목록에서 SSH 를 '이 IP만 허용' 으로 v2 → 설계 위반이 문제 목록에
  // (11차: 2계층은 화면 목록에서 숨김 — 주소로 열어 자동 초안 · IAM 요구사항 기능이 그대로인지 본다)
  await p.goto('about:blank');
  await p.goto(BASE + '#p=webapp-2tier&s=2', { waitUntil: 'networkidle' });
  await p.waitForSelector('#tInfra [data-node]', { timeout: 20000 });
  await next();
  await p.waitForSelector('#tMap [data-node]', { timeout: 20000 });
  const d3 = await txt('#mbody');
  check('H1 ③ 자동 기준 v1 · 위험한 통신은 막음 (목록)', d3.includes('v1 은 프로그램이 자동으로 만든 설계도입니다') && d3.includes('위험해서 자동으로 막음 — 인터넷 전체 → 관리 포트 SSH(22)'), d3.slice(0, 900));
  check('H2 ③ 설계도 그림: 인터넷 → web 은 80 만 (22 는 설계도에 없음)', (await p.$$eval('#tMap text.alab', (xs) => xs.map((x) => x.textContent))).some((t) => t === ':80') && !(await p.$$eval('#tMap text.alab', (xs) => xs.map((x) => x.textContent))).some((t) => t.includes('22')));
  const r22 = 'li.frow[data-key$="|22"]';
  await p.click(`${r22} [data-fr="ip"]`);
  await p.fill(`${r22} [data-i="cidr"]`, '203.0.113.0/24');
  await p.fill(`${r22} [data-i="label"]`, '운영팀 사무실');
  await p.click(`${r22} [data-fr="ip-ok"]`);
  await p.waitForFunction(() => document.querySelector('.ssave') && !document.querySelector('.ssave [data-act="s-save"]').disabled, null, { timeout: 15000 });
  check('H3 ③ 이 IP만 허용 → 바꾼 것 1개 · 목록에 운영팀 줄 · 그림에 운영팀', (await txt('.ssave')).includes('바꾼 것 1개') && (await txt('.frows')).includes('운영팀 사무실') && (await p.$eval('#tMap', (s) => s.textContent)).includes('운영팀 사무실'), await txt('.ssave'));
  // [막기] → [허용] 으로 되돌리면 바꾼 것에서 빠짐
  await p.click('li.frow[data-key$="|80"] [data-fr="block"]');
  await p.waitForFunction(() => (document.querySelector('.ssave') || {}).textContent && document.querySelector('.ssave').textContent.includes('바꾼 것 2개'), null, { timeout: 15000 });
  await p.click('li.frow[data-key$="|80"] [data-fr="allow"]');
  await p.waitForFunction(() => (document.querySelector('.ssave') || {}).textContent && document.querySelector('.ssave').textContent.includes('바꾼 것 1개'), null, { timeout: 15000 });
  check('H4 ③ 원래대로 되돌린 선택은 바꾼 것에서 빠짐', (await txt('.ssave')).includes('바꾼 것 1개'), await txt('.ssave'));
  await p.waitForFunction(() => !document.querySelector('.ssave [data-act="s-save"]').disabled, null, { timeout: 15000 });
  await p.fill('#sNote', 'E2E: SSH 는 사무실 대역만');
  await p.click('.ssave [data-act="s-save"]');
  await p.waitForSelector('.mtoast');
  check('H5 저장 → v2 (v1 = 자동 기준)', (await txt('.mtoast')).includes('설계도 v2 저장'), await txt('.mtoast'));
  await p.waitForTimeout(800);
  check('H6 ③ v2: 버전 v1 · 자동 / v2 · 지금 · 다른 곳 1개', (await txt('.vstrip')).includes('v1 · 자동') && (await txt('.vstrip')).includes('v2 · 지금') && (await txt('.sdiff')).includes('1개'), [await txt('.vstrip'), await txt('.sdiff')]);
  check('H6b ③ 버튼 정리: 그림 위 바꾸기 창 · AI 바로가기 없음', !(await p.$('[data-act="s-aifix"]')) && !(await p.$('.apop')));
  // R. IAM 요구사항 파일 버전 (D-40): v1 = 팀 작성 평가 기준 → 고친 JSON 올리기 → v2 초안 · 지금 기준 → 확정
  const req0 = await txt('.mcard.reqs');
  check('R1 ③ 그 밖의 고객 요구사항: IAM v1 · 팀 작성 평가 기준 · 올리기 버튼', req0.includes('v1 · 팀 작성 평가 기준') && !!(await p.$('[data-reqfile="arch-webapp-iam"]')) && !(await p.$('[data-act="r-confirm"]')), req0.slice(0, 300));
  const iamRaw = JSON.parse(require('fs').readFileSync(`${SP}/e2e/cap/experiments/candidate-sets/arch-webapp-iam/intents/arch-webapp-web-role.json`, 'utf8'));
  const iamBad = { ...iamRaw, intent_id: 'other-role' };
  const iamNew = JSON.parse(JSON.stringify(iamRaw)); iamNew.approved_permissions[0].actions = ['s3:GetObject']; iamNew.required_permissions = iamNew.required_permissions.filter((x) => x.action === 's3:GetObject');
  require('fs').writeFileSync(`${SHOTS}/iam-bad.json`, JSON.stringify(iamBad, null, 2)); require('fs').writeFileSync(`${SHOTS}/iam-v2.json`, JSON.stringify(iamNew, null, 2));
  await p.setInputFiles('[data-reqfile="arch-webapp-iam"]', `${SHOTS}/iam-bad.json`);
  await p.waitForSelector('#riGo'); await p.fill('#riBy', 'E2E'); await p.click('#riGo'); await p.waitForTimeout(400);
  check('R2 다른 요구사항 파일(intent_id 다름) → 거절 + 이유', !!(await p.$('#riGo')) && (await txt('.mtoast')).includes('intent_id'), await txt('.mtoast'));
  await p.click('.mmodal [data-close], .mm-x'); await p.waitForTimeout(200);
  await p.setInputFiles('[data-reqfile="arch-webapp-iam"]', `${SHOTS}/iam-v2.json`);
  await p.waitForSelector('#riGo'); await p.fill('#riNote', 'E2E: 고객이 ListBucket 을 뺌'); await p.fill('#riBy', '박지민'); await p.click('#riGo');
  await p.waitForFunction(() => (document.querySelector('.mcard.reqs') || {}).textContent && document.querySelector('.mcard.reqs').textContent.includes('v2 · 초안'), null, { timeout: 15000 });
  const req1 = await txt('.mcard.reqs');
  check('R3 올린 판 = v2 · 초안 · 지금 기준, 목록에 ListBucket 없음, 확정 버튼 · v1 칩은 팀 작성', req1.includes('v2 · 초안 — 확정 전') && req1.includes('v1 · 팀 작성') && req1.includes('v2 · 지금 · 초안') && !req1.includes('ListBucket') && !!(await p.$('[data-act="r-confirm"]')), req1.slice(0, 400));
  await p.click('[data-act="r-confirm"]'); await p.waitForSelector('#cfBy'); await p.fill('#cfBy', '박지민'); await p.fill('#cfNote', 'E2E: 고객 메일'); await p.click('#cfGo');
  await p.waitForFunction(() => (document.querySelector('.mcard.reqs') || {}).textContent && document.querySelector('.mcard.reqs').textContent.includes('확정 · 박지민'), null, { timeout: 15000 });
  check('R4 확정 → v2 · 확정 · 박지민 (칩 v2 · 지금 · 확정)', (await txt('.mcard.reqs')).includes('v2 · 지금 · 확정'), await txt('.mcard.reqs'));
  await shot('r-iam-versions');
  await next();
  const it2 = await txt('.ilist');
  check('H7 ④ 2계층 SSH 문제에 설계 위반 출처가 합쳐짐', /보안 그룹이 SSH · RDP 를 모든 IP 에서 받음[\s\S]*설계 위반/.test(it2), it2.slice(0, 400));
  await shot('h-2tier-issues');
  // ⑦ 2계층은 실제 AWS 미검증
  await next();
  await p.click('[data-cand="rule-based"]');
  await p.waitForSelector('.cmp-line', { timeout: 20000 });
  await next(); await next();
  check('H8 ⑦ 2계층 = 미검증 (시험 환경 없음)', (await txt('#mbody')).includes('미검증 — 이 프로젝트는 AWS 시험 환경이 없습니다'));
  // R5. ⑤ IAM 묶음 머리 = IAM 요구사항 v2 (박지민 확정) — 검사 입력이 올린 판을 따라감
  await p.click('[data-go="5"]'); await p.waitForSelector('.target', { timeout: 20000 });
  if (await p.$('[data-target="arch-webapp-iam"]')) { await p.click('[data-target="arch-webapp-iam"]'); await p.waitForTimeout(500); }
  check('R5 ⑤ IAM 묶음: 지켜야 할 기준 = IAM 요구사항 v2 (박지민 확정)', (await txt('.target')).includes('IAM 요구사항 v2 (박지민 확정)'), await txt('.target'));

  // I. AI 수정 (시험용 대역: 시도 1 막힘 → 시도 2 통과)
  await p.goto(BASE + '#p=webapp-3tier&s=5', { waitUntil: 'networkidle' });
  await p.reload({ waitUntil: 'networkidle' });
  await p.waitForSelector('[data-src="ai"]', { timeout: 20000 });
  await p.click('[data-src="ai"]');
  await p.click('[data-ctx="design"]');
  await p.click('[data-act="ai-run"]');
  await p.waitForSelector('.mcard.run', { timeout: 10000 });
  check('I1 AI 수정 진행 표시', (await txt('.mcard.run')).includes('AI 수정'));
  await p.waitForSelector('.cmp-line', { timeout: 300000 });
  await p.waitForTimeout(1500);
  const ai = await p.$eval('.cmpwrap', (x) => x.textContent);
  check('I2 AI 결과: 시도 기록(막힘 → 통과) 표시', ai.includes('이 AI 수정의 시도 기록') && ai.includes('시도 1') && ai.includes('시도 2'), ai.slice(0, 600));
  check('I3 AI 결과: 적용 후 그림', (await nodes('tPic')) >= 7 && (await txt('.mc-head b')).includes('적용 후'));
  const att = await p.$$eval('.cands [data-aiatt]', (xs) => xs.map((x) => x.textContent.trim()));
  check('I4 AI 시도가 하나씩 후보 버튼 (1차 ✕ · 2차 ✓)', att.length >= 2 && att.some((t) => t.startsWith('1차') && t.includes('✕')) && att.some((t) => t.startsWith('2차') && t.includes('✓')), att);
  await p.click('.cands [data-aiatt$="|1"]');
  await p.waitForFunction(() => (document.querySelector('.cmp-line') || {}).textContent && document.querySelector('.cmp-line').textContent.includes('시도 1'), null, { timeout: 15000 });
  check('I5 1차 시도 버튼 → 그 시도의 결과 (막힘)', (await txt('.cmp-line')).includes('시도 1'), await txt('.cmp-line'));
  await shot('i-ai');

  // N8. ⑦ 실제 AWS 검사 순서 (시험 환경이 있는 3계층)
  await p.goto(BASE + '#p=webapp-3tier&s=7&rec=20261023-124957-af6f0b', { waitUntil: 'networkidle' });
  await p.reload({ waitUntil: 'networkidle' });
  await p.waitForSelector('.awsflow', { timeout: 20000 }).catch(() => {});
  const af = await p.$$eval('.awsflow li', (xs) => xs.map((x) => x.textContent));
  check('N8 ⑦ 실제 AWS 검사 순서 5칸 (사람 단계 표시)', af.length === 5 && af.filter((x) => x.includes('사람')).length >= 3 && (await txt('.narrow')).includes('AWS 시험 환경에서 확인됨') && (await txt('.narrow .stages3')).includes('배포 전 검사'), af);

  // N9 · N10. PR 바로 가기 (B 11-02 "PR 할 링크도 하이라이트 안에 넣어서 바로 넘어가게") — 이동만, PR 을 만들지 않음
  await p.click('[data-act="goto-pr"]');
  await p.waitForSelector('#prcard.flash', { timeout: 8000 }).catch(() => {});
  check('N9 왼쪽 메뉴 PR 만들기 → ⑧ PR 칸으로 가서 밝게', (await txt('#mhead h1')).includes('최종적으로 무엇을 결정해야 하지?') && !!(await p.$('#prcard.flash')), await txt('#mhead h1'));
  await p.click('[data-go="6"]'); await p.waitForTimeout(800);
  check('N10 ⑥ 에서도 화면 안내 버튼 없음 (11차) — 머리말은 할 일 한 줄', !(await p.$('#mhead [data-act="tour"]')) && (await txt('#mhead .mh-todo')).includes('할 일'), await txt('#mhead'));

  check('Z 화면 오류 없음', errs.length === 0, errs.join(' | '));
  console.log(`\n${pass} PASS / ${fail} FAIL`);
  await b.close();
  process.exit(fail ? 1 : 0);
})();
