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
  check('N3 머리말 = 할 일 한 줄 + 이 화면 안내', (await txt('#mhead .mh-todo')).includes('할 일') && !!(await p.$('#mhead [data-act="tour"]')), await txt('#mhead'));
  check('N3b 시작하기 카드 3개 · 폴더 연결 칸은 눌러야 펼침', (await p.$$('.mstart .sopt')).length === 3 && !(await p.$('.pnew')), await txt('.mstart'));
  await p.click('#mhead [data-act="tour"]');
  await p.waitForSelector('.tour-box');
  let tn = 0; const tt = [];
  while ((await p.$('.tour')) && tn < 12) { tn++; tt.push((await txt('.tour-box b')).trim()); await p.click('[data-tour="1"]'); await p.waitForTimeout(150); }
  check('N4 화면 안내: 부분을 하나씩 (① 은 5칸 이상) · 끝나면 닫힘', tn >= 5 && !(await p.$('.tour')) && tt.includes('준비 상태'), tt);
  await p.click('.mside-foot [data-act="glossary"]');
  await p.fill('#glq', 'CIDR');
  check('N5 용어 풀이: 찾기 (CIDR → IP 대역 · 0.0.0.0/0 = 인터넷 전체)', (await txt('#glb')).includes('0.0.0.0/0 = 인터넷 전체'), await txt('#glb'));
  await p.click('.mm-x');
  await p.click('#mbig');
  const bigOn = await p.evaluate(() => document.body.classList.contains('big'));
  await p.click('#mbig');
  check('N6 크게 보기 켜기 · 끄기', bigOn && !(await p.evaluate(() => document.body.classList.contains('big'))));
  check('A2 시작: 프로젝트 카드 2개', (await p.$$('.pcard')).length === 2, body.slice(0, 200));
  check('A3 시작: V 번호 없음', !/\bV[1-8]\b/.test(body), body.match(/\bV[1-8]\b/));
  await p.click('.mside-foot [data-act="coverage"]');
  await p.waitForSelector('table.cov');
  const covRows = await p.$$eval('table.cov tbody tr', (xs) => xs.length);
  check('A4 검사 범위 표: 행 15개 이상 · 탐지 ≠ 수정 안내', covRows >= 15 && (await txt('.mm-b')).includes("'탐지 지원' 과 '수정 지원' 은 다르다"), covRows);
  await shot('a-coverage');
  await p.click('.mm-x');

  // B. 3계층 열기 → ② 현재 인프라 (코드에서 그림)
  await p.click('[data-open="webapp-3tier"]');
  await p.waitForSelector('#tInfra [data-node]', { timeout: 20000 });
  check('B1 ② 코드 그림 노드 7개 이상', (await nodes('tInfra')) >= 7, await nodes('tInfra'));
  const nums2 = await txt('.mpanel .nums');
  check('B2 ② 리소스 62 · 위험한 허용 1', nums2.includes('62') && /1\s*위험한 허용/.test(nums2), nums2);
  check('N9a 왼쪽 메뉴 ⑧ 밑 PR 만들기 = 후보 분석 전엔 잠김', await p.$eval('[data-act="goto-pr"]', (x) => x.disabled));
  const invClosed = !(await p.$eval('.dcard', (d) => d.open));
  await p.click('.dcard > summary');
  check('B3 ② 그림에 넣지 않은 것 표시 (목록만) — 기본은 접힘, 누르면 펼침', invClosed && (await txt('.invgrid')).includes('목록만 — 그림에 없음'), await txt('.invgrid'));
  const vb = await p.$eval('#tInfra', (s) => [s.getBoundingClientRect().width, s.getBoundingClientRect().height]);
  check('B4 ② 그림이 비율대로 (빈 칸 없음)', vb[1] < vb[0] * 0.75 && vb[1] > 150, vb);
  const frame = await p.$eval('#tInfra', (s) => [s.querySelectorAll('.a-vpc').length, s.querySelectorAll('.a-band.public').length, s.querySelectorAll('.a-band.private_nat, .a-band.private').length, s.querySelectorAll('.a-out').length, s.querySelectorAll('.abadge').length]);
  check('B6 ② AWS 구성도: VPC · 공개 · 비공개 서브넷 · VPC 밖 서비스 · 문제 수', frame[0] === 1 && frame[1] === 1 && frame[2] === 1 && frame[3] === 1 && frame[4] >= 3, frame);
  const kinds = await p.$$eval('#tInfra [data-node]', (xs) => xs.map((x) => x.dataset.node));
  check('B7 ② 코드의 리소스: CloudFront · ALB · NLB · ASG · RDS · 캐시 · S3 · IAM 역할', ['cloudfront_distribution', 'aws_lb.alb', 'aws_lb.nlb', 'autoscaling_group.web', 'db_instance.primary', 'elasticache', 's3_bucket', 'iam_role'].every((k) => kinds.some((x) => x.includes(k))), kinds);
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
  const nOnly = await nodes('tMap');
  await p.click('[data-mapfull]'); await p.waitForTimeout(400);
  check('C4 ③ 전체 보기 ↔ 통신 관련만', (await nodes('tMap')) > nOnly, [nOnly, await nodes('tMap')]);
  await p.click('[data-mapfull]'); await p.waitForTimeout(300);
  const brow = await p.$('li.frow.fix');
  check('C5 ③ 줄마다 [허용] [막기] · 인터넷 출처는 이 IP만 허용', !!(await brow.$('[data-fr="allow"]')) && !!(await brow.$('[data-fr="block"]')) && (await brow.innerText()).includes('이 IP만 허용'), await brow.innerText());
  await shot('c-design');

  // D. ④ 보안 문제
  await next();
  const top4 = await txt('.issues-top');
  check('D1 ④ 문제 20개 · Trivy 19 · 우리만 1 (한 줄 요약 + 강조 칸)', /문제 20개/.test(top4) && /Trivy 가 찾은 것 19/.test(top4) && /1\s*Trivy 는 못 보고/.test(top4) && !(await p.$('.issues-top .nums')), top4);
  const first = await txt('.iitem');
  check('D2 ④ 첫 문제 = SSH 관리 포트 (Trivy+자체+설계 합침)', first.includes('보안 그룹이 SSH · RDP 를 모든 IP 에서 받음') && first.includes('자체 검사') && first.includes('설계 위반'), first);
  await p.click('.iitem');
  await p.waitForTimeout(300);
  const det = await txt('.lay4 .col .mcard');
  check('D3 ④ 상세: 무엇 · 왜 · 어떻게 · 코드 위치 · CIS 근거', ['무엇', '왜 문제', '어떻게', 'security_groups.tf:', 'CIS AWS 1.2: 4.1, 4.2'].every((k) => det.includes(k)), det);
  check('D4 ④ 그림에서 강조', await p.$eval('#tIssue', (s) => s.classList.contains('focus')));
  await p.click('[data-ifilter="ours"]');
  await p.waitForTimeout(200);
  const ours = await p.$$('.iitem');
  check('D5 ④ Trivy 밖 필터 = 1개 (웹 서버 → MySQL)', ours.length === 1 && (await txt('.iitem')).includes('웹 서버 → MySQL'), ours.length);
  await p.click('[data-ifilter="all"]');
  // S3 문제를 고른 채로 ⑤ 로 가도 고칠 문제 제목은 묶음의 대상 지적이어야 한다
  const s3 = await p.$$('.iitem');
  for (const it of s3) { if ((await it.innerText()).includes('S3 버킷 접근 기록')) { await it.click(); break; } }
  await p.waitForTimeout(200);
  await shot('d-issues');
  await next();
  check('D6 ⑤ 고칠 문제 = 0107 (S3 문제를 골랐어도)', (await txt('.target')).includes('보안 그룹이 SSH · RDP 를 모든 IP 에서 받음'), await txt('.target'));

  // E. ⑤ 수정 후보 (6차 · 7차): AI 가 맨 위 · 팀 시험 후보는 한 줄 요약으로 접어 두고 펼치면 하나씩 (합치지 않음) · 누르면 왼쪽 설계도 · 오른쪽 그 후보 적용 후
  const tsum = await txt('.tsum');
  check('N7 ⑤ 팀 평가용 수정안 = 한 줄 요약(검사함 · 통과 · 막힘 · 검사 전), 처음엔 접힘 · AI 버튼이 맨 위 · "후보" 낱말 없음', /25개/.test(tsum) && tsum.includes('검사함') && tsum.includes('검사 전') && !(await p.$('.tlist')) && !!(await p.$('.cands .cg.ai [data-src="ai"]')) && (await txt('.cands')).includes('팀 평가용 수정안') && !(await txt('.cands')).includes('후보'), tsum);
  await p.click('[data-act="team-toggle"]');
  const chips = await p.$$eval('.cands [data-cand]', (xs) => xs.length);
  const row1 = await txt('.tlist .trow');
  check('E1 ⑤ 펼치면 팀 후보 25개 이상 하나씩 · 후보마다 무엇을 바꿨나 한 줄 (정답 이름 없음)', chips >= 25 + 1 && !(await p.$('.cl-team')) && /보안 그룹 .*변경 \(\+\d+ −\d+줄\)/.test(row1) && !/correct|deceptive|정답/.test(await txt('.tlist')), [chips, row1]);
  check('E1b ⑤ 고르기 전: 왼쪽 설계도 · 오른쪽 안내', (await nodes('tDesign')) >= 8 && (await txt('.pair')).includes('위에서 수정안을 누르세요'), await txt('.pair'));
  await p.click('[data-cand="correct-design"]');
  await p.waitForSelector('#tAfter [data-node]', { timeout: 20000 });
  check('E2 ⑤ 오른쪽 = 이 후보 적용 후 · 설계도와 같음', (await nodes('tAfter')) >= 8 && (await txt('.pdiff')).includes('설계도와 같음') && (await p.$$('#tAfter .a-x')).length === 0, await txt('.pdiff'));
  check('E2b ⑤ 같은 출처는 두 그림에서 같은 이름 (관리자 접속 허용 목록)', (await p.$eval('#tAfter', (s) => s.textContent)).includes('관리자 접속 허용 목록') && (await p.$eval('#tDesign', (s) => s.textContent)).includes('관리자 접속 허용 목록'));
  const grid = await txt('.cmp-grid');
  check('E3 ⑤ 이 후보가 바꾼 통신 ＋/－ · 해결된 문제', grid.includes('＋') && grid.includes('－') && grid.includes('해결 · Trivy'), grid);
  check('E4 ⑤ 자세히: 설계도와 비교(V6) 일치', (await txt('.mdetails')).includes('일치') || (await p.$eval('.mdetails', (d) => d.innerHTML)).includes('일치'));
  check('E5 ⑤ 실제 AWS 기록 안내 (같은 후보 파일)', (await txt('.cmpwrap')).includes('AWS 시험 환경 검사까지 한 기록'), await txt('.cmpwrap'));
  await p.screenshot({ path: `${SHOTS}/e-compare.png` });
  await p.click('[data-act="pair-zoom"]');
  await p.waitForSelector('#zAfter [data-node]');
  check('E6 ⑤ 둘 다 크게 (나란히)', (await p.$$('#zDesign [data-node]')).length >= 8 && (await p.$$('#zAfter [data-node]')).length >= 8);
  await p.click('.mm-x');
  // 설계도와 다른 후보 — 다른 선만 빨강 + 목록
  const chipIds = await p.$$eval('.cands [data-cand]', (xs) => xs.map((x) => [x.dataset.cand, x.textContent]));
  let redFound = false;
  for (const [id, t] of chipIds) {
    if (!t.includes('✕')) continue;
    await p.click(`[data-cand="${id}"]`); await p.waitForTimeout(1200);
    if (await p.$('#tAfter [data-node]') && (await txt('.pdiff')).includes('설계도와 다른 곳')) { redFound = true; break; }
  }
  check('E6b ⑤ 설계도와 다른 후보: 오른쪽만 빨강 ✕ + 다른 곳 목록', redFound && (await p.$$('#tAfter .a-x')).length >= 1 && (await p.$$('#tDesign .a-x')).length === 0, await txt('.pdiff'));
  // 막힌 후보 — 그림 대신 이유
  await p.click('[data-cand="ref-undeclared"]');
  await p.waitForFunction(() => (document.querySelector('.cmp-head') || {}).textContent && document.querySelector('.cmp-head').textContent.includes('수정안 01'), null, { timeout: 15000 });
  check('E7 ⑤ 막힌 후보: 적용 후 그림 대신 쉬운 이유 + 기술 이유(작게)', (await txt('.pair')).includes("'적용 후' 그림을 그릴 수 없어요") && (await txt('.pair .mc-why')).includes('plan 없음'), await txt('.pair'));
  check('E8 ⑤ 막힌 후보: 설계 비교 = 검사 못 함', (await p.$eval('.mdetails', (d) => d.textContent)).includes('검사 못 함'));

  // F. ⑥ · ⑧ 막힌 후보
  await next();
  check('F1 ⑥ 결론 배너 = 승인 불가', (await txt('.verdict')).includes('승인 불가'), await txt('.verdict'));
  check('F2 ⑥ 질문 5개 (V 번호는 자세히에만)', (await p.$$('.qrow')).length === 5 && !/\bV[1-8]\b/.test(await p.$$eval('.qh b', (xs) => xs.map((x) => x.textContent).join(' '))));
  await next(); await next();
  await p.waitForSelector('.final-grid');
  const fin = await txt('#mbody');
  check('F3 ⑧ 결론 배너 + 설계 위반 = 검사 못 함', fin.includes('승인 불가') && /고객 설계 위반\s*—\s*검사 못 함/.test(fin), fin.slice(0, 600));
  check('F4 ⑧ 승인 버튼 막힘 + 이유', await p.$eval('[data-dec="APPROVED"]', (b) => b.disabled) && fin.includes('승인 불가:'), fin.slice(-800));
  await shot('f-final-blocked');

  // G. 실제 AWS 까지 확인된 기록 → 승인 → PR 미리보기 (실행 안 함)
  await p.goto(BASE + '#p=webapp-3tier&s=8&rec=20261023-124957-af6f0b', { waitUntil: 'networkidle' });
  await p.reload({ waitUntil: 'networkidle' });
  await p.waitForSelector('.final-grid', { timeout: 20000 });
  check('G1 ⑧ AWS 시험 환경에서 확인됨 — 운영 반영 후 확인 아님 (세 단계 띠)', (await txt('.final-grid')).includes('AWS 시험 환경에서 확인됨 — 운영 반영 후 확인 아님') && (await txt('.stages3')).includes('운영 반영') && (await txt('.stages3')).includes('확인 안 함') && (await txt('.stages3')).includes('통과 (샌드박스)'), [await txt('.final-grid'), await txt('.stages3')]);
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
  await p.goto(BASE, { waitUntil: 'networkidle' });
  await p.reload({ waitUntil: 'networkidle' });
  await p.click('[data-open="webapp-2tier"]');
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
  if (!(await p.$('[data-cand="rule-based"]'))) await p.click('[data-act="team-toggle"]');
  await p.click('[data-cand="rule-based"]');
  await p.waitForSelector('.cmp-head', { timeout: 20000 });
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
  await p.waitForSelector('.cmp-head', { timeout: 300000 });
  await p.waitForTimeout(1500);
  const ai = await p.$eval('.cmpwrap', (x) => x.textContent);
  check('I2 AI 결과: 시도 기록(막힘 → 통과) 표시', ai.includes('이 AI 수정의 시도 기록') && ai.includes('시도 1') && ai.includes('시도 2'), ai.slice(0, 600));
  check('I3 AI 결과: 적용 후 그림 (오른쪽)', (await nodes('tAfter')) >= 7);
  const att = await p.$$eval('.cands [data-aiatt]', (xs) => xs.map((x) => x.textContent.trim()));
  check('I4 AI 시도가 하나씩 후보 버튼 (1차 ✕ · 2차 ✓)', att.length >= 2 && att.some((t) => t.startsWith('1차') && t.includes('✕')) && att.some((t) => t.startsWith('2차') && t.includes('✓')), att);
  await p.click('.cands [data-aiatt$="|1"]');
  await p.waitForFunction(() => (document.querySelector('.cmp-head') || {}).textContent && document.querySelector('.cmp-head').textContent.includes('시도 1'), null, { timeout: 15000 });
  check('I5 1차 시도 버튼 → 그 시도의 결과 (막힘)', (await txt('.cmp-head')).includes('시도 1'), await txt('.cmp-head'));
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
  await p.click('#mhead [data-act="tour"]'); await p.waitForSelector('.tour-box');
  for (let i = 0; i < 6 && !(await p.$('[data-tour-jump]')); i++) { await p.click('[data-tour="1"]'); await p.waitForTimeout(150); }
  const jl = await txt('.tour-jump');
  await p.click('[data-tour-jump]');
  await p.waitForSelector('#prcard.flash', { timeout: 8000 }).catch(() => {});
  check('N10 화면 안내 상자 안 바로 가기 (PR 만들기로) → 안내 닫히고 ⑧ PR 칸 밝게', jl.includes('PR 만들기로 바로 가기') && !(await p.$('.tour')) && !!(await p.$('#prcard.flash')), jl);

  check('Z 화면 오류 없음', errs.length === 0, errs.join(' | '));
  console.log(`\n${pass} PASS / ${fail} FAIL`);
  await b.close();
  process.exit(fail ? 1 : 0);
})();
