// 내 Terraform 폴더 연결 흐름 E2E (2026-11-01 갈아엎기 4차, D-32) — 3계층이 아닌 프로젝트(주문 API: ALB → ECS → PostgreSQL)로 ①~⑧.
// 실제 trivy · tofu(오프라인 plan) · 시험용 대역 claude. AWS 없음 · PR 실행 없음 (확인 창에서 취소).
// 실행 전: sync.py → reset.sh → mk_userproj.sh → start.sh
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const SP = '/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad';
const SHOTS = process.argv[2] || `${SP}/e2e/shots_proj`;
const BASE = 'http://127.0.0.1:8897/';
const UP = `${SP}/userproj/orders-infra`;
let pass = 0, fail = 0;
const check = (name, cond, info = '') => { if (cond) { pass++; console.log('PASS', name); } else { fail++; console.log('FAIL', name, '|', String(info).slice(0, 400)); } };

(async () => {
  require('fs').mkdirSync(SHOTS, { recursive: true });
  const gitBefore = execSync('git status --porcelain && git branch -a && git rev-parse HEAD', { cwd: UP }).toString();
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errs = [];
  p.on('pageerror', (e) => errs.push('pageerror: ' + e.message));
  p.on('console', (m) => { if (m.type() === 'error' && !m.text().includes('status of 403') && !m.text().includes('status of 400')) errs.push('console: ' + m.text()); });   // 400 = 입력 검증 거절(의도) — 어느 URL 인지는 response 쪽에서 거른다
  p.on('response', (r) => { if (r.status() >= 400 && !r.url().includes('/api/decision') && !r.url().includes('/api/design/confirm')) errs.push(`http ${r.status()} ${r.url()}`); });   // 결정 · 확정의 400 = 입력 검증 거절(의도)
  const txt = async (sel) => (await p.$(sel)) ? (await p.innerText(sel)) : '';
  const shot = async (n) => { await p.waitForTimeout(400); await p.screenshot({ path: `${SHOTS}/${n}.png` }); };
  const next = async () => { await p.click('.mh-nav .primary'); await p.waitForTimeout(600); };
  const nodes = async (id) => p.$$eval(`#${id} [data-node]`, (xs) => xs.length).catch(() => 0);

  // J1. 시작: 새 프로젝트 칸 · 예제
  await p.goto(BASE, { waitUntil: 'networkidle' });
  check('J1 시작: 시작하기 카드에 내 폴더 연결 · 누르면 연결 칸', (await txt('.mstart')).includes('내 Terraform 폴더 연결') && !(await p.$('.pnew')) && !(await txt('#mbody')).includes('내 프로젝트'), await txt('#mbody'));
  await p.click('[data-act="np-open"]');
  check('J1b 연결 칸 펼침', (await txt('.pnew')).includes('새 프로젝트 — 내 Terraform 폴더 연결'), await txt('.pnew'));
  // 입력 확인: 상대 경로 · .tf 없는 폴더 → 연결 못 함 + 이유
  await p.fill('#npPath', 'infra/prod');
  await p.click('[data-act="np-check"]');
  await p.waitForSelector('.np-info');
  check('J2 상대 경로 → 연결할 수 없음 (전체 경로로)', (await txt('.np-info')).includes('전체 경로로 넣어 주세요'), await txt('.np-info'));
  await p.fill('#npPath', `${SP}/userproj/empty-folder`);
  await p.click('[data-act="np-check"]');
  await p.waitForFunction(() => (document.querySelector('.np-info') || {}).textContent.includes('.tf 파일이 없음'), null, { timeout: 5000 }).catch(() => {});
  check('J3 .tf 없는 폴더 → 연결할 수 없음', (await txt('.np-info')).includes('.tf 파일이 없음'), await txt('.np-info'));

  // J4. 주문 서비스 폴더 연결 → 점검 → ② 코드에서 그린 그림 (3계층 아님)
  await p.fill('#npName', '주문 서비스');
  await p.fill('#npPath', UP);
  await p.click('[data-act="np-check"]');
  await p.waitForFunction(() => (document.querySelector('.np-info') || {}).textContent.includes('연결할 수 있음'), null, { timeout: 5000 }).catch(() => {});
  check('J4 연결 전 확인: .tf 12개 · git 저장소', /\.tf 12개/.test(await txt('.np-info')) && (await txt('.np-info')).includes('git 저장소'), await txt('.np-info'));
  await shot('j-start');
  await p.click('[data-act="np-create"]');
  await p.waitForSelector('#tInfra [data-node]', { timeout: 180000 });
  await p.waitForTimeout(800);
  check('J5 ② 프로젝트 이름 · 리소스 29 · 위험한 허용 2', (await txt('#mproj')).includes('주문 서비스') && /29\s*리소스/.test(await txt('.mpanel .nums')) && /2\s*위험한 허용/.test(await txt('.mpanel .nums')), await txt('.mpanel .nums'));
  const inf = await p.$eval('#tInfra', (s) => s.textContent);
  check('J6 ② 그림: 로드밸런서 → api(컨테이너 서비스 ECS) → DB · ops 서버 — 웹/앱/Bastion 없음', ['로드밸런서', 'api', '컨테이너 서비스 (ECS)', '데이터베이스 (RDS)', 'ops'].every((k) => inf.includes(k)) && !/Bastion|웹 서버/.test(inf), inf.slice(0, 400));
  check('J7 ② 코드의 라우팅으로 나눈 공개 · 비공개 서브넷 · VPC 밖 IAM 역할 · S3', ['공개 서브넷', '비공개 서브넷', 'VPC 밖 AWS 서비스', 'task_exec', 'IAM 역할', 'S3 버킷'].every((k) => inf.includes(k)), inf.slice(0, 600));
  check('J7b ② 연결한 폴더 · 다시 점검 버튼', (await txt('.rescan')).includes('userproj/orders-infra') && !!(await p.$('.rescan [data-act="scan"]')), await txt('.rescan'));
  await shot('j-infra');

  // J8. ③ 원하는 구조 = 점검 때 만든 자동 기준 v1 (지금 코드 − 위험한 통신) → 목록에서 운영 SSH 를 '이 IP만 허용' (운영팀 사무실) → v2
  await next();
  await p.waitForSelector('#tMap [data-node]', { timeout: 20000 });
  const d3 = await txt('#mbody');
  check('J8 ③ 자동 기준 v1 · 인터넷 → ops 22 는 위험해서 자동으로 막음', d3.includes('v1 은 프로그램이 자동으로 만든 설계도입니다') && d3.includes('위험해서 자동으로 막음 — 인터넷 전체 → 관리 포트 SSH(22)'), d3.slice(0, 900));
  const fixRows = await p.$$eval('li.frow.fix .fr-path', (xs) => xs.map((x) => x.innerText.replace(/\s+/g, ' ')));
  check('J9 ③ 지금 코드와 다른 줄 2개 (인터넷 → ops :22 · VPC 안 모든 서버 → orders :5432 — VPC 대역은 허용 못 함, 이 서버만 허용)', fixRows.length === 2 && fixRows.some((t) => t.includes('ops') && t.includes(':22')) && fixRows.some((t) => t.includes('VPC 안 모든 서버') && t.includes(':5432'))
    && !!(await p.$('li.frow.fix [data-fr="via"]')) && (await p.$eval('li.frow.fix:has([data-fr="via"]) [data-fr="allow"]', (b) => b.disabled)), fixRows);
  const ops = 'li.frow.fix:has([data-fr="ip"])';
  await p.click(`${ops} [data-fr="ip"]`);
  await p.fill(`${ops} [data-i="cidr"]`, '203.0.113.0/24');
  await p.fill(`${ops} [data-i="label"]`, '운영팀 사무실');
  await p.click(`${ops} [data-fr="ip-ok"]`);
  await p.waitForFunction(() => document.querySelector('.ssave') && !document.querySelector('.ssave [data-act="s-save"]').disabled, null, { timeout: 15000 });
  check('J10 ③ 이 IP만 허용: 바꾼 것 1개 · 운영팀 사무실이 설계도 그림에', (await txt('.ssave')).includes('바꾼 것 1개') && (await p.$eval('#tMap', (s) => s.textContent)).includes('운영팀 사무실'), await txt('.ssave'));
  await p.fill('#sNote', 'E2E: 운영 서버 SSH 는 운영팀 사무실에서만');
  await p.click('.ssave [data-act="s-save"]');
  await p.waitForSelector('.mtoast');
  check('J11 저장 → v2', (await txt('.mtoast')).includes('설계도 v2 저장'), await txt('.mtoast'));
  await p.waitForTimeout(900);
  const fix2 = await p.$$eval('li.frow.fix .fr-path', (xs) => xs.map((x) => x.innerText.replace(/\s+/g, ' ')));
  check('J12 ③ 지금 코드 vs v2: 다른 곳 2 (VPC → orders :5432 · 인터넷 → ops :22)', fix2.length === 2 && fix2.some((t) => t.includes(':5432')) && fix2.some((t) => t.includes(':22')) && (await txt('.sdiff')).includes('2개'), fix2);
  const hv = await txt('.mh-ver');
  check('L1 ③ 저장만 한 v2 = 초안 (머리말 · 확정 카드 · 확정 버튼)', hv.includes('초안') && (await txt('.mcard.confirm')).includes('아직 확정 전') && !!(await p.$('[data-act="s-confirm"]')), [hv, await txt('.mcard.confirm')]);
  await shot('j-design');

  // J13. ④ 문제 목록 — Trivy 밖 문제(DB 를 VPC 전체에 엶) 를 골라 고치기
  await next();
  const top = await txt('.issues-top');
  check('J13 ④ Trivy 는 못 보고 우리만 찾음 ≥ 1', /[1-9]\s*Trivy 는 못 보고/.test(top), top);
  // IAM(s3:*) 은 연결한 프로젝트에서 탐지만 — 필요한 권한(요구사항) 기준이 없어 고친 뒤 판정할 수 없음
  for (const it of await p.$$('.iitem')) { if ((await it.innerText()).includes('IAM 정책이 S3 권한을 제한 없이')) { await it.click(); break; } }
  await p.waitForTimeout(300);
  const iamDet = await txt('.lay4 .col .mcard');
  check('J13b ④ IAM 문제: 탐지만 + 이유 (고치기 버튼 없음)', iamDet.includes('연결한 프로젝트의 IAM 수정은 아직 검사 기준이 없음') && !(await p.$('[data-fix]')), iamDet.slice(-400));
  const items = await p.$$('.iitem');
  let picked = '';
  for (const it of items) { const t = await it.innerText(); if (t.includes('db :5432') && t.includes('고객 설계에 없는 통신')) { picked = t; await it.click(); break; } }
  await p.waitForTimeout(300);
  check('J14 ④ DB 설계 위반 = Trivy 는 못 봄', picked.includes('Trivy 는 못 봄'), picked);
  const det = await txt('.lay4 .col .mcard');
  check('J15 ④ 상세: 같이 고칠 Trivy 지적 안내 + 고치기 버튼', det.includes('을 고치는 수정으로 같이 검사') && !!(await p.$('[data-fix]')), det.slice(-500));
  await shot('j-issues');
  await p.click('[data-fix]');
  await p.waitForSelector('.target', { timeout: 15000 });
  const tg = await txt('.target');
  check('J16 ⑤ 고칠 문제 = 고른 DB 문제 · 함께 고칠 Trivy 지적(ops SSH) 설명', tg.includes('db :5432') && tg.includes('보안 그룹이 SSH · RDP 를 모든 IP 에서 받음') && tg.includes('aws_security_group.ops') && tg.includes('원하는 구조(고객 설계도) v2'), tg);
  check('J17 ⑤ 연결한 프로젝트: 팀 후보 없음 · AI 칸이 펼쳐짐 · 왼쪽 설계도 v2', !(await p.$('.cands [data-cand]')) && !!(await p.$('[data-act="ai-run"]')) && (await nodes('tDesign')) >= 4, await txt('.cands'));

  // J18. AI 수정 (대역: 시도 1 = ops 만 고침 → 설계 위반으로 막힘 → 시도 2 = 관문 통과) — 아직 설계도 v2 는 초안 → 실행 결과는 '검증 불가(확정 전 기준)'
  check('L0 ⑤ AI 칸: 설계도가 초안이라는 경고 + ③ 확정 버튼', (await txt('.aidraft')).includes('초안') && !!(await p.$('.aidraft [data-go="3"]')), await txt('.aidraft'));
  await p.click('[data-ctx="design"]');
  await p.click('[data-act="ai-run"]');
  await p.waitForSelector('.mcard.run', { timeout: 10000 });
  await p.waitForSelector('.cmp-head', { timeout: 300000 });
  await p.waitForTimeout(1500);
  const ai = await p.$eval('.cmpwrap', (x) => x.textContent);
  check('J18 AI 결과: 시도 1 막힘 → 시도 2 관문 통과 (시도마다 버튼 2개 · 시도 기록이 ⑤ 에)', ai.includes('시도 1') && ai.includes('시도 2') && (await p.$$('.cands [data-aiatt]')).length === 2, ai.slice(0, 600));
  const ar1 = await p.$eval('.airesult', (x) => x.textContent).catch(() => '');
  check('J18b AI 실행 결과 한 줄 = 검증 불가(설계도 초안) + 다음 할 일 = ③ 확정 뒤 다시 (D-36 · D-38)', ar1.includes('검증 불가') && ar1.includes('초안') && ar1.includes('다음:') && ar1.includes('③'), ar1);
  check('J18c ⑤ 결과 머리: 기준 = 확정 전 기준 (초안 설계도)', (await txt('.basis')).includes('확정 전 기준'), await txt('.basis'));
  // L2. 초안 기준 검사는 '고객 요구 충족' 이 아니다 (D-38): ⑥ 결론 · 질문 5 · ⑧ 승인 불가
  await p.click('[data-go="6"]'); await p.waitForSelector('.verdict', { timeout: 20000 });
  const v6d = await txt('.verdict');
  const q5 = await p.$$eval('.qrow', (xs) => xs.map((x) => x.textContent.replace(/\s+/g, ' ')).find((t) => t.includes('고객이 원하는 통신 구조')) || '');
  check('L2 ⑥ 초안 설계도 기준: 결론 = 승인 불가 · 설계도 확정 필요, 질문 5 = 초안 기준', v6d.includes('설계도가 아직 초안') && v6d.includes('설계도 확정 필요') && q5.includes('초안 기준') && q5.includes('확정한 뒤 다시 검사'), [v6d.slice(0, 200), q5.slice(0, 200)]);
  await p.click('[data-go="8"]'); await p.waitForSelector('.final-grid', { timeout: 20000 });
  check('L2b ⑧ 초안 기준 기록은 승인 버튼 막힘 + 이유', (await p.$eval('[data-dec="APPROVED"]', (b) => b.disabled)) && (await txt('.lay8')).includes('초안'), (await txt('.lay8')).slice(0, 300));
  await shot('l-draft-blocked');
  // L3. ③ 에서 담당자 확정 (이름 · 메모) → 머리말 '확정'
  await p.click('[data-go="3"]'); await p.waitForSelector('[data-act="s-confirm"]', { timeout: 20000 });
  await p.click('[data-act="s-confirm"]');
  await p.waitForSelector('#cfBy');
  await p.click('#cfGo'); await p.waitForTimeout(300);
  check('L3 확정: 이름 없이 누르면 거절', !!(await p.$('#cfBy')) && (await txt('.mtoast')).includes('이름'), await txt('.mtoast'));
  await p.fill('#cfBy', '김보성'); await p.fill('#cfNote', 'E2E: 고객 네트워크 담당자 확인');
  await p.click('#cfGo');
  await p.waitForFunction(() => (document.querySelector('.mh-ver') || {}).textContent.includes('확정'), null, { timeout: 15000 });
  check('L3b 확정 뒤: 머리말 · 확정 카드에 이름 · 버전 칩 v2 확정', (await txt('.mh-ver')).includes('확정') && (await txt('.mcard.confirm')).includes('김보성') && (await txt('.vstrip')).includes('v2 · 지금 · 확정'), [await txt('.mh-ver'), await txt('.vstrip')]);
  await shot('l-confirmed');
  // 확정한 설계도로 다시 AI 수정 (대역은 마지막 답 = 설계대로 고친 파일을 돌려준다)
  await p.click('[data-go="5"]'); await p.waitForSelector('[data-src="ai"]', { timeout: 20000 });
  if (!(await p.$('[data-act="ai-run"]'))) await p.click('[data-src="ai"]');
  await p.click('[data-ctx="design"]');
  await p.click('[data-act="ai-run"]');
  await p.waitForSelector('.mcard.run', { timeout: 10000 });
  await p.waitForSelector('.cmp-head', { timeout: 300000 });
  await p.waitForTimeout(1500);
  check('L4 확정 뒤 AI 수정: 실행 2개 (버튼 3개) · 최신 실행 1차 통과', (await p.$$('.cands [data-aiatt]')).length === 3 && (await txt('.cmp-head')).includes('시도 1'), await txt('.cands'));
  check('J19 ⑤ 나란히: 왼쪽 설계도 v2 · 오른쪽 AI 시도 2 적용 후 = 설계도와 같음', (await nodes('tAfter')) >= 4 && (await txt('.pair')).includes('설계도 v2') && (await txt('.pdiff')).includes('설계도와 같음'), [await nodes('tAfter'), await txt('.pdiff')]);
  const grid = await txt('.cmp-grid');
  check('J20 ⑤ 이 후보가 바꾼 통신 － · 설계도 비교 일치', grid.includes('－') && (await p.$eval('.mdetails', (d) => d.textContent)).includes('일치'), grid);
  await (await p.$$('.cands [data-aiatt$="|1"]')).pop().click();            // 실행은 최신 순 → 마지막 = 1차 실행(초안 기준)의 시도 1 = 막힘
  await p.waitForFunction(() => (document.querySelector('.pdiff') || {}).textContent && document.querySelector('.pdiff').textContent.includes('설계도와 다른 곳'), null, { timeout: 15000 }).catch(() => {});
  check('J20b ⑤ 막힌 시도 버튼 → 오른쪽이 그 시도 적용 후로 · 설계도와 다른 곳 빨강', (await txt('.pdiff')).includes('설계도와 다른 곳') && (await p.$$('#tAfter .a-x')).length >= 1, await txt('.pdiff'));
  check('J20c ⑤ 초안 기준 기록(1차 실행)은 "확정 전 기준" 표시 · 확정 기준 기록은 담당자 이름', (await txt('.basis')).includes('확정 전 기준'), await txt('.basis'));
  await (await p.$$('.cands [data-aiatt$="|1"]'))[0].click();                 // [0] = 2차 실행(확정 기준)의 시도 1 = 통과
  await p.waitForFunction(() => (document.querySelector('.pdiff') || {}).textContent && document.querySelector('.pdiff').textContent.includes('설계도와 같음'), null, { timeout: 15000 });
  check('J20d ⑤ 확정 기준 기록: 기준 = 설계도 v2 · 김보성 확정', (await txt('.basis')).includes('김보성') && (await txt('.basis')).includes('확정') && !(await txt('.basis')).includes('확정 전'), await txt('.basis'));
  await shot('j-compare');

  // J21. ⑥ 결론: 배포 전 통과 · 실제 AWS 미검증 (다음: 실제 AWS 검사 라고 하지 않음)
  await next();
  const v6 = await txt('.verdict');
  check('J21 ⑥ 결론 = 승인 판단 가능 · 실제 AWS 미검증', v6.includes('승인 판단 가능 · 실제 AWS 미검증') && !v6.includes('다음: 실제 AWS 검사'), v6);
  check('J22 ⑥ 확인하지 않은 것: 시험 환경 없음', (await txt('#mbody')).includes('이 프로젝트는 AWS 시험 환경이 없어 확인하지 않음'), '');
  // ⑦ 미검증
  await next();
  check('J23 ⑦ 미검증 — 시험 환경 없음', (await txt('#mbody')).includes('미검증 — 이 프로젝트는 AWS 시험 환경이 없습니다') && (await txt('.stages3')).includes('시험 환경 없음 → 미검증'), (await txt('#mbody')).slice(0, 300));
  // ⑧ 확인 표시 없이 승인 → 거절, 확인 표시 → 승인 → PR 준비(이 폴더의 git 저장소)
  await next();
  await p.waitForSelector('.final-grid');
  check('J24 ⑧ 실제 AWS 칸 = 시험 환경 없음', (await txt('.final-grid')).includes('미검증 — 이 프로젝트에는 AWS 시험 환경이 없음'), await txt('.final-grid'));
  check('J25 ⑧ 승인 버튼 열림 (확인 표시 필요 안내)', !(await p.$eval('[data-dec="APPROVED"]', (x) => x.disabled)) && (await txt('[data-dec="APPROVED"]')).includes('실제 AWS 미검증 확인 후 승인'), await txt('.decs'));
  await p.click('[data-dec="APPROVED"]');
  await p.waitForSelector('#decAck');
  await p.fill('#decReason', 'E2E: 설계 일치 · 실제 AWS 미검증 확인');
  await p.fill('#decBy', 'e2e');
  await p.click('[data-act="decide"]');
  await p.waitForSelector('.mtoast');
  check('J26 확인 표시 없이 승인 → 거절', (await txt('.mtoast')).includes('실제 AWS 미검증'), await txt('.mtoast'));
  await p.waitForTimeout(3500);   // 알림이 사라질 때까지
  await p.check('#decAck');
  await p.click('[data-act="decide"]');
  await p.waitForFunction(() => [...document.querySelectorAll('.mtoast')].some((x) => x.textContent.includes('결정을 기록함')), null, { timeout: 10000 }).catch(() => {});
  check('J27 확인 표시 → 승인 기록', (await p.$$eval('.mtoast', (xs) => xs.map((x) => x.textContent).join(' '))).includes('결정을 기록함'));
  await p.waitForSelector('[data-act="pr-check"]', { timeout: 10000 });
  await p.click('[data-act="pr-check"]');
  await p.waitForFunction(() => document.querySelectorAll('.prchk li').length >= 6, null, { timeout: 15000 });
  const chk = await txt('.prchk');
  check('J28 PR 준비 확인: 이 폴더의 git 저장소 · 원본 같음 · 실제 AWS 미검증 표시', !(await p.$('.prchk li.bad')) && chk.includes('userproj/orders-infra') && chk.includes('example/orders-infra') && chk.includes('미검증 — 사람이 확인하고 승인함'), chk);
  await p.click('[data-act="pr-preview"]');
  await p.waitForFunction(() => /git checkout -b/.test((document.querySelector('.lay8 .mcard:last-child') || {}).textContent || ''), null, { timeout: 15000 }).catch(() => {});
  const prv = await txt('.lay8 .mcard:last-child');
  check('J29 PR 미리보기: 이 폴더 저장소에서 새 브랜치 (세트 id · 후보 id 없음)', /git checkout -b iacpatch\/orders-infra-652acb-\d{8}-\d{6}-[0-9a-f]{6} origin\/main/.test(prv) && !/652acb\.t[0-9a-f]{8}/.test(prv) && prv.includes('git push'), prv.slice(0, 1200));
  await p.click('[data-act="pr-create"]');
  await p.waitForSelector('#prConfirm');
  check('J30 PR 만들기: 확인 문구 입력창 (여기서 취소 — 실행 안 함)', true);
  await shot('j-final');
  await p.click('.mmodal [data-close]');

  // J31. 시작 화면: 내 프로젝트 카드 → 연결 끊기 (폴더는 그대로)
  await p.goto(BASE, { waitUntil: 'networkidle' });
  await p.reload({ waitUntil: 'networkidle' });
  check('J31 시작: 내 프로젝트 1 (주문 서비스)', /내 프로젝트\s*1/.test(await txt('#mbody')) && (await txt('.pgrid')).includes('주문 서비스'), (await txt('#mbody')).slice(0, 600));
  await p.screenshot({ path: `${SHOTS}/j-start-mine.png`, fullPage: true });
  await p.click('[data-unlink]');
  await p.waitForSelector('#ulConfirm');
  await p.fill('#ulConfirm', '연결 끊기');
  await p.click('#ulGo');
  await p.waitForTimeout(800);
  check('J32 연결 끊기 → 카드 없어짐', !(await txt('#mbody')).includes('내 프로젝트'), (await txt('#mbody')).slice(0, 300));
  const gitAfter = execSync('git status --porcelain && git branch -a && git rev-parse HEAD', { cwd: UP }).toString();
  check('J33 연결했던 폴더 · git 저장소는 그대로 (파일 · 브랜치 · 커밋)', gitAfter === gitBefore, gitAfter);

  // K. 지원 범위 밖(AWS 를 조회하는 data 소스) → '분석 못 함' + 이유
  if (!(await p.$('#npName'))) await p.click('[data-act="np-open"]');
  await p.fill('#npName', 'data 소스 있는 폴더');
  await p.fill('#npPath', `${SP}/userproj/with-data`);
  await p.click('[data-act="np-create"]');
  await p.waitForFunction(() => (document.querySelector('#mbody') || {}).textContent.includes('현재 인프라를 아직 그리지 못했어요'), null, { timeout: 180000 }).catch(() => {});
  const k = await txt('#mbody');
  check('K1 data 소스 폴더: ② 그리지 못함 + 이유(지원 범위 밖) — plan 을 돌리지 않고 바로', k.includes('현재 인프라를 아직 그리지 못했어요') && k.includes('data.aws_vpc.default') && k.includes('지원 범위 밖'), k.slice(0, 700));
  await shot('k-unsupported');
  await p.click('[data-go="4"]');
  await p.waitForSelector('.iitem', { timeout: 15000 });
  await p.click('.iitem');
  await p.waitForTimeout(300);
  const kd = await txt('.lay4 .col .mcard:last-child');
  check('K2 ④ Trivy 탐지는 보임 · 고치기 없음 (원본 plan 없음 → 수정 검사 불가)', kd.includes('원본 plan 이 없어 수정 검사를 할 수 없음') && !(await p.$('[data-fix]')), kd.slice(-400));

  check('Z 화면 오류 없음', errs.length === 0, errs.join(' | '));
  console.log(`\n${pass} PASS / ${fail} FAIL`);
  await b.close();
  process.exit(fail ? 1 : 0);
})();
