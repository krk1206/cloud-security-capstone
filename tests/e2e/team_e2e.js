// D-49 팀 3계층 예제 (깃허브 main 의 infrastructure/three-tier 사본 + 시나리오 1): ① 첫 카드 → ② 점검(실제 tofu 오프라인 plan · trivy) → ③ 팀 설계 문서 + 초안 확정
// → ④ SSH 공개 (Trivy · 자체 검사 · 설계 위반이 한 줄) → ⑤ 수정안 1~4 누를 때마다 그림이 바뀜 · 설계도대로 자동 수정(규칙 기반) → ⑥ good → ⑧ 승인 → PR 준비 확인. AWS · AI 없음.
const { chromium } = require('playwright');
const SP = '/tmp/claude-0/-home-claude/8555f975-09e8-5e0e-8dca-92479ac45f1c/scratchpad';
const BASE = 'http://127.0.0.1:8897/';
const SHOTS = process.argv[2] || `${SP}/e2e/shots_team`;
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

  // ① 시작
  await p.goto(BASE, { waitUntil: 'networkidle' });
  // 16차 (D-52): 팀 3계층 요청은 ① 고객 요청함의 줄(최근 것 위) · 3계층 실측은 아래 '다른 예제' 카드
  const names = await p.$$eval('.ibrow', (xs) => xs.map((x) => x.querySelector('.ib-seq').textContent));
  const others = await p.$$eval('.pcard .pc-top b', (xs) => xs.map((x) => x.textContent));
  check('T1 ① 고객 요청함 3줄 (요청 3 · 2 · 1) + 다른 예제 = 3계층(AWS 시험 환경 실측) · 게시판 없음 (15차 D-51 · 16차 D-52)', names.join('|') === '요청 3|요청 2|요청 1' && others.join('|') === '3계층 웹 서비스 — AWS 시험 환경 실측' && !(await p.$('[data-open="board-saas"]')), [names, others]);
  const r1 = '.ibrow[data-rid="three-tier-team"]';
  check('T2 ① 요청 1 줄 표시: 예제 · 팀 설계 문서 → 설계도', (await txt(r1)).includes('예제 · 팀 설계 문서 → 설계도'), await txt(r1));
  check('T2c ① 요청 1 줄에 숫자 칸 없음 (17차 — 리소스 수는 ② 를 열면 왼쪽 메뉴 ② 밑에)', !/리소스\s*\d/.test(await txt(r1)) && !(await p.$(`${r1} .ib-facts`)), await txt(r1));
  check('T2b ① 요청 1 줄: 요청 번호 · 제목 · 보낸 사람 · 받은 시각 (가상 고객 요청함)', (await txt(r1)).includes('요청 1') && (await txt(r1)).includes('Bastion SSH 전체 공개 — 점검 지적 조치 요청') && (await txt(r1)).includes('운영팀 보안 담당')
    && (await txt(r1)).includes('2026-11-05 09:10') && (await txt('.ib-h')).includes('(가상) 3계층 웹 서비스 운영팀'), await txt(r1));
  await p.click('[data-open="three-tier-team"]');
  await p.waitForTimeout(1200);
  if ((await txt('#mbody')).includes('점검 실행')) await p.click('[data-act="scan"]');
  await p.waitForSelector('#tInfra [data-node]', { timeout: 400000 });
  await p.waitForTimeout(800);

  // ② 흐름 그림 — 상자 5개(인터넷 · ALB · 웹 ASG · Bastion · MySQL), 틀 없음, 빨간 선 = 인터넷 → Bastion 22
  const ids = await p.$$eval('#tInfra [data-node]', (xs) => xs.map((x) => x.dataset.node).sort());
  check('T3 ② 그림 상자 = 인터넷 · ALB · 웹 ASG · Bastion · MySQL 만 (VPC · 서브넷 · IGW · NAT · IAM · S3 없음)', JSON.stringify(ids) === JSON.stringify(['n:aws_autoscaling_group.web', 'n:aws_db_instance.mysql', 'n:aws_instance.bastion', 'n:aws_lb.web', 'x:internet'])
    && (await p.$$('#tInfra .a-vpc, #tInfra .a-band')).length === 0 && !(await p.$('[data-mapfull]')), ids);
  check('T4 ② 리소스 54 (data 소스 1개 빼고, 14차) · 위험 1 (인터넷 → Bastion :22 빨강) — 숫자는 왼쪽 메뉴 ② 밑 (17차: 그림 아래 숫자 칸 뺌)', (await txt('#msteps button[data-go="2"]')).includes('리소스 54개') && /위험 1/.test(await txt('#msteps button[data-go="2"]')) && !(await p.$('.mpanel .nums')) && !!(await p.$('#tInfra .a-link[data-link="l:x:internet>n:aws_instance.bastion>main"] .al.risk')), await txt('.mpanel .nums'));
  // 13차 버그: '그림의 상자' 숫자가 그림과 달랐다 → 17차 (D-53): 그 숫자 칸을 뺐다 (그림이 곧 상자 수). 상자 이름은 잘리지 않아야 한다
  check('T4b ② 그림 상자 5개 · 상자 이름이 \'…\' 로 잘리지 않음', ids.length === 5 && (await p.$$eval('#tInfra .fname, #tInfra .fsub', (xs) => xs.every((x) => !x.textContent.endsWith('…')))), ids.length);
  const lab = await p.$$eval('#tInfra .fname', (xs) => xs.map((x) => x.textContent));
  check('T5 ② 이름이 겹치는 상자 구분: web (ALB) · web (ASG)', lab.includes('web (ALB)') && lab.includes('web (ASG)'), lab);
  // 14차 (D-50): ② 맨 위 = 가상 고객 요청 (누가 · 무엇을 · 조건 5개) + [요청서 보기] 원문
  const rb = await txt('.reqbar');
  check('T5b ② 맨 위 고객 요청 칸: 가상 · 제목 · 보낸 곳 · 조건 5개 · 할 일에 고객 요청', rb.includes('고객 요청 1 · 가상') && rb.includes('Bastion SSH 전체 공개') && rb.includes('(가상) 3계층 웹 서비스 운영팀')
    && (await p.$$('.reqbar .rq-c')).length === 5 && (await txt('.mh-todo')).includes('고객 요청'), rb.slice(0, 300));
  check('T5c ② 고객 요청 칸이 그림보다 위', await p.evaluate(() => document.querySelector('.reqbar').getBoundingClientRect().bottom <= document.querySelector('#tInfra').getBoundingClientRect().top));
  await p.click('.reqbar [data-act="request"]'); await p.waitForSelector('.mmodal .reqtext');
  const rt = await txt('.mmodal');
  check('T5d [요청서 보기] = 원문 그대로 (가상 표시 · 조건 1 · 5 · 받는 사람)', rt.includes('이 예제를 위해 만든 가상의 요청서') && rt.includes('Bastion 서버 SSH(22)는 운영자 IP(203.0.113.10)에서만 접속되게 해 주세요.')
    && rt.includes('저희 담당자가 승인한 뒤에 반영해 주세요.') && rt.includes('클라우드 보안 담당'), rt.slice(0, 300));
  await shot('t-s2-req');
  await p.click('.mmodal [data-close]'); await p.waitForTimeout(200);
  await shot('t-s2');

  // ③ 팀 설계 문서 + 초안 확정
  await p.click('#msteps button[data-go="3"]'); await p.waitForSelector('#tMap [data-node]', { timeout: 30000 }); await p.waitForTimeout(600);
  const g3 = await txt('.mcard.guide');
  check('T6 ③ 다음 할 일: 팀 설계 문서에서 옮긴 설계도 v1 초안 — 원문과 맞는지 확인하고 확정', g3.includes('팀 설계 문서에서 옮긴 설계도 v1 초안') && !!(await p.$('.mcard.guide [data-act="s-confirm"]')), g3.slice(0, 300));
  const pr = await txt('.mcard.proposal');
  check('T7 ③ 팀 설계 문서 칸: 출처(three-tier-design.md) · 문서 문장 그대로 · 운영자 IP/32', pr.includes('팀 설계 문서') && pr.includes('docs/architecture/three-tier-design.md') && pr.includes('운영자 IP/32 →22→ Bastion SG') && pr.includes('203.0.113.10/32'), pr.slice(0, 500));
  const rows = await p.$$eval('li.frow .fr-path', (xs) => xs.map((x) => x.innerText.replace(/\s+/g, ' ')));
  check('T8 ③ 통신 목록: web (ALB) → web (ASG) :80 · 운영자 → bastion :22 · 지금 코드와 다른 곳 1개', rows.includes('web (ALB) → web (ASG) :80') && rows.includes('운영자 → bastion :22') && (await txt('.sdiff')).includes('1개'), rows);
  check('T9 ③ 확정 칸: 팀 설계 문서의 허용 통신을 옮긴 초안', (await txt('.mcard.confirm')).includes('팀 설계 문서의 허용 통신을 옮긴 초안'), await txt('.mcard.confirm'));
  await shot('t-s3');
  await p.click('.mcard.guide [data-act="s-confirm"]');
  await p.fill('#cfBy', '김담당'); await p.click('#cfGo');
  await p.waitForFunction(() => (document.querySelector('.mtoast') || {}).textContent?.includes('확정'), null, { timeout: 15000 });
  await p.waitForTimeout(900);
  check('T10 ③ 확정 → 확정된 설계도 v1 · 김담당 확정 (17차: \'다음 할 일\' 칸은 [다음] 하나뿐이라 확정 뒤에는 없음)', (await txt('.mcard.confirm')).includes('확정된 설계도 v1') && (await txt('.mcard.confirm')).includes('김담당') && !(await p.$('.mcard.guide')), await txt('.mcard.confirm'));

  // ④ 같은 문제는 한 줄 (Trivy 는 규칙 리소스 · 자체 검사 · 설계 비교는 보안 그룹 이름으로 찾음 — D-49)
  await p.click('#msteps button[data-go="4"]'); await p.waitForTimeout(900);
  const iss = await p.evaluate(async () => (await (await fetch('/api/p/issues?id=three-tier-team')).json()));
  const ssh = iss.issues.filter((x) => /bastion/.test(x.resource) && x.group !== 'undecidable');
  check('T11 ④ Bastion SSH 공개 = 한 줄 (Trivy + 자체 검사 + 설계 위반) · "Trivy 는 못 봄" 0', ssh.length === 1 && ['trivy', 'sg', 'design'].every((k) => ssh[0].sources.includes(k)) && iss.only_ours === 0, JSON.stringify(ssh.map((x) => [x.resource, x.sources])));
  check('T12 ④ 문제 6개 (원본 README 의 MEDIUM 2 · LOW 3 + 시나리오 1)', iss.issues.length === 6, iss.issues.length);
  for (const it of await p.$$('.iitem')) { if ((await it.innerText()).includes('SSH · RDP 를 모든 IP')) { await it.click(); break; } }
  await p.waitForTimeout(500);
  check('T13 ④ 그림 위치: 아래 그림에서 강조됨 (선 포함) · 그림에서 Bastion 이 강조', (await txt('.col.sticky')).includes('아래 그림에서 강조됨 (선 포함)') && !!(await p.$('#tIssue .anode.hl[data-node="n:aws_instance.bastion"]')), (await txt('.col.sticky')).slice(0, 400));
  await shot('t-s4');
  await p.click('[data-fix]'); await p.waitForTimeout(900);
  check('T14 ⑤ 고칠 문제 = bastion_ssh_in 규칙 · Trivy AVD-AWS-0107', (await txt('.target')).includes('aws_vpc_security_group_ingress_rule.bastion_ssh_in') && (await txt('.target')).includes('AVD-AWS-0107'), await txt('.target'));

  // ⑤ 미리 분석 → 수정안 1~4 마다 그림
  await p.waitForFunction(() => !document.querySelector('.pfx.run'), null, { timeout: 600000 });
  await p.waitForTimeout(800);
  const bigs = await p.$$eval('.tbig .cbig', (xs) => xs.map((x) => x.innerText.replace(/\s+/g, ' ')));
  check('T15 ⑤ 수정안 4개 · 모두 분석됨 · 통과 1 (3번) · 막힘 3', bigs.length === 4 && bigs.every((t) => !t.includes('분석 전')) && bigs[2].includes('통과') && bigs.filter((t) => t.includes('막힘')).length === 3, bigs);
  check('T16 ⑤ 고르기 전: 그림 = 고객 설계도 v1', (await txt('.mc-head b')).includes('고객 설계도 v1') && (await txt('.picnote')).includes('위에서 수정안 번호를 누르세요'), await txt('.mc-head'));
  const want = [
    ['T17 ⑤ 수정안 1 (쪼개기): 0.0.0.0/1 · 128.0.0.0/1 → bastion :22 설계도에 없는 통신 ✕ 2', (d, x) => /0\.0\.0\.0\/1 → bastion :22/.test(d) && /128\.0\.0\.0\/1 → bastion :22/.test(d) && x === 2],
    ['T18 ⑤ 수정안 2 (DB 공개): 사용자(인터넷) → mysql :3306 설계도에 없는 통신 ✕', (d, x) => /사용자\(인터넷\) → mysql :3306/.test(d) && x >= 1],
    ['T19 ⑤ 수정안 3 (운영자 IP 로): 설계도와 같음 · 빨강 없음', (d, x) => d.includes('설계도와 같음') && x === 0],
    ['T20 ⑤ 수정안 4 (다른 대역): 198.51.100.0/24 → bastion :22 설계도에 없는 통신 + 운영자 → bastion :22 설계도에 있는데 막힘', (d, x) => /198\.51\.100\.0\/24 → bastion :22/.test(d) && /운영자 → bastion :22 설계도에 있는데 막힘/.test(d) && x >= 1],
  ];
  const seen = [];
  // 14차 (D-50): 고른 수정안마다 고객 요청 조건 5칸 — 1 SSH 운영자 IP 만 · 2 웹 80 · 3 DB 웹 · Bastion 만 · 4 다른 곳 그대로 · 5 승인 뒤 반영(아직)
  const reqWant = [['bad', 'good', 'good', 'good', 'wait'], ['good', 'good', 'bad', 'good', 'wait'], ['good', 'good', 'good', 'good', 'wait'], ['bad', 'good', 'good', 'good', 'wait']];
  const reqSeen = [];
  for (let i = 0; i < 4; i++) {
    await p.click(`.cbig >> nth=${i}`);
    await p.waitForFunction((k) => (document.querySelector('.mc-head b') || {}).textContent?.includes(`수정안 ${k} 적용 후`), i + 1, { timeout: 60000 }).catch(() => {});
    await p.waitForTimeout(700);
    const d = (await txt('.pdiff')).replace(/\s+/g, ' ');
    const x = (await p.$$('#tPic .a-x')).length;
    seen.push(await p.$eval('#tPic', (s) => s.innerHTML.length + ':' + s.querySelectorAll('.a-link').length));
    check(want[i][0], (await txt('.mc-head b')).includes(`수정안 ${i + 1} 적용 후`) && want[i][1](d, x), `${d} | x=${x}`);
    await p.waitForSelector('.reqrow .rqchip', { timeout: 20000 }).catch(() => {});
    reqSeen.push(await p.$$eval('.reqrow .rqchip', (xs) => xs.map((x) => ['good', 'bad', 'unknown', 'wait', 'dim'].find((k) => x.classList.contains(k)))));
    if (i === 0) {
      const t1 = await p.$eval('.reqrow .rqchip', (x) => x.title);
      check('T17b ⑤ 수정안 1: 조건 1 어김 — 근거에 \'요청에 없는 통신\' 과 \'Trivy 지적이 없어짐\' 이 함께 (Trivy 통과 ≠ 요청 충족)', t1.includes('요청에 없는 통신') && t1.includes('AVD-AWS-0107 지적이 없어짐'), t1);
    }
    await shot(`t-s5-${i + 1}`);
  }
  check('T21b ⑤ 수정안마다 고객 요청 조건: 1번 ✕(쪼개기) · 3번 ✕(DB 공개) · 모두 ✓(운영자 IP) · 1번 ✕(다른 대역), 5번 = 아직(승인 전)', JSON.stringify(reqSeen) === JSON.stringify(reqWant), JSON.stringify(reqSeen));
  check('T21 ⑤ 네 번 누른 그림이 모두 다름', new Set(seen).size === 4, seen);
  await p.click('[data-pv="design"]'); await p.waitForTimeout(400);
  check('T22 ⑤ [고객 설계도 v1] 단추 → 같은 자리에 설계도 (빨강 없음)', (await txt('.mc-head b')).includes('고객 설계도 v1') && (await p.$$('#tPic .a-x')).length === 0, await txt('.mc-head'));
  await p.click('[data-pv="after"]'); await p.waitForTimeout(300);

  // 설계도대로 자동 수정 (규칙 기반) → 통과 → ⑥ → ⑧
  await p.click('.cg.rb [data-act="run-rb"]');
  await p.waitForSelector('.mcard.run', { timeout: 10000 });
  await waitRun(); await p.waitForTimeout(800);
  check('T23 ⑤ 규칙 기반 자동 수정 — 배포 전 검사 통과 · 설계도와 같음 (결과 한 줄)', (await txt('.cmp-line')).includes('규칙 기반') && (await txt('.cmp-line')).includes('배포 전 검사를 모두 통과') && (await txt('.pdiff')).includes('설계도와 같음'), (await txt('.cmp-line')).slice(0, 300));
  await p.click('#msteps button[data-go="6"]'); await p.waitForSelector('.verdict', { timeout: 20000 });
  check('T24 ⑥ 결론 good · 아래 그림 없음 (17차: ⑤ 와 같은 그림이라 뺌)', (await p.$eval('.verdict', (x) => x.className)).includes('good') && !(await p.$('#tVerdict')), await txt('.verdict'));
  const rc6 = await p.$eval('.reqcheck', (x) => x.textContent.replace(/\s+/g, ' '));      // 지킨 조건의 근거 · 확인 방법은 접힌 칸 (17차)
  check('T24b ⑥ 고객 요청을 지켰나요? — 지킴 4 · 아직 1 · 조건마다 확인 방법', rc6.includes('고객 요청 조건 5개 — 지킴 4 · 아직 1') && (await p.$$('.reqcheck .rq-items > li.good')).length === 4
    && rc6.includes('확인 방법: V1 Trivy 다시 검사 · V6 설계도 비교') && rc6.includes('⑧ 에서 담당자가 승인하기 전'), rc6.slice(0, 500));
  await shot('t-s6');
  await p.click('#msteps button[data-go="8"]'); await p.waitForSelector('.final-grid', { timeout: 20000 }); await p.waitForTimeout(600);
  check('T25 ⑧ 승인 버튼 열림 (실제 AWS 미검증 확인 후 승인 — 이 예제는 시험 환경 없음)', !(await p.$eval('[data-dec="APPROVED"]', (x) => x.disabled)) && (await txt('[data-dec="APPROVED"]')).includes('미검증 확인 후 승인'), await txt('.decs'));
  await p.click('[data-dec="APPROVED"]');
  await p.waitForSelector('#decAck');
  await p.fill('#decReason', 'E2E: 팀 설계 문서 1.5절대로 — Bastion SSH 운영자 IP 만');
  await p.fill('#decBy', '김담당');
  await p.check('#decAck');
  await p.click('[data-act="decide"]');
  await p.waitForFunction(() => [...document.querySelectorAll('.mtoast')].some((x) => x.textContent.includes('결정을 기록함')), null, { timeout: 10000 }).catch(() => {});
  check('T25b ⑧ 승인 기록', (await p.$$eval('.mtoast', (xs) => xs.map((x) => x.textContent).join(' '))).includes('결정을 기록함'));
  await p.waitForFunction(() => document.querySelectorAll('.prchk li').length >= 6, null, { timeout: 20000 }).catch(() => {});
  check('T25c ⑧ PR 준비 확인: 예제 프로젝트 — 시연용 PR 줄 (D-44)', (await txt('.prchk')).includes('예제 프로젝트 — 시연용 PR'), (await txt('.prchk')).slice(0, 600));
  await p.waitForSelector('.reqcheck', { timeout: 20000 }).catch(() => {});
  const rc8 = await txt('.reqcheck.compact');
  const t5 = await p.$eval('.reqcheck.compact .rqchip:nth-of-type(5)', (x) => x.title).catch(() => '');
  check('T25d ⑧ 승인 뒤 고객 요청 조건 5개 모두 지킴 (짧은 칸) · 5번 근거 = 김담당 승인 · 반영은 사람이', rc8.includes('고객 요청 조건 5개 — 지킴 5') && (await p.$$('.reqcheck.compact .rqchip.good')).length === 5
    && t5.includes('김담당 승인') && t5.includes('반영(apply)은 이 프로그램이 하지 않음'), rc8.slice(0, 300) + ' | ' + t5);
  check('T25e ⑧ 끝맺음 \'확인한 것\' 에 고객 요청 줄', (await txt('.mcard.closing')).includes('고객 요청 조건 5개 — 지킴 5 (가상 고객 요청서)'), (await txt('.mcard.closing')).slice(0, 400));
  const rec8 = await p.evaluate(() => new URLSearchParams(location.hash.slice(1)).get('rec'));
  const pv = await p.evaluate(async (rid) => (await (await fetch('/api/week5/pr_preview', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ record_id: rid, base_branch: 'main' }) })).json()), rec8);
  const body = String(pv.pr_body || '');
  check('T25f PR 미리보기 본문: 끝맺음 다음에 고객 요청 (가상 · 예제) 칸 · 조건 1 지킴 (실행 안 함)', body.includes('## 고객 요청 (가상 · 예제) — Bastion SSH 전체 공개 — 점검 지적 조치 요청') && body.includes('1. Bastion 서버 SSH(22)는 운영자 IP(203.0.113.10)에서만 접속되게 해 주세요. — **지킴**')
    && body.indexOf('끝맺음') < body.indexOf('## 고객 요청'), body.slice(0, 1600));
  await shot('t-s8');
  check('T26 화면 오류 없음', errs.length === 0, errs.slice(0, 5));
  console.log(`\n${pass}/${pass + fail} PASS`);
  await b.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
