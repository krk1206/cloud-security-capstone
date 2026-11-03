// 쉽게 쓰기 (7차 · D-35, B 11-02 "청중 · 사용자가 쓰기 쉽게 — 전체적으로, 다양한 것 추가"):
// 준비 상태(검사 도구 설치) · 화면 안내(하이라이트로 하나씩) · 용어 풀이 · 크게 보기(발표용).
// 판정은 만들지 않는다 — 서버 값(/api/app, 작업 기록)을 그대로 보여 준다.
import { $, S, api, esc, render, toast, modal, followJob, STEPS, canGo, jumpTo } from "./m_core.js";

// ------------------------------------------------------------------ 준비 상태 (① 맨 위)
const TOOL_KO = { trivy: "Trivy", terraform: "Terraform" };
// 버전 글자: trivy 는 'Version: 0.74.0' → 'Trivy 0.74.0', terraform 은 'Terraform v1.16.1' · 'OpenTofu v1.10.6' 그대로 (제품 이름이 들어 있음)
const ver = (k, v) => {
  const s = String((v && v.version) || "?").replace(/^Version:\s*/i, "").trim();
  return k === "trivy" ? `Trivy ${s}` : /^(terraform|opentofu)\b/i.test(s) ? s : `Terraform ${s}`;
};

export function toolsOk() { return !!(S.app && S.app.tools_ok); }

export function readyHtml() {
  const a = S.app || {};
  if (S.run && S.run.kind === "setup") {
    return `<section class="ready run"><div class="rd-t"><b>검사 도구 준비 중…</b><p>Trivy · Terraform 을 인터넷에서 받아 이 프로그램 폴더의 tools 에 넣습니다. 몇 분 걸릴 수 있습니다 (AWS 접속 없음).</p>
      <pre class="mlog" id="mlog">${esc(S.log.slice(-10).join("\n"))}</pre></div></section>`;
  }
  const probs = a.selfcheck || [];
  const folder = probs.length ? `<p class="small bad">프로그램 폴더가 완전하지 않습니다: ${esc(probs.slice(0, 2).join(" · "))}${probs.length > 2 ? " …" : ""} — IaCPatch.exe 를 받은 폴더째로(옆의 policy · scenarios · scripts 폴더와 함께) 두세요.</p>` : "";
  const last = setupFailHtml();
  if (a.tools_ok && !probs.length) {
    const t = a.tools || {};
    return `<section class="ready ok"><em aria-hidden="true">✓</em><span><b>준비됨</b> 검사 도구 ${Object.keys(TOOL_KO).map((k) => `<code>${esc(ver(k, t[k]))}</code>`).join(" · ")} — 예제를 열면 바로 시작합니다.</span>${versionHtml()}</section>`;
  }
  const miss = Object.keys(TOOL_KO).filter((k) => !((a.tools || {})[k] || {}).ok).map((k) => TOOL_KO[k]);
  return `<section class="ready bad"><div class="rd-t"><b>${miss.length ? "처음 한 번 준비가 필요해요" : "프로그램 폴더를 확인하세요"}</b>
      ${miss.length ? `<p>검사 도구가 없습니다 (<b>${esc(miss.join(" · "))}</b>). '준비하기' 를 누르면 이 프로그램 폴더의 tools 에 받습니다 — 인터넷 필요 · AWS 접속 없음 · 한 번만.</p>` : ""}
      ${folder}${last}${versionHtml()}</div>
    ${miss.length ? `<button type="button" class="mbtn primary big" data-act="setup" ${S.run ? "disabled" : ""}>준비하기 ▶</button>` : ""}</section>`;
}

// 프로그램 판 · 커밋 · 소스 지문 (D-37) — exe 안 코드와 옆 폴더 코드가 다르면 경고. 값은 서버 /api/app 의 provenance 그대로
export function versionHtml() {
  const a = S.app || {}, p = a.provenance || {};
  if (!a.version_line) return "";
  const stale = p.stale_exe ? `<span class="vstale" title="exe 를 만든 뒤 옆 폴더의 코드가 바뀌었습니다. exe 를 다시 빌드해야 화면 · 판정이 폴더의 코드와 같아집니다">exe 가 옆 폴더 코드와 다름 — 다시 빌드 필요</span>` : "";
  const nocommit = !((p.build || {}).sha || (p.git_head || {}).sha) ? `<span class="vwarn" title="이 폴더에 git 커밋이 없거나 읽지 못했습니다. 소스 지문으로만 구분됩니다">커밋 없음</span>` : "";
  return `<span class="vline" title="프로그램 판 · 만든 커밋 · 소스 지문(코드 내용의 sha256 앞 12자리 — 커밋 안 한 수정도 반영) · 정책 ${esc(p.policy_version || "?")} · 위험도 기준표 ${esc(String(p.rubric_version || "?").split(" (")[0])}">${esc(a.version_line)}${nocommit}${stale}</span>`;
}

// 마지막 준비(설치)가 실패했으면 그 기록 — ① 준비 상태와 ② 둘 다에 보인다 (알림은 몇 초 뒤 사라지므로)
export function setupFailHtml() {
  const L = S.setupLast;
  if (!L || L.ok) return "";
  return `<details class="small left" open><summary class="bad">마지막 준비 기록 (실패)</summary><pre class="mlog">${esc((L.lines || []).join("\n") || L.error || "")}</pre>
      <p class="small muted">인터넷이 안 되면: 다른 PC 의 tools 폴더(trivy · terraform 실행 파일 · plugin-cache)를 통째로 이 폴더의 tools 에 복사해도 됩니다.</p></details>`;
}

// 검사 도구 설치 (scripts/setup_tools.* — 서버 작업). 끝나면 도구 상태를 다시 읽는다
export async function runSetup(after) {
  if (S.run) return;
  const r = await api.post("/api/job/setup_tools", {});
  if (!r || !r.started) { toast((r && r.error) || "준비를 시작하지 못함 (다른 작업이 진행 중일 수 있음)"); return; }
  S.run = { kind: "setup", label: "검사 도구 준비", t0: Date.now(), since: 0 }; S.log = [];
  render();
  const res = await followJob(() => { const el = $("#mlog"); if (el) { el.textContent = S.log.slice(-10).join("\n"); el.scrollTop = el.scrollHeight; } });
  S.run = null;
  S.app = await api.get("/api/app");
  const ok = toolsOk();
  S.setupLast = { ok, lines: S.log.slice(-14), error: res.error || "" };
  render();
  toast(ok ? "준비 완료 — 이제 예제를 열면 바로 점검합니다" : "준비하지 못함 — 아래 '마지막 준비 기록' 을 확인하세요", ok ? "good" : "bad");
  if (ok && after) await after();
}

// ------------------------------------------------------------------ 크게 보기 (발표 · 프로젝터)
export function applyBig() {
  document.body.classList.toggle("big", !!S.big);
  const b = $("#mbig");
  if (b) { b.textContent = S.big ? "보통 크기" : "크게 보기"; b.title = S.big ? "보통 크기로 되돌림" : "발표 · 프로젝터용 — 오른쪽 내용을 크게"; b.classList.toggle("on", !!S.big); }
}
export function toggleBig() {
  S.big = !S.big;
  try { localStorage.setItem("iacpatch.big", S.big ? "1" : "0"); } catch (e) { /* 저장 못 해도 이번 창에서는 동작 */ }
  applyBig();
}
export function loadBig() {
  try { S.big = localStorage.getItem("iacpatch.big") === "1"; } catch (e) { S.big = false; }
  applyBig();
}

// ------------------------------------------------------------------ 용어 풀이 (비유 없이, 실제로 무엇인지)
export const GLOSSARY = [
  ["인프라 · 도구", [
    ["Terraform", "AWS 같은 클라우드 자원(서버 · 네트워크 · 권한)을 코드(.tf 파일)로 적어 두고, 그 코드대로 만들거나 바꾸는 도구."],
    ["실행 계획 (plan)", "terraform plan. 코드를 실제로 적용하기 전에 무엇이 새로 생기고 · 바뀌고 · 지워지는지 계산한 목록. 이 프로그램은 AWS 에 접속하지 않고 계산한다(오프라인)."],
    ["문법 검사 (validate)", "terraform validate. 코드의 문법 · 속성 이름 · 참조가 맞는지만 본다. 보안상 맞는지는 보지 않는다."],
    ["반영 (apply)", "코드대로 실제 AWS 를 바꾸는 명령. 이 프로그램은 사람 확인 없이 실행하지 않는다 (시험 환경 반영도 사람이 확인 창에서만)."],
    ["보안 그룹 (Security Group)", "AWS 의 서버 · DB 등에 붙는 방화벽 규칙 묶음. '어디서(출발지) 어느 포트로 들어오는 통신을 허용' 하는지 적는다. 적지 않은 통신은 막힌다."],
    ["포트", "서비스가 통신을 받는 번호. 22 = SSH(서버 원격 접속), 3389 = RDP(윈도 원격 접속), 443 = HTTPS, 3306 = MySQL, 6379 = Redis."],
    ["IP 대역 (CIDR)", "IP 주소 범위를 적는 방법. 10.0.0.0/16 = 10.0.x.x 전체, 0.0.0.0/0 = 인터넷 전체. 0.0.0.0/1 과 128.0.0.0/1 을 합치면 0.0.0.0/0 과 같다."],
    ["VPC · 서브넷", "VPC = AWS 안의 내 네트워크. 서브넷 = VPC 안을 나눈 구역. 인터넷 게이트웨이로 가는 경로가 있으면 공개 서브넷, 없으면 비공개 서브넷."],
    ["IAM", "AWS 의 권한 관리. 역할(role)과 정책(policy)으로 누가 어떤 작업을 어떤 자원에 할 수 있는지 정한다."],
  ]],
  ["이 프로그램", [
    ["Trivy", "알려진 설정 오류 규칙으로 코드를 검사하는 보안 스캐너. 규칙에 없는 문제는 못 찾는다 (예: 0.0.0.0/0 을 두 대역으로 나눠 적으면 못 찾음)."],
    ["설정 오류 (Misconfiguration)", "인프라 설정을 잘못한 것 (예: 서버 원격 접속을 인터넷 전체에 열어 둠). 소프트웨어 자체의 결함인 취약점(Vulnerability · CVE)과 다르다. 이 프로그램은 설정 오류를 본다."],
    ["원하는 구조 (설계도)", "고객이 허용한 통신 목록 (출발 → 도착 : 포트). 검사 기준이다. 처음엔 지금 코드에서 위험한 통신만 막아 자동으로 만들고(v1), 바꿔서 저장하면 새 버전이 된다."],
    ["수정안", "문제를 고치려고 만든 코드. AI 가 만든 것 · 팀이 시험용으로 미리 만든 것 · 사람이 직접 올린 것이 있다. 모두 같은 검사를 받는다."],
    ["8개 관문 (V1~V8)", "수정안을 검사하는 8단계. V1 기존 문제 해결 · V2 새 문제 · V3 문법 · V4 실행 계획 · V5 관련 없는 설정 변경 · V6 원하는 구조 유지 — 여기까지는 배포 전 코드만으로. V7 실제 AWS 설정 · V8 실제 연결 — 시험 환경에서."],
    ["시험 환경", "검사용으로 따로 만든 AWS 환경 (3계층 예제에만 있음). 반영(apply)과 삭제(destroy)는 사람만 한다."],
    ["위험도 · 검토 수준", "미리 정한 기준표로 바뀌는 범위를 점수 매겨 LOW · MEDIUM · HIGH 를 정하고, 검사 결과와 합쳐 사람이 어떤 검토를 할지 정한다. 자동으로 반영되는 경우는 없다."],
    ["AI 수정", "Claude Code(구독)에게 고친 코드를 받는 것. AI 는 도구 없이 글만 쓰고 AWS · 저장소에 접근하지 못한다. 막히면 막힌 이유를 붙여 다시 요청한다 (최대 3번)."],
    ["PR (Pull Request)", "GitHub 에 '이 수정을 반영해 주세요' 하고 올리는 요청. 승인한 뒤 사람이 확인 문구를 넣어야 만든다. 병합(merge)은 사람이 GitHub 에서 한다."],
  ]],
];

export function showGlossary() {
  const body = (q) => GLOSSARY.map(([g, rows]) => {
    const hit = rows.filter(([t, d]) => !q || (t + d).toLowerCase().includes(q.toLowerCase()));
    return hit.length ? `<h4 class="gl-g">${esc(g)}</h4><dl class="gl">${hit.map(([t, d]) => `<dt>${esc(t)}</dt><dd>${esc(d)}</dd>`).join("")}</dl>` : "";
  }).join("") || `<p class="muted">찾는 낱말이 없음</p>`;
  const m = modal("용어 풀이", `<input class="minput" id="glq" placeholder="찾을 낱말 (예: plan, 포트, V6)"><div id="glb">${body("")}</div>`);
  const inp = m.querySelector("#glq");
  inp.addEventListener("input", () => { m.querySelector("#glb").innerHTML = body(inp.value.trim()); });
  inp.focus();
}

// ------------------------------------------------------------------ 화면 안내 — 이 화면의 부분을 하나씩 밝게 보여 주며 설명
// sel 이 지금 화면에 없으면 그 칸은 건너뛴다 (예: 수정안을 고르기 전)
// 칸마다 넷째 값 = 바로 가기 [글자, 단계, 그 단계에서 밝게 보일 자리] (B 11-02 "PR 할 링크도 하이라이트 안에 넣어서 바로 넘어가게").
// 갈 수 없는 단계(예: 수정안 분석 전의 ⑧)면 버튼을 그리지 않는다. 바로 가기는 화면 이동뿐 — PR 을 만들거나 결정하지 않는다
const PR_JUMP = ["PR 만들기로 바로 가기 ▶", 8, "#prcard"];
const TOUR = {
  1: [
    ["#mside", "왼쪽 = 진행 순서", "보기(현재 인프라 · 원하는 구조 · 보안 문제) → 고치기(수정안) → 확인(적용 판단 · AWS 시험 환경) → 결정. 흐린 단계는 앞 단계를 해야 열립니다."],
    [".ready", "준비 상태", "검사 도구(Trivy · Terraform)가 있는지 보여 줍니다. 없으면 '준비하기' 한 번으로 받습니다 (인터넷 필요 · AWS 접속 없음)."],
    [".hero", "이 프로그램이 하는 일", "AI 나 사람이 고친 Terraform 코드가 보안 문제를 없애면서, 고객이 원하는 통신 구조(설계도)도 지키는지 확인합니다. 검사기(Trivy)를 통과해도 구조를 깨는 수정이 있기 때문입니다."],
    [".mstart", "시작하기", "처음이면 예제 '3계층 웹 서비스' 를 여세요. 내 Terraform 폴더를 연결해도 같은 순서로 검사합니다."],
    [".mside-foot", "도움 버튼", "화면 안내 · 용어 풀이 · 크게 보기(발표용) · 검사 범위 표가 여기 있습니다. 왼쪽 메뉴 맨 아래 'PR 만들기' 는 ⑧ 의 PR 칸으로 바로 갑니다."],
  ],
  2: [
    ["#tInfra", "지금 코드의 구성도", "Terraform 코드의 리소스를 AWS 구성도처럼 그린 것입니다. 파란 선 = 보안 그룹이 허용한 통신(포트), 빨간 선 = 자체 검사가 위험하다고 본 허용. 상자나 선을 누르면 설명이 나옵니다."],
    [".mpanel .nums", "숫자로 보기", "리소스 수 · 그림의 상자 수 · 보안 그룹 허용 수 · 위험한 허용 수."],
    [".mh-nav .primary", "다음", "다 봤으면 ③ 원하는 구조로 갑니다.", ["③ 원하는 구조로 바로 가기 ▶", 3, ".s3-list"]],
  ],
  3: [
    [".s3-pic", "원하는 구조 (설계도)", "고객이 허용한 통신만 그린 그림입니다. 처음엔 지금 코드에서 위험한 통신만 막아 자동으로 만들어 둡니다 (v1)."],
    [".s3-list", "통신 목록", "한 줄 = 출발 → 도착 : 포트. [허용] · [막기] 를 고르면 왼쪽 그림이 바로 바뀝니다 (미리보기)."],
    [".ssave", "저장", "저장하면 새 버전(v2 …)이 되고, 앞으로의 검사 · AI 수정이 그 버전을 기준으로 합니다.", ["④ 보안 문제로 바로 가기 ▶", 4, ".ilist"]],
  ],
  4: [
    [".isum", "문제 수", "Trivy 가 찾은 것 · 자체 보안 그룹 검사가 찾은 것 · 설계 위반을 한 목록으로 합쳐 셉니다. 같은 문제를 여러 도구가 찾으면 1개로 셉니다."],
    [".isum-hl", "Trivy 가 못 본 문제", "이 프로그램만 찾은 문제입니다 — 검사기만으로는 놓치는 부분입니다."],
    [".ilist", "문제 목록", "하나를 누르면 오른쪽에 무엇 · 왜 · 어떻게 고치는지와 코드 위치가 나오고, 위 그림에서 그 자리가 밝게 표시됩니다."],
    [".col.sticky .mcard", "고치기", "고칠 수 있는 문제면 '이 문제 고치기' 버튼이 나옵니다 → ⑤ 수정안.", ["⑤ 수정안으로 바로 가기 ▶", 5, ".cands"]],
  ],
  5: [
    [".target", "고칠 문제", "지금 고치려는 문제와, 고친 뒤에도 지켜야 할 기준(설계도 버전)입니다."],
    [".cands .cg.ai", "AI 에게 고치게 하기", "AI 가 고친 코드를 내면 8개 관문으로 검사합니다. 막히면 막힌 이유를 붙여 다시 요청합니다 (최대 3번). 시도마다 버튼이 하나씩 생깁니다."],
    [".cands .cg.team", "팀 평가용 수정안", "팀이 평가용으로 미리 만든 수정입니다. 이름 대신 번호와 '무엇을 바꿨는지' 만 보입니다 — 정답 · 오답은 검사해야 보입니다."],
    [".pair", "설계도 ↔ 적용 후", "왼쪽 = 설계도, 오른쪽 = 고른 수정안을 적용한 뒤. 설계도대로면 파랑, 설계도와 다르면 빨강입니다."],
    [".cmp-head", "결과", "고른 수정안의 검사 결과입니다. '이 수정안 적용해도 될까?' 를 누르면 ⑥ 으로 갑니다.", ["⑥ 적용 판단으로 바로 가기 ▶", 6, ".qcol"]],
  ],
  6: [
    [".verdict", "결론", "배포 전(코드만, AWS 접속 없음) 검사의 결론입니다."],
    [".qcol", "다섯 질문", "기존 문제 해결 · 새 문제 · 코드가 올바른가 · 관련 없는 설정 변경 · 고객 구조 유지. 빨간 답이나 '검사 못 함' 이 있으면 승인할 수 없습니다. '자세히' 에 V1~V6 근거."],
    ["#tVerdict", "적용 후 예상 구성", "이 수정안을 적용하면 어떻게 바뀌는지 코드로 계산한 그림입니다.", PR_JUMP],
  ],
  7: [
    [".awsflow", "AWS 시험 환경 5단계", "원본 반영 → 수정 전 측정(V7 · V8) → 수정안 반영 → 수정 후 측정 → 시험 환경 삭제. 파란 테두리가 지금 단계, 초록은 끝난 단계입니다. 운영 환경에는 반영하지 않습니다."],
    [".narrow .mcard.guide, .narrow .mcard", "다음 할 일", "지금 상태에서 할 일 하나와 버튼입니다. 반영 · 삭제 버튼은 plan 을 계산해 확인 창을 띄우고, 사람이 체크하고 [실행] 을 눌러야 AWS 가 바뀝니다. 측정은 읽기만 하고 시간이 되면 자동으로 합니다.", PR_JUMP],
  ],
  8: [
    [".final-grid", "한눈에 정리", "해결된 문제 · 남은 문제 · 새 문제 · 설계 위반 · 검증 못 한 것 · AWS 시험 환경 결과."],
    [".decs", "결정", "승인 · 수정 요청 · 재생성 · 폐기 중 하나를 고르고 이유와 함께 기록합니다. 조건을 어긴 승인은 프로그램이 거절합니다.", ["PR 칸으로 바로 가기 ▼", 8, "#prcard"]],
    ["#prcard", "PR", "승인을 기록한 뒤에만 PR 을 만들 수 있고, 사람이 확인 문구를 넣어야 실행됩니다. 병합은 사람이 GitHub 에서."],
  ],
};

let tourEl = null;
export function endTour() { if (tourEl) { tourEl.remove(); tourEl = null; document.removeEventListener("keydown", tourKey); } }
function tourKey(e) {
  if (!tourEl) return;
  if (e.key === "Escape") endTour();
  else if (e.key === "ArrowRight" || e.key === "Enter") tourEl.dispatchEvent(new CustomEvent("tour", { detail: 1 }));
  else if (e.key === "ArrowLeft") tourEl.dispatchEvent(new CustomEvent("tour", { detail: -1 }));
}

export function startTour(step = S.step) {
  endTour();
  const st = STEPS[step - 1];
  const items = [[null, `${st.n}. ${st.short} — ${st.q}`, `${st.sub} 할 일: ${st.todo}`], ...(TOUR[step] || [])]
    .filter(([sel]) => !sel || document.querySelector(sel));
  let i = 0;
  tourEl = document.createElement("div");
  tourEl.className = "tour";
  tourEl.setAttribute("role", "dialog");
  tourEl.setAttribute("aria-label", "화면 안내");
  document.body.appendChild(tourEl);
  const show = () => {
    const [sel, t, d, jump] = items[i];
    const el = sel ? document.querySelector(sel) : null;
    const jb = jump && canGo(jump[1]) ? `<button type="button" class="mbtn jump" data-tour-jump="${i}">${esc(jump[0])}</button>` : "";
    if (el) el.scrollIntoView({ block: "center", inline: "nearest" });
    requestAnimationFrame(() => {
      if (!tourEl) return;
      const r = el ? el.getBoundingClientRect() : null;
      const vw = window.innerWidth, vh = window.innerHeight, pad = 6;
      const hi = r ? `<div class="tour-hi" style="left:${Math.max(4, r.left - pad)}px;top:${Math.max(4, r.top - pad)}px;width:${Math.min(vw - 8, r.width + pad * 2)}px;height:${Math.min(vh - 8, r.height + pad * 2)}px"></div>` : `<div class="tour-dim"></div>`;
      tourEl.innerHTML = `${hi}<div class="tour-box" role="document"><small>화면 안내 ${i + 1} / ${items.length}</small><b>${esc(t)}</b><p>${esc(d)}</p>
        ${jb ? `<div class="tour-jump">${jb}</div>` : ""}
        <div class="mnav"><button type="button" class="mbtn" data-tour="-1" ${i ? "" : "disabled"}>◀ 이전</button><button type="button" class="mbtn primary" data-tour="1">${i === items.length - 1 ? "끝" : "다음 ▶"}</button><button type="button" class="mbtn" data-tour="0">그만 보기</button></div></div>`;
      const box = tourEl.querySelector(".tour-box");
      const bw = box.offsetWidth, bh = box.offsetHeight;
      let left, top;
      if (!r) { left = (vw - bw) / 2; top = (vh - bh) / 2; }
      else if (r.bottom + bh + 18 < vh) { left = r.left; top = r.bottom + 14; }
      else if (r.top - bh - 18 > 0) { left = r.left; top = r.top - bh - 14; }
      else if (r.right + bw + 18 < vw) { left = r.right + 14; top = r.top; }
      else { left = (vw - bw) / 2; top = vh - bh - 16; }
      box.style.left = `${Math.max(12, Math.min(vw - bw - 12, left))}px`;
      box.style.top = `${Math.max(12, Math.min(vh - bh - 12, top))}px`;
      const nb = box.querySelector('[data-tour="1"]'); if (nb) nb.focus();
    });
  };
  const move = (k) => { if (k === 0) { endTour(); return; } const n = i + k; if (n >= items.length) { endTour(); return; } if (n < 0) return; i = n; show(); };
  tourEl.addEventListener("click", (e) => {
    const j = e.target.closest("[data-tour-jump]");
    if (j) { const jump = items[+j.dataset.tourJump][3]; endTour(); jumpTo(jump[1], jump[2]); return; }
    const b = e.target.closest("[data-tour]"); if (b && !b.disabled) move(+b.dataset.tour);
  });
  tourEl.addEventListener("tour", (e) => move(e.detail));
  document.addEventListener("keydown", tourKey);
  show();
}
