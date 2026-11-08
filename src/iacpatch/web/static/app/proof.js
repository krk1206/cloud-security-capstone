// 탐지 방식 화면 조각. 서버가 기록 파일에서 만든 카드(JSON)를 그대로 그린다 — 판정·숫자를 여기서 만들지 않는다.
export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const VK = { PASS: "통과", FAIL: "실패", WARN: "통과(경고)", UNKNOWN: "판정 불가", NOT_RUN: "미실행", SKIPPED: "건너뜀", ERROR: "오류" };
// 사전 점검 기록(calibration.json)에 저장된 판정·결과 낱말 → 화면 용어. 기록 값은 바꾸지 않는다 (색·비교는 원래 값으로).
const CALV = (v) => { const s = String(v ?? ""); return s === "맞음" ? "일치" : s === "틀림" ? "불일치" : s.startsWith("못 잡음") ? "미탐지 (알려진 한계 — 이전 측정과 동일)"
  : s.startsWith("잡음") ? "탐지 (이전 측정과 다름 — 확인 필요)" : s.startsWith("참고") ? "참고 (이 네트워크는 무응답 대신 즉시 오류 반환)" : s; };
const CALR = (r) => ({ "지적": "탐지", "통과": "미탐지(통과)" }[String(r ?? "")] || String(r ?? ""));
// 예전 기록에 저장된 문구 → 지금 화면 용어 (표시할 때만)
const LEGACY = [["번째 줄", "행"], ["(없는 속성 이름)", "(존재하지 않는 속성 이름)"], ["이 PC 에 열어 둔 포트 (듣는 프로그램 있음)", "이 PC 에 열어 둔 포트 (수신 프로그램 있음)"],
  ["이 PC 의 닫힌 포트 (도달은 하지만 듣는 프로그램 없음)", "이 PC 의 닫힌 포트 (도달 가능, 수신 프로그램 없음)"],
  ["응답하지 않는 주소 (문서용 예시 대역 — 보안 그룹이 막을 때와 같은 '무응답')", "무응답 주소 (문서용 예시 대역 — 보안 그룹 차단과 같은 '무응답')"]];
const legacy = (t) => LEGACY.reduce((s, [a, b]) => s.split(a).join(b), String(t ?? ""));
const fmtN = (n) => (typeof n === "number" ? n.toLocaleString("en-US") : n ?? "?");
export const toneOf = (v) => (v === "PASS" ? "ok" : v === "FAIL" || v === "ERROR" ? "bad" : v ? "warn" : "wait");
const hhmmss = (iso) => { const m = String(iso || "").match(/T(\d{2}:\d{2}:\d{2})/); return m ? m[1] : ""; };
const short = (h, n = 12) => (h ? String(h).slice(0, n) : "");
const fmtBytes = (b) => (b == null ? "" : b >= 1048576 ? `${(b / 1048576).toFixed(1)} MB` : b >= 1024 ? `${(b / 1024).toFixed(1)} KB` : `${b} B`);

// ------------------------------------------------------------------ 블록
function codeHtml(b) {
  const lines = (b.lines || []).map((l) => `<div class="${l.mark ? "mk" : ""}"><span class="n">${esc(l.n)}</span>${esc(l.text)}</div>`).join("");
  return `<div class="pf-blk"><div class="pf-bt">${esc(b.title)} <span class="mono muted">${esc(b.file || "")}</span></div><div class="pf-code ${esc(b.tone || "")}">${lines}</div></div>`;
}
function tableHtml(b) {
  const rows = b.rows || [];
  const tones = b.tones || [];
  if (!rows.length) return `<div class="pf-blk"><div class="pf-bt">${esc(b.title)}</div><div class="pf-empty ${esc(b.tone || "")}">${esc(b.empty || "없음")}</div></div>`;
  return `<div class="pf-blk"><div class="pf-bt">${esc(b.title)}</div><div class="pf-tbw"><table class="pf-tb"><thead><tr>${(b.head || []).map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>`
    + rows.map((r, i) => `<tr class="${esc(tones[i] || b.tone || "")}">${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("") + `</tbody></table></div></div>`;
}
function kvHtml(b) {
  return `<div class="pf-blk"><div class="pf-bt">${esc(b.title)}</div><dl class="pf-kv ${esc(b.tone || "")}">${(b.rows || []).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl></div>`;
}
// 숫자 타일 — 요약 값 두세 개 (예: 신규 탐지 0건 · 해소 1건)
function statsHtml(b) {
  return `<div class="pf-blk"><div class="pf-stats">${(b.items || []).map((x) => `<div class="st-tile ${esc(x.tone || "")}"><b>${esc(x.value)}</b><span>${esc(x.label)}</span></div>`).join("")}</div></div>`;
}
// 변경 행만 — 수정 전(빨강) · 수정 후(초록) 두세 줄
function difflineHtml(b) {
  const row = (cls, tag, l, i) => `<div class="${cls}"><i>${i === 0 ? tag : ""}</i><span class="n">${esc(l.n)}</span><code>${esc(String(l.text || "").trim())}</code></div>`;
  return `<div class="pf-blk"><div class="pf-bt">${esc(b.title)} <span class="mono muted">${esc(b.file || "")}</span></div><div class="pf-dl">`
    + (b.old || []).map((l, i) => row("r", "수정 전", l, i)).join("") + (b.new || []).map((l, i) => row("a", "수정 후", l, i)).join("") + `</div></div>`;
}
export function blockHtml(b) {
  if (b.t === "stats") return statsHtml(b);
  if (b.t === "diffline") return difflineHtml(b);
  if (b.t === "code") return codeHtml(b);
  if (b.t === "table") return tableHtml(b);
  if (b.t === "kv") return kvHtml(b);
  if (b.t === "note") return `<div class="pf-note">${esc(b.text)}</div>`;
  return "";
}

function cmdsHtml(cmds) {
  if (!cmds || !cmds.length) return `<div class="pf-cmd"><div class="m">실행된 명령 없음</div></div>`;
  return `<div class="pf-cmd">` + cmds.map((c) => {
    if (c.cached) return `<div class="c skip">${esc(c.step)} — 재실행 없음 (이전 결과 사용)</div><div class="m">${esc(c.note)} · 최초 생성 시각 ${esc(c.cache_created_at || "?")}</div>`;
    if (!c.cmd) return `<div class="m">${esc(c.note || "")}</div>`;
    const meta = [hhmmss(c.started_at) && `시작 ${hhmmss(c.started_at)}`, c.elapsed_s != null && `${c.elapsed_s}초`, c.returncode != null && `종료 코드 ${c.returncode}`,
      c.output && `출력 ${c.output}${c.output_sha256 ? " · sha256 " + short(c.output_sha256) + "…" : ""}`, c.note].filter(Boolean).join(" · ");
    return `<div class="c">${esc(c.cmd)}</div><div class="m">${esc(c.step)} · ${esc(meta)}</div>`;
  }).join("") + `</div>`;
}

function stdHtml(s) {
  const ok = /^공식 문서 확인|^공식 도구/.test(s.status || "");
  return `<div class="pf-std"><div class="row"><b>${esc(s.org)}</b><span class="grow">${esc(s.doc)} · <b>${esc(s.item)}</b></span><span class="st ${ok ? "ok" : "warn"}">${esc(s.status)}</span></div>
    <div class="t">${esc(s.text)}</div>${s.detail ? `<div class="muted small">${esc(s.detail)}</div>` : ""}
    ${s.url ? `<div class="muted small mono">${esc(s.url)}${s.checked ? ` · 확인 ${esc(s.checked)}` : ""}</div>` : ""}</div>`;
}

function basisHtml(bs) {
  bs = bs || {};
  let out = "";
  if ((bs.standard || []).length) out += `<div class="pf-sub">외부 기준 — 공식 문서 항목 (확인 상태 표시)</div>` + bs.standard.map(stdHtml).join("");
  if ((bs.team || []).length) out += `<div class="pf-sub">팀 요구사항 — 외부 기준 아님</div><dl class="pf-kv">` + bs.team.map((x) => `<dt>${esc(x.k)}</dt><dd>${esc(x.v)}</dd>`).join("") + `</dl>`;
  if ((bs.tool || []).length) out += `<div class="pf-sub">도구</div><dl class="pf-kv">` + bs.tool.map((x) => `<dt>${esc(x.k)}</dt><dd>${esc(x.v)}</dd>`).join("") + `</dl>`;
  if ((bs.cross || []).length) out += `<div class="pf-sub">교차 확인 — 같은 값을 다른 방법으로 재계산</div><dl class="pf-kv">`
    + bs.cross.map((x) => `<dt>${esc(x.k)}</dt><dd>${x.same === true ? `<span class="st ok">일치</span> ` : x.same === false ? `<span class="st bad">불일치</span> ` : ""}${esc(x.v)}</dd>`).join("") + `</dl>`;
  return out || `<div class="muted small">없음</div>`;
}

function leavesListHtml(leaves, rid) {
  if (!leaves || !leaves.length) return `<div class="muted small">없음</div>`;
  return `<div class="pf-files">` + leaves.map((l) => `<div class="f"><span class="mono">${esc(l.path)}</span><span class="muted">${esc(fmtBytes(l.bytes))}</span><span class="mono muted">${esc(short(l.sha256, 16))}</span>`
    + (rid && l.sha256 ? `<button class="mini" data-action="open-file" data-rid="${esc(rid)}" data-path="${esc(l.path)}">열기</button>` : `<span></span>`) + `</div>`).join("") + `</div>`;
}

// 접어 두는 '자세히' — 열고 닫은 상태는 화면이 다시 그려져도 유지된다 (app.js 가 more 로 넘김)
const moreHtml = (more, label, body) => `<details class="pf-more"${more ? " open" : ""}><summary><b>자세히 보기</b><small>${esc(label)}</small></summary><div class="pf-more-b">${body}</div></details>`;
const stepsHtml = (steps) => `<ol class="pf-steps">${(steps || []).map((s) => `<li>${esc(s)}</li>`).join("")}</ol>`;

// ------------------------------------------------------------------ 카드 한 장
// 표시 순서: 질문 → 결과 요약 한 줄 → 확인 방법 한 줄 → 그림 → 핵심 증거. 나머지(순서·명령·기준·한계·파일)는 '자세히' 안에 있다.
const ICON = { ok: "✓", bad: "✕", warn: "!", wait: "·", run: "…" };
const howHtml = (how) => (how ? `<div class="pf-how"><b>확인 방법</b><span>${esc(how)}</span></div>` : "");
export function cardHtml(c, { running = false, rid = "", dwell = 0, more = false } = {}) {
  const v = c.verdict;
  const done = c.status === "done";
  const vtxt = done ? (c.verdict_ko || VK[v] || v) : running ? "검사 중" : c.skipped === "case" ? "해당 없음" : c.skipped ? "미실행" : "기록 없음";
  const sec = (t, body) => `<div class="pf-sec"><h4>${t}</h4>${body}</div>`;
  let out = `<div class="pf-h"><span class="pf-l">${esc(c.layer === "임시" ? "반영" : c.layer)}</span><b class="grow">${esc(c.name)}</b><span class="pf-v ${done ? toneOf(v) : running ? "run" : "wait"}">${esc(vtxt)}</span></div>`;
  if (dwell) out += `<div class="pf-bar"><i id="pfBar"></i></div>`;
  out += `<div class="pf-q">${esc(c.question)}</div>`;
  if (!done) {
    out += `<div class="pf-wait">${running ? "검사 중 — 명령 완료 후 결과 표시" : esc(c.reason || "이 기록에 해당 단계 결과 없음")}</div>`;
    if (running) return out + sec("실행 중인 명령 (이 PC)", cmdsHtml(c.method.commands));
    return out + moreHtml(more, "검사 내용", howHtml(c.how) + stepsHtml(c.method.steps));
  }
  const tone = toneOf(v);
  out += `<div class="pf-sum ${tone}"><i>${ICON[tone] || ""}</i><span>${esc(c.summary || c.reason || "")}</span></div>`;
  if (c.scope === "before" && c.reason) out += `<div class="pf-reason warn">${esc(c.reason)}</div>`;
  if (c.diagram) out += `<svg class="pf-svg" data-diagram="${esc(c.layer)}"></svg>`;
  const ev = c.evidence || [];
  const key = ev.filter((b) => b.key);
  const rest = ev.filter((b) => !b.key);
  if (key.length) out += `<div class="pf-key">${key.map(blockHtml).join("")}</div>`;
  const nCmd = (c.method.commands || []).filter((x) => x.cmd).length;
  const label = ["확인 방법", nCmd ? `실행 명령 ${nCmd}개` : "", rest.length ? `증거 ${rest.length}개` : "", "판정 기준",
    (c.limits || []).length ? "검사 한계" : "", (c.leaves || []).length ? "근거 파일" : ""].filter(Boolean).join(" · ");
  out += moreHtml(more, label,
    (c.how ? sec("확인 방법", howHtml(c.how)) : "")
    + sec("검사 순서", stepsHtml(c.method.steps))
    + sec("실행 명령 — 실행 기록(commands.json) 원문", cmdsHtml(c.method.commands))
    + (rest.length ? sec("증거 — 도구 출력·코드 추출값", rest.map(blockHtml).join("")) : "")
    + sec("판정 기준", basisHtml(c.basis))
    + ((c.limits || []).length ? sec("검사 한계", `<ul class="pf-lim">${c.limits.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`) : "")
    + ((c.leaves || []).length ? sec("근거 파일 — 기록 폴더 파일·sha256", leavesListHtml(c.leaves, rid)) : ""));
  return out;
}

// ------------------------------------------------------------------ 검사 전 정책 확인에서 막힌 기록
export function policyHtml(bb, rid = "", { more = false } = {}) {
  let out = `<div class="pf-h"><span class="pf-l">정책</span><b class="grow">정책 확인 (검사 전)</b><span class="pf-v bad">차단</span></div>`;
  out += `<div class="pf-bar"><i id="pfBar"></i></div>`;
  out += `<div class="pf-q">수정 내용이 팀 정책 허용 범위 안인가 (검사 시작 전 확인)</div>`;
  out += `<div class="pf-sum bad"><i>✕</i><span>차단 — 정책 위반으로 V1~V6 검사 미실행 (위험도·확신도와 무관)</span></div>`;
  const list = bb.violations_ko || bb.violations || [];
  out += `<div class="pf-key"><div class="pf-blk"><div class="pf-bt">위반 항목</div><ul class="pf-lim">${list.map((v) => `<li>${esc(v)}</li>`).join("") || "<li>policy.json 참고</li>"}</ul></div></div>`;
  out += moreHtml(more, "확인 방법 · 검사 순서 · 원본 기록", howHtml("후보 파일을 팀 정책 파일(policy/patch_policy.json)과 대조 — 변경 파일 수, 변경 금지 파일, 금지 코드(provisioner·local-exec 등)")
    + stepsHtml(["V1~V6 시작 전 후보 파일을 정책 파일(policy/patch_policy.json)과 대조",
      "변경 파일 수, 변경 금지 파일(provider.tf·versions.tf 등), 금지 코드(provisioner·local-exec·null_resource 등), terraform·provider 설정 블록 변경 확인",
      "하나라도 위반하면 검사를 시작하지 않고 차단"])
    + (rid ? `<div class="btns"><button class="btn" data-action="open-file" data-rid="${esc(rid)}" data-path="policy.json">원본 기록 policy.json 열기</button></div>` : ""));
  return out;
}

// ------------------------------------------------------------------ 0. 검증 도구 사전 점검
export function calHtml(cal, { running = false, lines = [], dwell = 0, more = false } = {}) {
  const sec = (t, body) => `<div class="pf-sec"><h4>${t}</h4>${body}</div>`;
  const s = (cal && cal.summary) || {};
  // 보고서(report.py cal_ok)와 같은 기준 — Trivy 예제를 실제로 돌리지 못했으면(0개) 정상이 아니다
  const ok = cal && s.trivy_total > 0 && s.trivy_correct === s.trivy_total && s.cidr_mismatches === 0 && s.validate_ok;
  let out = `<div class="pf-h"><span class="pf-l">0</span><b class="grow">검증 도구 사전 점검</b>`
    + `<span class="pf-v ${cal ? (ok ? "ok" : "warn") : running ? "run" : "wait"}">${cal ? (ok ? "통과" : "경고") : running ? "검사 중" : "기록 없음"}</span></div>`;
  if (dwell) out += `<div class="pf-bar"><i id="pfBar"></i></div>`;
  out += `<div class="pf-q">기대 결과가 고정된 점검 시료로 Trivy·Terraform·통신 판정 규칙의 동작을 검사 전에 확인 (후보 평가와 별개)</div>`;
  if (!cal) {
    out += sec("진행", `<div class="pf-cmd">${(lines.length ? lines : ["사전 점검 시작 대기"]).map((l) => `<div class="m">${esc(l)}</div>`).join("")}</div>`);
    return out;
  }
  const d = ((cal.cidr || {}).differential) || {};
  const pr = cal.probe || [];
  const pOk = s.probe_ok ?? pr.filter((x) => x.verdict === "맞음").length, pAll = s.probe_total ?? pr.length;
  out += `<div class="pf-sum ${ok ? "ok" : "warn"}"><i>${ok ? "✓" : "!"}</i><span>${ok ? "사전 점검 통과 — 모든 항목이 기대 결과와 일치" : "사전 점검 경고 — 기대 결과와 다른 항목 있음"}</span></div>`;
  out += `<div class="pf-note">점검 시료 기준 동작 확인 — 전체 탐지 정확도를 보장하지 않음</div>`;
  if (cal._detached) out += `<div class="pf-note">이 기록에 사전 점검 결과가 없어 이 PC 의 최근 점검(${esc(cal.id)}) 표시</div>`;
  // Trivy 미탐지 사례(0.0.0.0/0 분할 표기)를 V6 대역 계산은 '인터넷 전체'로 검출하는가 — 둘 다 기대대로면 통과
  const splitSeen = !!((((cal.cidr || {}).split || {}).mine || {}).covers_internet);
  const chk = [
    [s.trivy_total > 0 && s.trivy_correct === s.trivy_total ? "good" : "bad", "Trivy 점검 시료 — 위험 시료 탐지 · 안전 시료 통과", `검증 결과 ${esc(s.trivy_correct ?? 0)}/${esc(s.trivy_total ?? 0)} 일치`],
    [s.known_limit_reproduced && splitSeen ? "good" : "warn", "Trivy 미탐지 사례 — 0.0.0.0/0 분할 표기 (0.0.0.0/1 + 128.0.0.0/1)",
      s.known_limit_reproduced ? (splitSeen ? "Trivy 미탐지 (알려진 한계) → V6 대역 계산은 '인터넷 전체'로 검출" : "Trivy 미탐지 · V6 대역 계산 결과 확인 필요") : "이전 측정과 다른 결과 — 확인 필요"],
    [d.mismatches === 0 ? "good" : "bad", `IP 대역 계산 — 독립 구현 2개로 무작위 ${esc(fmtN(d.cases))}회 교차 검증`, `결과 불일치 ${esc(fmtN(d.mismatches))}건`],
    [s.validate_ok ? "good" : "bad", "terraform validate — 잘못된 Terraform 구성 탐지", s.validate_ok ? "오류 탐지" : "미탐지"],
    [pOk === pAll ? "good" : "warn", "통신 시험 판정 규칙 — 열린 포트·닫힌 포트·무응답 주소 구분", `검증 결과 ${esc(pOk)}/${esc(pAll)} 일치${pOk === pAll ? "" : " (불일치 항목은 이 PC 네트워크 환경 영향 — 참고)"}`],
  ];
  const tiles = [
    [chk[0][0], `${esc(s.trivy_correct ?? 0)}/${esc(s.trivy_total ?? 0)} 일치`, "Trivy 점검 시료 검증"],
    [s.known_limit_reproduced && splitSeen ? "good" : "warn", s.known_limit_reproduced ? (splitSeen ? "V6 설계 위반 검출" : "Trivy 미탐지") : "확인 필요", "Trivy 미탐지 사례 검증"],
    [chk[2][0], `결과 불일치 ${esc(fmtN(d.mismatches))}건`, `IP 대역 계산 ${esc(fmtN(d.cases))}회 교차 검증`],
    [chk[3][0], s.validate_ok ? "오류 탐지" : "미탐지", "잘못된 Terraform 구성 탐지"],
    [chk[4][0], `${esc(pOk)}/${esc(pAll)} 일치`, "통신 판정 규칙 검증"],
  ];
  out += `<div class="pf-key"><div class="pf-blk"><div class="pf-stats five">${tiles.map(([t, v, l]) => `<div class="st-tile ${t}"><b>${v}</b><span>${l}</span></div>`).join("")}</div></div></div>`;
  const chkTable = `<div class="pf-tbw"><table class="pf-tb"><thead><tr><th>점검 항목</th><th>결과</th></tr></thead><tbody>`
    + chk.map(([t, a, b]) => `<tr class="${t}"><td>${a}</td><td><b>${b}</b></td></tr>`).join("") + `</tbody></table></div>`;
  const rows = (cal.trivy || []).map((r) => {
    const tone = r.verdict === "맞음" ? "good" : /한계/.test(r.verdict || "") ? "warn" : "bad";
    return `<tr class="${tone}"><td>${esc(r.label)}</td><td>${r.risky ? "위험" : "안전"}</td><td>${esc(CALR(r.result))}</td><td>${esc(CALV(r.verdict))}</td></tr>`;
  }).join("");
  const trivySamples = `<div class="pf-tbw"><table class="pf-tb"><thead><tr><th>시료</th><th>기대 결과</th><th>Trivy 결과</th><th>판정</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  const rule = (cal.rule || {}).rule || {};
  const fw = Object.entries(rule.frameworks || {}).filter(([k, v]) => v && v.length && k !== "default").map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · ");
  const sp = ((cal.cidr || {}).split) || {};
  const v = cal.validate || {};
  const dg = v.diagnostic || {};
  const trivyFull = `<div class="pf-tbw"><table class="pf-tb"><thead><tr><th>시료</th><th>허용 대역</th><th>출력 sha256</th></tr></thead><tbody>`
    + (cal.trivy || []).map((r) => `<tr><td>${esc(r.label)}</td><td class="mono">${esc((r.cidrs || []).join(", "))}</td><td class="mono muted">${esc(short(r.output_sha256))}</td></tr>`).join("") + `</tbody></table></div>`;
  out += moreHtml(more, "확인 방법 · Trivy 시료 · 규칙 정의 · IP 대역 계산 · validate · 통신 판정 · 점검 기록",
    sec("확인 방법", howHtml("기대 결과가 고정된 점검 시료를 도구에 먼저 넣어 판정 결과가 기대와 일치하는지 확인 (검사마다 함께 기록). 시료 기준 동작 확인이며 전체 탐지 정확도를 보장하지 않음"))
    + sec("점검 항목 5개", chkTable)
    + sec("Trivy 점검 시료 3개", trivySamples)
    + sec("Trivy 시료 대역·출력 해시 (같은 실행 파일 · 같은 옵션)", trivyFull)
    + sec("판정에 사용하는 Trivy 규칙 정의 — 실행 파일에서 직접 추출",
      `<dl class="pf-kv"><dt>규칙</dt><dd class="mono">${esc(rule.avd_id || "")} · ${esc(rule.severity || "")}</dd><dt>제목</dt><dd>${esc(rule.title || "")}</dd>`
      + `<dt>Trivy 규칙의 기준 태그</dt><dd>${esc(fw || "없음")}</dd><dt>참고 문서</dt><dd class="mono small">${(rule.related_resources || []).map(esc).join("<br>")}</dd>`
      + `<dt>추출 위치</dt><dd>trivy ${esc((cal.rule || {}).version || "")} 실행 파일 ${esc(fmtBytes((cal.rule || {}).bytes))} 내부 규칙 메타데이터 · 기준값과 ${((cal.rule || {}).reference || {}).same ? "일치" : "불일치 — 확인 필요"}</dd></dl>`)
    + sec("IP 대역 계산 교차 검증 (독립 구현 2개)",
      `<dl class="pf-kv"><dt>방법</dt><dd>검사기(파이썬 ipaddress) ↔ 정수 구간 기반 별도 구현</dd><dt>무작위 대역 목록</dt><dd>${esc(fmtN(d.cases))}건 · 불일치 <b>${esc(fmtN(d.mismatches))}</b>건 · 인터넷 전체 포함 사례 ${esc(fmtN(d.cases_covering_internet))}건 · seed ${esc(d.seed)} · ${esc(d.elapsed_s)}초</dd>`
      + `<dt>분할 표기 대역</dt><dd>${esc(((sp.mine || {}).cidrs || []).join(" + "))} → ${(sp.mine || {}).covers_internet ? "합집합 = 인터넷 전체" : esc(((sp.mine || {}).union || []).join(", "))} · 두 방법 ${sp.same ? "일치" : "불일치"}</dd></dl>`)
    + sec("잘못된 Terraform 구성 탐지 (terraform validate)",
      `<dl class="pf-kv"><dt>시료</dt><dd>${esc(legacy(v.sample || v.reason || ""))}</dd><dt>변경 행</dt><dd class="mono small">${esc(v.before || "")} → ${esc(v.after || "")}</dd>`
      + `<dt>validate 결과</dt><dd>${esc(v.result || "")} — 판정 ${esc(CALV(v.verdict || ""))}</dd>`
      + (dg.summary ? `<dt>진단 (원문)</dt><dd class="mono small">${esc(dg.severity)}: ${esc(dg.summary)} — ${esc(dg.detail)} (${esc(dg.file)}:${esc(dg.line)})</dd>` : "")
      + `<dt>도구</dt><dd>${esc(v.tool || "")} · ${esc(v.elapsed_s ?? "")}초</dd></dl>`)
    + sec("통신 시험 판정 규칙 (실제 AWS 검사 V8 에서 사용)",
      `<div class="pf-tbw"><table class="pf-tb"><thead><tr><th>시료</th><th>대상</th><th>기대</th><th>결과</th><th>판정</th></tr></thead><tbody>`
      + pr.map((x) => `<tr class="${x.verdict === "맞음" ? "good" : "warn"}"><td>${esc(legacy(x.what || x.label || ""))}</td><td class="mono">${esc(x.target || "")}</td><td>${esc(x.expect)}</td><td>${esc(x.result)}</td><td>${esc(CALV(x.verdict))}</td></tr>`).join("") + `</tbody></table></div>`)
    + sec("점검 기록", `<dl class="pf-kv"><dt>점검</dt><dd>${esc(cal.id)} · ${esc(String(cal.started_at || "").replace("T", " ").slice(0, 19))} · ${cal.reused ? `이전 점검 재사용 (같은 도구 버전, ${Math.round((cal.age_s_at_use || 0) / 60)}분 전)` : "이번 검사 직전 실행"} · ${esc(cal.elapsed_s)}초</dd>`
      + `<dt>파일</dt><dd class="mono small">data/calibration/${esc(cal.dir || cal.id)}/ · 기록 폴더 evidence/calibration.json</dd></dl>`));
  return out;
}

// ------------------------------------------------------------------ 설계도 ↔ 코드
const loc = (f, a, b) => `${f}:${a}${b && b !== a ? "-" + b : ""}`;
export function topomapBrief(m) {
  if (!m || !m.ok) return "";
  const rows = (m.tiers || []).map((t) => {
    const mem = (t.members || [])[0];
    const kind = mem ? ({ public: "공개", private: "비공개" }[mem.subnet_kind] || mem.subnet_kind) : "?";
    return `<div class="tm"><b>${esc(t.label)}</b><span class="mono small">${esc(t.sg.file)}:${esc(t.sg.line)}</span><span class="small">${(t.members || []).map((x) => esc(x.res.addr.split(".")[0].replace("aws_", ""))).join(", ") || "연결 리소스 없음"}</span><span class="chip ${kind === "공개" ? "warn" : ""}">${esc(kind)}</span></div>`;
  }).join("");
  return `<div class="tmap">${rows}</div>`;
}

export function topomapHtml(m) {
  if (!m || !m.ok) return `<div class="card">${esc((m && (m.reason || m.error)) || "대응표 생성 불가")}</div>`;
  const sec = (t, body, sub = "") => `<div class="sec"><h3>${t}</h3>${sub ? `<p class="muted small" style="margin:-4px 0 8px">${sub}</p>` : ""}${body}</div>`;
  const kindKo = (k) => ({ public: "공개 서브넷", private: "비공개 서브넷" }[k] || k);
  let out = `<div class="phead"><div class="tag">설계도 ↔ Terraform</div><h2>설계도 요소(상자·화살표)와 Terraform 코드 대응</h2>
    <p>${esc(m.target_dir)} 의 .tf 파일 ${m.files.length}개(리소스 ${m.resources}개)를 행 단위로 분석한 대응표. ${esc(m.note)}</p></div>`;
  out += sec("파일", `<table class="t"><thead><tr><th>파일</th><th>리소스</th><th>행 수</th><th>sha256</th></tr></thead><tbody>`
    + m.files.map((f) => `<tr><td class="mono">${esc(f.name)}</td><td>${f.resources}</td><td>${f.lines}</td><td class="mono small muted">${esc(short(f.sha256, 16))}</td></tr>`).join("") + `</tbody></table>`);
  const net = m.network || {};
  out += sec("네트워크 구성 — 공개/비공개 구분 기준은 서브넷의 기본 경로", `<table class="t"><thead><tr><th>서브넷</th><th>개수</th><th>대역</th><th>구분</th><th>근거 (경로 테이블)</th></tr></thead><tbody>`
    + (net.subnets || []).map((s) => `<tr><td class="mono">${esc(s.addr)}</td><td>${esc(s.count || 1)}</td><td class="mono small">${esc(s.cidr)}</td><td>${esc(kindKo(s.kind))}</td><td class="small">${esc(s.word)}${s.via ? ` <span class="mono muted">${esc(loc(s.via.file, s.via.line))}</span>` : ""}</td></tr>`).join("")
    + `</tbody></table>`, `VPC ${(net.vpc || []).map((v) => esc(`${v.addr} (${loc(v.file, v.start, v.end)})`)).join(", ")}`);
  out += sec("계층 7개 — 상자 1개 = 보안 그룹 1개 + 해당 보안 그룹 연결 리소스", `<table class="t"><thead><tr><th>설계도 상자</th><th>보안 그룹</th><th>연결 리소스 (연결 행)</th><th>배치 위치</th><th>외부 노출 속성</th></tr></thead><tbody>`
    + (m.tiers || []).map((t) => `<tr><td><b>${esc(t.label)}</b></td><td class="mono small">${esc(t.sg.addr)}<br><span class="muted">${esc(loc(t.sg.file, t.sg.start, t.sg.end))}</span></td><td class="small">`
      + (t.members || []).map((x) => `<span class="mono">${esc(x.res.addr)}${x.count ? ` ×${esc(x.count)}` : ""}</span> <span class="muted mono">${esc(loc(x.attach.file, x.attach.line))}</span>`
        + (x.placement || []).filter((h) => h.via_user).map((h) => `<br><span class="muted">← ${esc(h.via_user.addr)} (${esc(loc(h.via_user.file, h.via_user.line))})</span>`).join("")).join("<br>")
      + `</td><td class="small">` + (t.members || []).map((x) => `${esc(kindKo(x.subnet_kind))}${(x.placement || [])[0] ? ` <span class="muted mono">${esc(loc(x.placement[0].from.file, x.placement[0].from.line))}</span>` : (x.subnet_kind === "?" ? ` <span class="muted">코드에 서브넷 지정 없음</span>` : "")}`).join("<br>")
      + `</td><td class="small mono">` + (t.members || []).flatMap((x) => (x.exposure || []).map((e) => `${esc(e.text)} <span class="muted">${esc(loc(e.file, e.line))}</span>`)).join("<br>") + `</td></tr>`).join("")
    + `</tbody></table>`);
  out += sec("설계 기준 경로 9개 — 화살표 1개 = 대상 보안 그룹의 ingress 블록", `<table class="t"><thead><tr><th>설계도 화살표</th><th>포트</th><th>정의 블록</th><th>코드상 허용 출발지</th><th>설계상 허용 출발지</th></tr></thead><tbody>`
    + (m.flows || []).map((f) => `<tr data-flow="${esc(f.id)}"><td><b>${esc(f.from_label)} → ${esc(f.to_label)}</b><br><span class="muted small">${esc(f.label)}</span></td><td>${esc(f.port)}</td><td class="small">`
      + (f.rules.length ? f.rules.map((r) => `<span class="mono">${esc(loc(r.file, r.start, r.end))}</span><br><span class="muted">${esc(r.description)}</span>`).join("<br>") : `<span class="chip bad">코드에 없음</span>`)
      + `</td><td class="small mono">${f.rules.map((r) => esc(String(r.source_code).replace("aws_security_group.", "SG "))).join("<br>")}</td><td class="small">${f.rules.map((r) => `${esc(r.source_design)}${r.same_text === false ? ` <span class="chip warn">불일치</span>` : ""}`).join("<br>") || esc(f.from_label)}</td></tr>`).join("")
    + `</tbody></table>`, "허용 출발지를 IP 대역 대신 다른 보안 그룹으로 지정하면 해당 보안 그룹이 연결된 서버의 통신만 허용");
  const ux = m.rules_outside_design || [];
  out += sec("설계 외 허용 경로 (ingress 블록)", ux.length ? ux.map((u) => `<div class="card small"><div class="row"><b>${esc(u.source)} → ${esc(u.to_label)} ${esc(u.ports)}</b><span class="grow"></span><span class="mono muted">${esc(loc(u.file, u.start, u.end))}</span></div>`
      + `<div class="pf-code bad" style="margin-top:6px">${(u.lines || []).map((l) => `<div class="mk"><span class="n">${esc(l.n)}</span>${esc(l.text)}</div>`).join("")}</div></div>`).join("") : `<div class="muted small">없음</div>`,
    "설계도에 화살표가 없으나 코드에 있는 블록. 판정은 배포 전 검사 V6 에서 실행 계획 기준으로 재계산");
  out += sec("IAM — 서버의 AWS API 호출 권한 (보안 그룹과 별개)", (m.iam || []).map((r) => `<div class="card small"><div class="row"><b>${esc(r.tiers.join(", ") || "?")}</b><span class="mono">${esc(r.role.addr)}</span><span class="grow"></span><span class="mono muted">${esc(loc(r.role.file, r.role.start, r.role.end))}</span></div>`
    + r.policies.map((p) => `<div style="margin-top:4px">정책 <span class="mono">${esc(p.res.addr)}</span> <span class="muted mono">${esc(loc(p.res.file, p.res.start, p.res.end))}</span> · 허용 <span class="mono">${esc(p.actions.join(", "))}</span> · 대상 <span class="mono">${esc(p.resources.join(", "))}</span></div>`).join("")
    + `<div class="muted" style="margin-top:4px">연결: ${esc(r.role.addr)} → ${r.profiles.map((p) => esc(p.addr)).join(", ")} → ${r.used_by.map((u) => `${esc(u.addr)} (${esc(loc(u.file, u.line))})`).join(", ")}</div></div>`).join(""));
  const byFile = {};
  (m.outside || []).forEach((o) => { (byFile[o.file] = byFile[o.file] || []).push(o); });
  out += sec("판정 대상 외 — 보안 그룹 판정에 사용하지 않는 리소스", `<table class="t"><thead><tr><th>파일</th><th>리소스</th></tr></thead><tbody>`
    + Object.entries(byFile).map(([f, os]) => `<tr><td class="mono">${esc(f)}</td><td class="small">${os.map((o) => `${esc(o.what || o.type)} <span class="mono muted">${esc(o.addr)}:${esc(o.line)}</span>`).join("<br>")}</td></tr>`).join("") + `</tbody></table>`);
  out += `<p class="small muted">설계도 파일 ${esc(m.intent_file)} · sha256 ${esc(short(m.intent_sha256, 16))}</p>`;
  return out;
}
