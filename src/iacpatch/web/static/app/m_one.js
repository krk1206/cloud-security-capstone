// 화면 ① 시작 · ② 현재 인프라 · ③ 고객 설계 · ④ 보안 문제 · 검사 범위 표
import { $, S, api, esc, register, registerTodo, render, chip, sevChip, SRC, modal, caseMode } from "./m_core.js";
import { mapBox, drawMap, mapView, MLEG, pop, nodeInfo, linkInfo, drawnIds } from "./m_map.js";
import { readyHtml, toolsOk, setupFailHtml } from "./m_help.js";
import { reqBanner, handoffCard } from "./m_req.js";
import { inboxHtml, isInboxCase, kindChip, statCells } from "./m_inbox.js";

// ------------------------------------------------------------------ ① 시작 — 내 Terraform 폴더 연결이 먼저, 예제는 아래 (D-32)
function projCard(p) {
  const user = p.kind === "user";
  const scanTxt = !p.folder_ok ? "폴더 없음" : p.scanned ? (p.scan_why && p.scan_why.length ? "점검 일부 실패" : "점검 끝") : "점검 전";
  return `<article class="pcard ${p.id === S.pid ? "on" : ""} ${user ? "user" : ""}">
      <div class="pc-top"><b>${esc(p.name)}</b>${kindChip(p)}</div>
      <p>${esc(user ? `연결한 폴더: ${p.tf_dir}` : p.summary)}</p>
      ${p.request ? `<p class="pc-req"><span class="mchip warn">고객 요청${p.request.seq ? ` ${esc(p.request.seq)}` : ""} · 가상</span>${esc(p.request.title)}</p>` : ""}
      ${user ? `<dl>${statCells(p)}</dl>` : ""}
      ${user && (p.scan_why || []).length ? `<p class="small warn">${esc(p.scan_why[0])}</p>` : ""}
      <div class="pc-foot"><span class="muted">${user ? esc(scanTxt) + (p.scanned_at ? ` · ${esc(String(p.scanned_at).replace("T", " ").slice(5, 16))}` : "") : ""}</span>
        <span class="pc-btns">${user ? `<button type="button" class="mbtn" data-unlink="${esc(p.id)}" title="이 프로그램의 기록만 지움 — 폴더는 그대로">연결 끊기</button>` : ""}
        <button type="button" class="mbtn primary" data-open="${esc(p.id)}" ${p.folder_ok === false ? "disabled" : ""}>${p.id === S.pid ? "계속하기 ▶" : "열기 ▶"}</button></span></div>
    </article>`;
}

function newProjectHtml() {
  const n = S.np || {};
  const info = n.info;
  const box = info ? `<div class="np-info ${info.ok ? "ok" : "bad"}">
      ${info.ok ? `<b>연결할 수 있음</b> — .tf ${info.tf_files.length}개 (${esc(info.tf_files.slice(0, 6).join(", "))}${info.tf_files.length > 6 ? " …" : ""})${info.git && info.git.repo ? ` · git 저장소: <code>${esc(info.git.repo)}</code>` : ""}` : `<b>연결할 수 없음</b>`}
      ${(info.errors || []).map((x) => `<div class="bad">${esc(x)}</div>`).join("")}${(info.notes || []).map((x) => `<div class="muted">${esc(x)}</div>`).join("")}</div>` : "";
  return `<section class="pnew"><div class="pn-h"><span class="mh-n">＋</span><div><h2>새 프로젝트 — 내 Terraform 폴더 연결</h2>
      <p>폴더를 <b>복사하지도 고치지도 않고 읽기만</b> 합니다. 연결하면 바로 점검(Trivy · Terraform plan, AWS 접속 없음)하고 ② 현재 인프라부터 시작합니다.</p></div></div>
    <div class="pn-row"><label>프로젝트 이름<input id="npName" class="minput" value="${esc(n.name || "")}" placeholder="예: 결제 서비스 인프라"></label>
      <label class="grow">폴더 경로 (탐색기 주소창에서 복사)<input id="npPath" class="minput" value="${esc(n.path || "")}" placeholder="C:\\Users\\me\\infra\\prod"></label>
      <button type="button" class="mbtn" data-act="np-check">확인</button><button type="button" class="mbtn primary" data-act="np-create" ${S.run ? "disabled" : ""}>연결하고 점검 ▶</button></div>
    ${box}
    <p class="mnote">지원 범위: Terraform 폴더 하나 · AWS provider · 원격 모듈 없음 · AWS 를 조회하는 data 소스 없이 plan 이 되는 코드. 범위 밖이면 그 이유와 함께 '분석 못 함 · 판정 불가' 로 보여 줍니다 (<button type="button" class="linkbtn" data-act="coverage">검사 범위 표</button>).
      PR 은 ⑧ 에서 사람이 확인 문구를 넣었을 때만, 그 폴더의 git 저장소에 새 브랜치로 만듭니다.</p></section>`;
}

// 11차 (D-47, B "쓸데없는 기능 · 내용 다 빼고 프로젝트만"): 준비 상태 한 줄 + 프로젝트 카드만. 설명 글 · 네 묶음 · 안내 카드는 뺐다
// 16차 (D-52): 맨 위 = 고객 요청함 (가상 고객의 요청이 시간이 지나면 하나씩 도착 — 최근 것이 위). 그 아래 다른 예제 · 내 프로젝트
// 17차 (D-53): 예제 카드의 숫자 칸 · 폴더 경로는 뺐다 (내 프로젝트 카드는 점검 상태를 보여야 해서 그대로)
registerTodo(1, () => "프로젝트를 선택하세요. 가상 고객 요청은 아래 요청함에서 별도로 볼 수 있습니다.");
register(1, () => {
  const all = S.projects || [];
  const mine = all.filter((p) => p.kind === "user");
  const ex = all.filter((p) => p.kind !== "user");
  // Prefer in-scope SG cases for a short briefing, without hiding other projects.
  const ranked = ex.map((p, i) => ({p, i, score:
    (p.id === S.pid ? 100 : 0) + (p.fix_scope !== "out_of_policy" ? 10 : 0) +
    (/three-tier-team$/.test(p.id) ? 30 : 0) + (p.testbed ? 20 : 0)
  })).sort((a,b) => b.score - a.score || a.i - b.i).map((x) => x.p);
  const main = ranked.slice(0, 4), more = ranked.slice(4);
  const npOpen = S.npOpen || !!(S.np && (S.np.info || S.np.path));
  $("#mbody").innerHTML = `
    <section class="rf-hero" aria-label="프로그램 소개">
      <div><span class="rf-eyebrow">TERRAFORM PATCH VERIFICATION</span>
        <h2>수정된 코드, 검증한 뒤 승인하세요.</h2>
        <p>스캐너의 경고가 사라졌는지뿐 아니라, 허용 통신 기준과 변경 범위를 함께 확인합니다.</p></div>
      <div class="rf-flow" aria-label="검토 흐름"><b>현황</b><span>→</span><b>수정</b><span>→</span><b>검증</b><span>→</span><b>승인</b></div>
    </section>
    ${readyHtml()}
    <div class="rf-section-title"><div><h2>검토할 프로젝트</h2><p>예제 데이터와 실제 연결 프로젝트를 구분해 선택하세요.</p></div>
      <button type="button" class="mbtn ${npOpen ? "on" : ""}" data-act="np-open">${npOpen ? "폴더 연결 닫기" : "＋ 내 Terraform 연결"}</button></div>
    ${npOpen ? newProjectHtml() : ""}
    ${mine.length ? `<div class="pgrid">${mine.map(projCard).join("")}</div><div class="rf-section-title"><h2>예제 프로젝트 <small>가상 시나리오 · 실제 운영 고객 아님</small></h2></div>` : ""}
    ${main.length ? `<div class="pgrid">${main.map(projCard).join("")}</div>` : `<div class="mempty">표시할 예제가 없습니다. Terraform 폴더를 연결하거나 아래 요청함을 확인하세요.</div>`}
    ${more.length ? `<details class="rf-fold"><summary>전체 예제 더 보기 <small>추가 ${more.length}개 · IAM / 정책 범위 밖 사례 포함</small></summary><div class="pgrid">${more.map(projCard).join("")}</div></details>` : ""}
    <details class="rf-fold"><summary>가상 고객 요청함 <small>시연용 요청 목록 · 실제 고객 요청 아님</small></summary>
      <section class="ibox" id="ibox" aria-label="고객 요청함">${inboxHtml()}</section>
    </details>
    <p class="rf-footer">배포 전 검증과 실제 AWS 통신 시험은 서로 다른 단계입니다. 미검증은 통과가 아니며, 승인 · PR 생성 · AWS 변경은 기존 확인 절차를 따릅니다.</p>`;
});

// ------------------------------------------------------------------ ② 현재 인프라 — 코드의 리소스 전부를 AWS 구성도처럼 (D-33)
registerTodo(2, () => (!((S.proj || {}).request && S.infra && S.infra.ok) ? ""
  : caseMode() === "iam" ? "맨 위 고객 요청을 읽고, 권한 그림에서 빨간 선(넓은 권한)을 찾아보세요. 선을 누르면 어떤 동작이 허용되는지 나옵니다."
  : caseMode() === "handoff" ? "맨 위 고객 요청과 '사람에게 넘김' 칸을 읽으세요 — 이 요청은 팀 정책의 자동 수정 범위 밖이라 프로그램이 고치지 않습니다."
  : "맨 위 고객 요청을 읽고, 그림에서 요청에 나온 빨간 선(위험한 허용)을 찾아보세요. 상자 · 선을 누르면 설명이 나옵니다."));
register(2, () => {
  const I = S.infra;
  if (!I) { $("#mbody").innerHTML = `<div class="mempty">불러오는 중…</div>`; return; }
  if (S.run && (S.run.kind === "scan" || S.run.kind === "setup")) {
    const setup = S.run.kind === "setup";
    $("#mbody").innerHTML = `<div class="mempty"><b>${esc(setup ? "검사 도구 준비 중…" : S.run.label || "프로젝트 점검 중")}</b><p>${setup ? "Trivy · Terraform 을 받아 프로그램 폴더의 tools 에 넣습니다 (인터넷 필요 · AWS 접속 없음). 끝나면 바로 점검합니다."
      : "실행 전 안전 점검 → Terraform 오프라인 plan(작업 폴더 사본) → Trivy. AWS 접속 없음 · 폴더는 읽기만. 처음 한 번은 Terraform 이 AWS provider 를 받느라 시간이 걸릴 수 있습니다."}</p>
      <pre class="mlog" id="mlog">${esc(S.log.slice(-10).join("\n"))}</pre></div>`;
    return;
  }
  if (!I.ok) {
    const why = (I.scan && I.scan.why) || [];
    const noTools = !toolsOk();
    const last = S.scanLast && S.scanLast.pid === S.pid && !S.scanLast.ok ? S.scanLast : null;
    // 7차: 도구가 없으면 '점검 실행' 대신 '검사 도구 준비하기' (전에는 눌러도 반응이 없었음). 마지막 점검이 실패했으면 그 기록을 남겨 보인다
    $("#mbody").innerHTML = `<div class="mempty"><b>현재 인프라를 아직 그리지 못했어요</b><p>${esc(I.reason || "")}</p>
      ${why.length ? `<ul class="notes left">${why.map((x) => `<li class="bad">${esc(x)}</li>`).join("")}</ul>` : ""}
      ${noTools ? `<p><b>검사 도구(Trivy · Terraform)가 아직 없어서 점검할 수 없어요.</b><br>'검사 도구 준비하기' 를 누르면 받아서 설치한 뒤 바로 점검합니다 (인터넷 필요 · AWS 접속 없음).</p>${setupFailHtml()}`
        : I.need_scan ? `<p>먼저 점검(Trivy · Terraform plan)을 한 번 해야 그림이 나옵니다 — AWS 접속 없음 · 폴더는 읽기만.</p>` : `<p class="small">그림 · 설계 비교는 plan 이 있어야 합니다. ${I.trivy_ok ? "Trivy 결과는 ④ 보안 문제에서 볼 수 있습니다 (탐지만)." : ""}</p>`}
      ${last ? `<details class="left" open><summary class="bad">마지막 점검에서 그림을 만들지 못함${last.error ? ` — ${esc(last.error)}` : ""}</summary><pre class="mlog">${esc((last.lines || []).join("\n"))}</pre></details>` : ""}
      <div class="mnav center">${noTools ? `<button type="button" class="mbtn primary" data-act="setup" ${S.run ? "disabled" : ""}>검사 도구 준비하기 ▶</button>`
        : `<button type="button" class="mbtn primary" data-act="scan">${I.need_scan ? "점검 실행" : "다시 점검"}</button>`}${I.trivy_ok ? `<button type="button" class="mbtn" data-go="4">④ 보안 문제 보기</button>` : ""}</div></div>`;
    return;
  }
  const A = I.arch || {};
  const perm = caseMode() === "iam";             // 15차: 권한 요청은 권한 그림 (역할 → 리소스)
  // 11차 (D-47): 리소스 목록 · '그림 읽는 법' 카드는 뺐다 — 그림(범례 포함) + (내 프로젝트) 다시 점검
  // 12차 (D-48): 기본 그림은 흐름 그림(출발지 · 보안 그룹 묶음 · 허용 포트만). VPC · IAM · S3 까지 전부는 [전체 보기]
  // 14차 (D-50): 고객 요청서가 있는 예제는 맨 위에 '누가 · 무엇을 요청했나' 부터 (가상 요청서)
  // 17차 (D-53): 그림 아래 숫자 네 칸(리소스 · 그림의 상자 · 허용 · 위험)은 뺐다 — 왼쪽 메뉴 ② 밑에 같은 숫자(리소스 · 허용 · 위험)가 있다
  const R = (S.proj || {}).request;
  const notes = (A.notes || []).length ? `<ul class="notes">${A.notes.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : "";
  const rescan = (S.proj || {}).kind === "user" ? `<div class="mcard small rescan"><b>연결한 폴더</b><p><code>${esc(S.proj.tf_dir || "")}</code></p>
          <p class="muted">마지막 점검 ${esc(String((I.scan || {}).at || "").replace("T", " "))} — 폴더의 코드를 바꿨으면(예: PR 병합 뒤) 다시 점검하세요. 폴더는 읽기만 합니다.</p>
          <div class="mnav"><button type="button" class="mbtn" data-act="scan" ${S.run ? "disabled" : ""}>다시 점검</button></div></div>` : "";
  $("#mbody").innerHTML = `${reqBanner(R)}${caseMode() === "handoff" ? handoffCard(R && R.handoff) : ""}${perm ? mapBox("tInfra", `지금 코드의 권한 — ${S.proj.name}`, MLEG.perm) : mapBox("tInfra", `지금 코드의 통신 — ${S.proj.name}`, MLEG.codeSimple)}${notes || rescan ? `<div class="lay2 below one">
      <aside class="mpanel">${notes}${rescan}</aside></div>` : ""}`;
  drawMap("tInfra", A, { badges: (S.issues || {}).badges, simple: !perm, perm }, (p) => {
    const v = mapView("tInfra");
    if (p.type === "node") pop(nodeInfo(v, p.node) + issueLinks(p.node.id), p.x, p.y);
    else pop((p.links || [p.link]).map((l) => linkInfo(v, l)).join("<hr>"), p.x, p.y);
  });
});

// 상자에 걸린 보안 문제 → ④ 로 바로 가기
function issueLinks(nid) {
  const b = ((S.issues || {}).badges || {})[nid];
  if (!b || !b.n) return "";
  const its = ((S.issues || {}).issues || []).filter((x) => b.ids.includes(x.id)).slice(0, 5);
  return `<b class="small">보안 문제 ${b.n}개</b><ul class="flist small">${its.map((x) => `<li><button type="button" class="linkbtn" data-issue-go="${esc(x.id)}">${sevChip(x.severity)} ${esc(x.title)}</button></li>`).join("")}</ul>`;
}

// ------------------------------------------------------------------ ④ 보안 문제
registerTodo(4, () => (caseMode() === "handoff" ? "문제를 눌러 위치 · 이유를 보세요 — 이 요청은 자동 수정 범위 밖이라 '이 문제 고치기' 가 없습니다 (사람에게 넘김)." : ""));
const LANG_NOTE = `<span class="mchip dim" title="Trivy 가 낸 설명을 그대로 옮김">Trivy 원문</span>`;
register(4, () => {
  const I = S.issues;
  if (!I) { $("#mbody").innerHTML = `<div class="mempty">불러오는 중…</div>`; return; }
  if (!I.ok) { $("#mbody").innerHTML = `<div class="mempty">${esc(I.reason || "")}</div>`; return; }
  const all = I.issues || [];
  const list = all;
  const sel = all.find((x) => x.id === S.issue);
  const bys = I.by_source || {};
  const groups = (I.groups || []).filter((g) => list.some((x) => x.group === g.key));
  const srcChips = (x) => x.sources.map((s) => { const [c, w] = SRC[s] || ["dim", s]; return chip(c, w); }).join("") + (!x.sources.includes("trivy") && x.group !== "undecidable" ? chip("miss", "Trivy 는 못 봄") : "");
  let detail = `<h3>문제를 고르세요</h3><p class="muted small">왼쪽 목록에서 문제를 누르면 무엇이 · 왜 문제인지 · 어떻게 고치는지와 코드 위치가 나오고, 아래 그림에서 그 위치가 강조됩니다.</p>`;
  const perm = caseMode() === "iam";
  const shown = I.arch && I.arch.ok ? drawnIds(I.arch, true, perm) : new Set();
  if (sel) {
    const en = sel.text_lang === "en";
    const fn = (sel.focus || {}).nodes || [];
    const inPic = fn.some((id) => shown.has(id));
    const where = inPic ? `아래 그림에서 강조됨${(sel.focus.edges || []).length ? " (선 포함)" : ""} <button type="button" class="linkbtn" data-totop="tIssue">그림 보기 ↓</button>`
      : fn.length ? (perm ? "권한 그림에는 없는 리소스 (역할 · 권한과 무관 — 목록만)" : "통신 그림에는 없는 리소스 (보안 그룹 통신과 무관 — 목록만)") : "그림에 자리가 없는 리소스 (목록만)";
    detail = `<div class="ihead">${sevChip(sel.severity)}${srcChips(sel)}</div><h3>${esc(sel.title)}</h3>${sel.title_en && sel.title_en !== sel.title ? `<p class="muted small en">${esc(sel.title_en)}</p>` : ""}
      <dl class="kv"><dt>무엇</dt><dd>${esc(sel.what)}</dd>${sel.why ? `<dt>왜 문제</dt><dd>${esc(sel.why)} ${en ? LANG_NOTE : ""}</dd>` : ""}${sel.how ? `<dt>어떻게</dt><dd>${esc(sel.how)} ${en ? LANG_NOTE : ""}</dd>` : ""}
        ${sel.design_detail ? `<dt>설계 기준</dt><dd>${esc(sel.design_detail)}</dd>` : ""}${sel.req_detail ? `<dt>고객 요구사항</dt><dd>${esc(sel.req_detail)}</dd>` : ""}
        <dt>코드 위치</dt><dd>${sel.file ? `<code>${esc(sel.file)}:${esc(sel.line)}</code> ` : ""}<code>${esc(sel.resource || "—")}</code></dd>
        <dt>근거</dt><dd><code>${esc(sel.rule)}</code>${sel.service ? ` <span class="muted">(${esc(sel.service)})</span>` : ""}${(sel.frameworks || []).length ? ` · ${esc(sel.frameworks.join(" · "))} <span class="muted">(Trivy 메타데이터)</span>` : ""}</dd>
        <dt>그림 위치</dt><dd>${where}</dd>
        <dt>고칠 수 있나</dt><dd>${esc(sel.fix.how)}</dd></dl>
      ${sel.trivy_why ? `<details><summary>Trivy 원문 설명</summary><p class="small en">${esc(sel.trivy_why)}</p><p class="small en">${esc(sel.trivy_how || "")}</p></details>` : ""}
      ${sel.fix.set_id || sel.fix.target ? `<div class="mnav"><button type="button" class="mbtn primary" data-fix="${esc(sel.id)}">이 문제 고치기 ▶ ⑤ 수정</button></div>`
        : `<p class="small muted">이 문제는 지금 자동 수정 · 수정 검사 대상이 아닙니다 — 탐지만 합니다.</p>`}`;
  }
  // 11차 (D-47): 고칠 수 있는 문제(⑤ 로 이어지는 것)를 먼저 크게, 탐지만 되는 나머지는 한 줄로 접어 둔다. 거름 버튼 · 검사 범위 표는 뺐다
  const fixable = list.filter((x) => x.fix && (x.fix.set_id || x.fix.target));
  const rest = list.filter((x) => !fixable.includes(x));
  if (sel && rest.includes(sel)) S.issueRestOpen = true;      // 그림에서 탐지만 되는 문제를 골랐으면 접힌 목록을 펼쳐 보여 준다
  const item = (x) => `<button type="button" class="iitem ${x.id === S.issue ? "on" : ""}" data-issue="${esc(x.id)}"><span class="it">${sevChip(x.severity)}${esc(x.title)}</span>
          <span class="ir"><code>${esc(x.resource || "")}</code>${srcChips(x)}</span></button>`;
  const restHtml = groups.filter((g) => rest.some((x) => x.group === g.key)).map((g) => `<section><h3>${esc(g.label)} <small>${rest.filter((x) => x.group === g.key).length}</small></h3>${rest.filter((x) => x.group === g.key).map(item).join("")}</section>`).join("");
  const HR = caseMode() === "handoff" ? handoffCard(((S.proj || {}).request || {}).handoff, true) : "";
  $("#mbody").innerHTML = `${HR}<div class="issues-top"><div class="isum">
        <div class="isum-l"><b>문제 ${all.length}개</b><span>고칠 수 있는 문제 ${fixable.length} · 탐지만 ${rest.length} <small>(Trivy ${bys.trivy || 0} · 자체 보안 그룹 검사 ${bys.sg || 0} · 설계 · 요구사항 위반 ${(bys.design || 0) + (bys.requirement || 0) + (bys.iam || 0)} — 같은 문제를 여러 도구가 찾으면 1개로 셈)</small></span></div>
        ${I.only_ours ? `<div class="isum-hl" title="Trivy 는 못 보고 이 프로그램만 찾은 문제"><b>${I.only_ours}</b><span>Trivy 는 못 보고<br>이 프로그램만 찾은 문제</span></div>` : ""}</div></div>
    <div class="lay4">
      <div class="ilist"><section class="fixable"><h3>고칠 수 있는 문제 <small>${fixable.length} — 누르고 '이 문제 고치기'</small></h3>${fixable.map(item).join("") || `<p class="muted small">고칠 수 있는 문제 없음</p>`}</section>
        ${rest.length ? `<details class="irest" ${S.issueRestOpen || !fixable.length ? "open" : ""}><summary>탐지만 되는 문제 <b>${rest.length}</b> <small>(이 프로그램은 찾기만 하고 고치지는 않음${fixable.length ? " — 펼치기" : ""})</small></summary>${restHtml}</details>` : ""}
        ${(I.notes || []).length ? `<p class="mnote">${I.notes.map(esc).join("<br>")}</p>` : ""}</div>
      <div class="col sticky"><div class="mcard">${detail}</div></div></div>
    ${I.arch && I.arch.ok ? `<div class="below">${mapBox("tIssue", sel ? `문제 위치 — ${sel.title}` : perm ? "문제 위치 (지금 코드의 권한)" : "문제 위치 (지금 코드의 통신)", perm ? MLEG.perm : MLEG.codeSimple)}</div>` : ""}`;
  const ir = $(".irest"); if (ir) ir.addEventListener("toggle", () => { S.issueRestOpen = ir.open; });
  if (I.arch && I.arch.ok) {
    const v = drawMap("tIssue", I.arch, { badges: I.badges, simple: !perm, perm }, (p) => {
      // 누른 상자 · 선에 걸린 문제를 고른다 (여러 개면 지금 고른 것 다음 것으로)
      const ids = p.type === "node" ? [p.id] : [];
      const eds = p.type === "link" ? (p.links || [p.link]).flatMap((l) => l.edges) : [];
      const hits = list.filter((x) => (x.focus || {}).nodes && (x.focus.nodes.some((n) => ids.includes(n)) || (x.focus.edges || []).some((e) => eds.includes(e))));
      if (!hits.length) { const vv = mapView("tIssue"); pop(p.type === "node" ? nodeInfo(vv, p.node) + `<p class="small muted">이 상자에 걸린 문제 없음 (지금 고른 묶음 기준)</p>` : linkInfo(vv, p.link), p.x, p.y); return; }
      const k = hits.findIndex((x) => x.id === S.issue);
      S.issue = hits[(k + 1) % hits.length].id; render();
    });
    if (v && sel) v.focus((sel.focus || {}).nodes || [], (sel.focus || {}).edges || []);
  }
});

// ------------------------------------------------------------------ 검사 범위 표
export async function showCoverage() {
  const c = S.cov || (S.cov = await api.get("/api/p/coverage"));
  const cell = (v) => { const t = String(v || ""); const cls = t.startsWith("지원") ? "y" : t.startsWith("미지원") ? "n" : t.startsWith("일부") ? "p" : t.startsWith("확인 필요") ? "q" : ""; return `<td class="${cls}">${esc(t)}</td>`; };
  modal("검사 범위 표 — 무엇을 보고, 무엇을 안 보나", `<p class="small">Trivy ${esc(c.trivy_version || "")} 내장 AWS 체크 ${esc(c.trivy_checks)}개(사용 중지 제외) · 자동 수정 지원 룰: ${esc((c.supported_target_rules || []).join(", "))}</p>
    <div class="tscroll"><table class="cov"><thead><tr><th>리소스</th><th>문제 유형</th><th>Trivy 탐지</th><th>자체 검사</th><th>자동 수정</th><th>AWS 시험 환경 검증</th><th>판정할 수 없는 조건</th></tr></thead>
    <tbody>${(c.rows || []).map((r) => `<tr><td><b>${esc(r.resource)}</b></td><td>${esc(r.type)}</td>${cell(r.trivy)}${cell(r.ours)}${cell(r.fix)}${cell(r.aws)}<td class="small">${esc(r.undecidable)}</td></tr>`).join("")}</tbody></table></div>
    <ul class="small">${(c.notes || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
    <p class="small muted">Trivy 서비스별 체크 수: ${Object.entries(c.trivy_by_service || {}).map(([k, v]) => `${esc(k)} ${v}`).join(" · ")}</p>
    <p class="small muted">변형 축(CIDR 분할 · IPv4/IPv6 · 포트 범위 · 보안 그룹 여러 개 · 참조) · IAM 지원 · 미지원 요소 · 변이 시험 결과는 프로그램 폴더의 <code>docs/VERIFICATION_SCOPE.md</code>, 기업용으로 더 있어야 하는 것은 <code>docs/OUT_OF_SCOPE.md</code> 에 코드 기준으로 적혀 있습니다.</p>`, true);
}

