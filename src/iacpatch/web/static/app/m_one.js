// 화면 ① 시작 · ② 현재 인프라 · ③ 고객 설계 · ④ 보안 문제 · 검사 범위 표
import { $, S, api, esc, register, render, chip, sevChip, SRC, modal } from "./m_core.js";
import { mapBox, drawMap, mapView, MLEG, pop, nodeInfo, linkInfo } from "./m_map.js";
import { readyHtml, toolsOk, setupFailHtml } from "./m_help.js";

// 구성도(archmap)의 리소스 목록 묶음 — 그림에 어떻게 반영됐는지 (지어내지 않는다: plan 의 리소스 전부)
const GROUP_LABEL = { picture: "그림의 상자", link: "그림의 선 · 상자 설명으로 반영", frame: "그림의 틀 (VPC · 서브넷 띠)", list: "목록만 — 그림에 없음 (Trivy 탐지 대상)",
  data: "AWS 조회 (data) — 분석 안 함" };

// ------------------------------------------------------------------ ① 시작 — 내 Terraform 폴더 연결이 먼저, 예제는 아래 (D-32)
function projCard(p) {
  const user = p.kind === "user";
  const scanTxt = !p.folder_ok ? "폴더 없음" : p.scanned ? (p.scan_why && p.scan_why.length ? "점검 일부 실패" : "점검 끝") : "점검 전";
  return `<article class="pcard ${p.id === S.pid ? "on" : ""} ${user ? "user" : ""}">
      <div class="pc-top"><b>${esc(p.name)}</b>${user ? chip("run", "내 프로젝트") : p.testbed ? chip("ok", "예제 · AWS 시험 환경 있음") : chip("dim", "예제 · 실제 AWS 시험 환경 없음")}</div>
      <p>${esc(user ? `연결한 폴더: ${p.tf_dir}` : p.summary)}</p>
      <dl><div><dt>Terraform 파일</dt><dd>${p.files == null ? "—" : esc(p.files)}</dd></div><div><dt>리소스</dt><dd>${p.resources == null ? (p.scanned ? "plan 없음" : "점검 전") : esc(p.resources)}</dd></div>
        <div><dt>Trivy 지적</dt><dd>${p.trivy_findings == null ? "점검 전" : esc(p.trivy_findings)}</dd></div><div><dt>고객 설계도</dt><dd>${p.design ? `v${esc(p.design.version)}` : "없음 (초안부터)"}</dd></div></dl>
      ${user && (p.scan_why || []).length ? `<p class="small warn">${esc(p.scan_why[0])}</p>` : ""}
      <div class="pc-foot"><span class="muted">${user ? esc(scanTxt) + (p.scanned_at ? ` · ${esc(String(p.scanned_at).replace("T", " ").slice(5, 16))}` : "") : esc(p.tf_dir)}</span>
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

// 7차 (D-35): 맨 위 = 준비 상태, 그다음 = 하는 일(네 묶음, 왼쪽 메뉴와 같은 이름), 시작하기 카드 3개. 폴더 연결 칸은 눌러야 펼친다
const FLOW = [["보기", "현재 인프라 · 원하는 구조 · 보안 문제", "코드의 구성도를 보고, 고객이 원하는 통신(설계도)과 지금 문제를 확인"],
  ["고치기", "수정안", "AI · 팀 · 직접 만든 수정을 하나씩 — 적용 후 구조를 설계도와 나란히"],
  ["확인", "적용 판단 · AWS 시험 환경", "배포 전 검사(코드만) → 시험 환경이 있으면 AWS 시험 환경에 반영해 설정 · 연결 확인 (운영 아님)"],
  ["결정", "최종 결정", "사람이 승인 · 수정 요청 · 재생성 · 폐기 — 승인해야 PR"]];

register(1, () => {
  const mine = (S.projects || []).filter((p) => p.kind === "user"), ex = (S.projects || []).filter((p) => p.kind !== "user");
  const first = ex.find((p) => p.id === "webapp-3tier") || ex[0];
  const npOpen = S.npOpen || !!(S.np && (S.np.info || S.np.path));
  $("#mbody").innerHTML = `${readyHtml()}
    <section class="hero slim">
      <p class="hero-lead">AI 나 사람이 고친 Terraform 코드를, <b>우리 회사가 원하는 구조(설계도)를 지키는지까지</b> 확인하고 적용을 결정합니다.</p>
      <ol class="hero-flow four">${FLOW.map(([g, s, d]) => `<li><b>${esc(g)}</b><i>${esc(s)}</i><span>${esc(d)}</span></li>`).join("")}</ol>
      <p class="hero-why">Trivy 같은 검사기는 '알려진 위험 규칙' 만 봅니다. 고객이 어떤 통신을 원하는지는 모르기 때문에, 검사기는 통과하지만 고객 구조를 깨는 수정을 걸러내지 못합니다 — 그 부분을 설계도로 확인합니다.</p>
      <p class="hero-path"><b>가장 짧은 길</b> 예제 열기 → ④ 문제 하나 '고치기' → ⑤ 수정안 고르기(AI · 팀 · 내 파일) → ⑥ 답 확인 → ⑧ 승인 → PR. 화면마다 머리말의 <b>'할 일'</b> 한 줄과 <b>'다음 할 일'</b> 칸의 버튼만 따라가면 됩니다. (③ 은 예제에선 확인만 · ⑦ 은 시험 환경이 있는 예제에서만)</p>
    </section>
    <h2 class="msec">시작하기</h2>
    <div class="mstart">
      ${first ? `<article class="sopt main"><b>예제로 해 보기</b><p>${esc(first.name)}${first.testbed ? " — AWS 시험 환경 측정 기록까지 있는 예제입니다" : ""}. 처음이면 여기부터.</p>
        <button type="button" class="mbtn primary" data-open="${esc(first.id)}">${first.id === S.pid ? "계속하기 ▶" : "열기 ▶"}</button></article>` : ""}
      <article class="sopt"><b>내 Terraform 폴더 연결</b><p>폴더를 복사하지도 고치지도 않고 읽기만 합니다. 연결하면 바로 점검하고 같은 순서로 검사합니다.</p>
        <button type="button" class="mbtn ${npOpen ? "on" : ""}" data-act="np-open">${npOpen ? "닫기 ▴" : "폴더 연결하기 ▾"}</button></article>
      <article class="sopt"><b>처음 사용 안내</b><p>화면의 각 부분을 하나씩 밝게 짚어 설명합니다. 모르는 낱말은 '용어 풀이' 에.</p>
        <div class="mnav"><button type="button" class="mbtn" data-act="tour">안내 시작 ▶</button><button type="button" class="mbtn" data-act="glossary">용어 풀이</button></div></article>
    </div>
    ${npOpen ? newProjectHtml() : ""}
    ${mine.length ? `<h2 class="msec">내 프로젝트 <small>${mine.length}</small></h2><div class="pgrid">${mine.map(projCard).join("")}</div>` : ""}
    <h2 class="msec">예제 <small>시연 · 실험용 — 3계층은 AWS 시험 환경 측정 기록이 있음</small></h2>
    <div class="pgrid">${ex.map(projCard).join("")}</div>`;
});

// ------------------------------------------------------------------ ② 현재 인프라 — 코드의 리소스 전부를 AWS 구성도처럼 (D-33)
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
  const inv = A.inventory || { rows: [], counts: {}, total: 0 };
  const boxes = (A.nodes || []).filter((n) => n.cat !== "external");
  const sgl = (A.edges || []).filter((e) => e.kind === "sg");
  const risky = sgl.filter((e) => e.risk);
  const groups = ["picture", "link", "frame", "list", "data"].filter((g) => inv.counts[g]);
  $("#mbody").innerHTML = `${mapBox("tInfra", `지금 코드의 구성 — ${S.proj.name}`, MLEG.code)}<div class="lay2 below">
      <div class="col">
        <details class="mcard dcard"><summary><b>그림에 넣은 것 · 넣지 않은 것</b> <small>plan 의 리소스 ${esc(inv.total)}개 전부 — 눌러서 펼치기</small></summary>
          <div class="invgrid">${groups.map((g) => `<details ${g === "list" ? "open" : ""}><summary>${esc(GROUP_LABEL[g])} <b>${inv.counts[g]}</b></summary>
            <ul class="inv">${inv.rows.filter((r) => r.group === g).slice(0, 120).map((r) => `<li><code>${esc(r.address)}</code><small>${esc(r.type_ko)} — ${esc(r.why)}</small></li>`).join("")}</ul></details>`).join("")}</div>
          <p class="mnote">공개 · 비공개 서브넷은 코드의 라우팅 테이블(인터넷 게이트웨이 · NAT 경로)로 나눴습니다 — 실제 AWS 라우팅 · NACL 확인은 아닙니다.</p></details>
      </div>
      <aside class="mpanel sticky">
        <div class="nums"><div><b>${esc(inv.total)}</b><span>리소스 (plan)</span></div><div><b>${boxes.length}</b><span>그림의 상자</span></div>
          <div><b>${sgl.length}</b><span>보안 그룹 허용 (선)</span></div><div class="${risky.length ? "bad" : ""}"><b>${risky.length}</b><span>위험한 허용</span></div></div>
        <div class="mcard"><h3>그림 읽는 법</h3><ul class="howto"><li><b>상자</b> = 코드의 리소스 (같은 종류 여러 개는 ×N, 딸린 리소스는 주인 상자에 합침)</li>
          <li><b>틀</b> = VPC · 서브넷 (초록 = 공개, 파랑 = 비공개). 오른쪽 = VPC 밖 AWS 서비스</li>
          <li><b>회색 선</b> = 요청 경로 · <b class="blue">파란 선</b> = 보안 그룹이 허용한 통신 (포트) · <b class="bad">빨간 선 · 포트</b> = 자체 검사가 위험으로 본 허용 · <b class="perm">보라 점선</b> = IAM 권한</li>
          <li>상자 오른쪽 위 숫자 = ④ 의 보안 문제 수. 상자 · 선을 누르면 자세히.</li></ul>
          ${(A.notes || []).length ? `<ul class="notes">${A.notes.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}</div>
        ${(S.proj || {}).kind === "user" ? `<div class="mcard small rescan"><b>연결한 폴더</b><p><code>${esc(S.proj.tf_dir || "")}</code></p>
          <p class="muted">마지막 점검 ${esc(String((I.scan || {}).at || "").replace("T", " "))} — 폴더의 코드를 바꿨으면(예: PR 병합 뒤) 다시 점검하세요. 폴더는 읽기만 합니다.</p>
          <div class="mnav"><button type="button" class="mbtn" data-act="scan" ${S.run ? "disabled" : ""}>다시 점검</button></div></div>` : ""}
      </aside></div>`;
  drawMap("tInfra", A, { badges: (S.issues || {}).badges }, (p) => {
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
const LANG_NOTE = `<span class="mchip dim" title="Trivy 가 낸 설명을 그대로 옮김">Trivy 원문</span>`;
register(4, () => {
  const I = S.issues;
  if (!I) { $("#mbody").innerHTML = `<div class="mempty">불러오는 중…</div>`; return; }
  if (!I.ok) { $("#mbody").innerHTML = `<div class="mempty">${esc(I.reason || "")}</div>`; return; }
  const all = I.issues || [];
  const f = S.issueFilter || "all";
  const list = all.filter((x) => f === "all" || (f === "ours" ? !x.sources.includes("trivy") : x.sources.includes(f)));
  const sel = all.find((x) => x.id === S.issue);
  const bys = I.by_source || {};
  const groups = (I.groups || []).filter((g) => list.some((x) => x.group === g.key));
  const srcChips = (x) => x.sources.map((s) => { const [c, w] = SRC[s] || ["dim", s]; return chip(c, w); }).join("") + (!x.sources.includes("trivy") && x.group !== "undecidable" ? chip("miss", "Trivy 는 못 봄") : "");
  let detail = `<h3>문제를 고르세요</h3><p class="muted small">왼쪽 목록에서 문제를 누르면 무엇이 · 왜 문제인지 · 어떻게 고치는지와 코드 위치가 나오고, 위 그림에서 그 위치가 강조됩니다.</p>`;
  if (sel) {
    const en = sel.text_lang === "en";
    detail = `<div class="ihead">${sevChip(sel.severity)}${srcChips(sel)}</div><h3>${esc(sel.title)}</h3>${sel.title_en && sel.title_en !== sel.title ? `<p class="muted small en">${esc(sel.title_en)}</p>` : ""}
      <dl class="kv"><dt>무엇</dt><dd>${esc(sel.what)}</dd>${sel.why ? `<dt>왜 문제</dt><dd>${esc(sel.why)} ${en ? LANG_NOTE : ""}</dd>` : ""}${sel.how ? `<dt>어떻게</dt><dd>${esc(sel.how)} ${en ? LANG_NOTE : ""}</dd>` : ""}
        ${sel.design_detail ? `<dt>설계 기준</dt><dd>${esc(sel.design_detail)}</dd>` : ""}${sel.req_detail ? `<dt>고객 요구사항</dt><dd>${esc(sel.req_detail)}</dd>` : ""}
        <dt>코드 위치</dt><dd>${sel.file ? `<code>${esc(sel.file)}:${esc(sel.line)}</code> ` : ""}<code>${esc(sel.resource || "—")}</code></dd>
        <dt>근거</dt><dd><code>${esc(sel.rule)}</code>${sel.service ? ` <span class="muted">(${esc(sel.service)})</span>` : ""}${(sel.frameworks || []).length ? ` · ${esc(sel.frameworks.join(" · "))} <span class="muted">(Trivy 메타데이터)</span>` : ""}</dd>
        <dt>그림 위치</dt><dd>${(sel.focus || {}).nodes && sel.focus.nodes.length ? `위 그림에서 강조됨${(sel.focus.edges || []).length ? " (선 포함)" : ""} <button type="button" class="linkbtn" data-totop="tIssue">그림 보기 ↑</button>` : "그림에 자리가 없는 리소스 (목록만)"}</dd>
        <dt>고칠 수 있나</dt><dd>${esc(sel.fix.how)}</dd></dl>
      ${sel.trivy_why ? `<details><summary>Trivy 원문 설명</summary><p class="small en">${esc(sel.trivy_why)}</p><p class="small en">${esc(sel.trivy_how || "")}</p></details>` : ""}
      ${sel.fix.set_id || sel.fix.target ? `<div class="mnav"><button type="button" class="mbtn primary" data-fix="${esc(sel.id)}">이 문제 고치기 ▶ ⑤ 수정</button></div>`
        : `<p class="small muted">이 문제는 지금 자동 수정 · 수정 검사 대상이 아닙니다 — 탐지만 합니다.</p>`}`;
  }
  const fbtn = (k, w, n) => `<button type="button" class="${f === k ? "on" : ""}" data-ifilter="${k}">${esc(w)} <b>${n}</b></button>`;
  // 7차: 숫자 카드 다섯 개 → 한 줄 요약 + 'Trivy 가 못 본 문제' 하나만 크게 (이 프로그램이 더 찾는 것)
  $("#mbody").innerHTML = `<div class="issues-top"><div class="isum">
        <div class="isum-l"><b>문제 ${all.length}개</b><span>Trivy 가 찾은 것 ${bys.trivy || 0} · 자체 보안 그룹 검사 ${bys.sg || 0} · 고객 설계 · 요구사항 위반 ${(bys.design || 0) + (bys.requirement || 0) + (bys.iam || 0)} <small>(같은 문제를 여러 도구가 찾으면 1개로 셈)</small></span></div>
        ${I.only_ours ? `<button type="button" class="isum-hl" data-ifilter="ours" title="이 문제만 보기"><b>${I.only_ours}</b><span>Trivy 는 못 보고<br>이 프로그램만 찾은 문제</span></button>` : ""}</div>
      <div class="itools"><div class="seg">${fbtn("all", "전체", all.length)}${fbtn("trivy", "Trivy", bys.trivy || 0)}${fbtn("ours", "Trivy 밖", all.filter((x) => !x.sources.includes("trivy")).length)}${fbtn("design", "설계 위반", bys.design || 0)}</div>
      <button type="button" class="linkbtn" data-act="coverage">검사 범위 표 (무엇을 보고 · 무엇을 안 보나)</button></div></div>
    <p class="mnote top">그림의 숫자 = 상자에 걸린 문제 수 — 상자를 누르면 그 문제로.</p>
    ${I.arch && I.arch.ok ? mapBox("tIssue", sel ? `문제 위치 — ${sel.title}` : "문제 위치 (지금 코드의 구성)", MLEG.code) : ""}
    <div class="lay4 below">
      <div class="ilist">${groups.map((g) => `<section><h3>${esc(g.label)} <small>${list.filter((x) => x.group === g.key).length}</small></h3>
        ${list.filter((x) => x.group === g.key).map((x) => `<button type="button" class="iitem ${x.id === S.issue ? "on" : ""}" data-issue="${esc(x.id)}"><span class="it">${sevChip(x.severity)}${esc(x.title)}</span>
          <span class="ir"><code>${esc(x.resource || "")}</code>${srcChips(x)}</span></button>`).join("")}</section>`).join("") || `<p class="muted">이 조건의 문제 없음</p>`}
        ${(I.notes || []).length ? `<p class="mnote">${I.notes.map(esc).join("<br>")}</p>` : ""}</div>
      <div class="col sticky"><div class="mcard">${detail}</div></div></div>`;
  if (I.arch && I.arch.ok) {
    const v = drawMap("tIssue", I.arch, { badges: I.badges }, (p) => {
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

