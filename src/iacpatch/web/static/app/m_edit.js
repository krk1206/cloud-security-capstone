// 고객 설계도 편집 (D-30) — 구성요소 · 외부 출처 · 허용 통신을 넣고 뺀다. 바꿀 때마다 서버 미리보기(저장 안 함)로 '이 설계도 + 지금 코드' 를 다시 그린다.
// 두 가지: 있는 설계도를 고쳐 새 버전으로 저장(edit) · 설계도가 없는 프로젝트에서 지금 코드로 만든 초안을 고쳐 처음 확정(create, v1)
import { $, S, api, esc, render, draw, topoStates, toast, designVersion } from "./m_core.js";

const KIND_SUB = { elb: "로드밸런서", ec2: "서버 (EC2)", ecs: "컨테이너 서비스 (ECS)", rds: "데이터베이스 (RDS)", elasticache: "캐시 (ElastiCache)" };
const uid = (p) => p + Math.random().toString(36).slice(2, 7).replace(/[^a-z0-9]/g, "x");
const portText = (f) => (f.protocol === "-1" ? "전체" : f.port != null ? String(f.port) : f.from_port != null ? (f.from_port === f.to_port ? String(f.from_port) : `${f.from_port}-${f.to_port}`) : "");
const sgShort = (a) => String(a || "").split(".").pop();

export function startEdit() {
  const d = JSON.parse(JSON.stringify(((S.design || {}).design || {}).design || {}));
  S.edit = { mode: "edit", key: S.design.set_id, draft: { intent_id: d.intent_id, target_dir: d.target_dir, vpc_cidr: d.vpc_cidr, tiers: d.tiers || [], external: d.external || [], flows: d.flows || [] },
    note: "", preview: null, errors: [], seq: 0 };
  render(); schedule(0);
}

export function startCreate() {
  const d = JSON.parse(JSON.stringify((S.design || {}).draft || {}));
  S.edit = { mode: "create", key: S.pid, draft: { intent_id: d.intent_id, target_dir: d.target_dir, vpc_cidr: d.vpc_cidr, tiers: d.tiers || [], external: d.external || [], flows: d.flows || [] },
    note: "", preview: null, errors: [], seq: 0, risky: d.draft_risky || {} };
  render(); schedule(0);
}

function codeSgs() {
  const m = (S.infra && S.infra.model) || {};
  const out = [];
  (m.nodes || []).filter((n) => n.kind === "tier").forEach((n) => (n.security_groups || []).forEach((sg) => out.push({ address: sg, resources: n.resources || [] })));
  return out;
}

function sgOptions(cur) {
  const list = codeSgs();
  const used = new Set(((S.edit && S.edit.draft.tiers) || []).map((t) => t.security_group));
  const opts = list.map((g) => `<option value="${esc(g.address)}" ${g.address === cur ? "selected" : ""}>${esc(sgShort(g.address))} · 리소스 ${g.resources.length}${used.has(g.address) && g.address !== cur ? " (사용 중)" : ""}</option>`);
  if (cur && !list.some((g) => g.address === cur)) opts.unshift(`<option value="${esc(cur)}" selected>${esc(sgShort(cur))} · 코드에 없음</option>`);
  if (!cur) opts.unshift(`<option value="" selected>보안 그룹 고르기</option>`);
  return opts.join("") + `<option value="__new">＋ 새 보안 그룹 이름…</option>`;
}

export function editorHtml() {
  const E = S.edit, d = E.draft;
  const nextV = E.mode === "create" ? 1 : Math.max(...(((S.design.design || {}).versions || []).map((v) => v.version)), 1) + 1;
  const typeSel = (t) => `<select data-f="type" title="종류 (그림 아이콘)"><option value="">종류 자동</option>${Object.entries(KIND_SUB).map(([k, v]) => `<option value="${k}" ${t.type === k ? "selected" : ""}>${esc(v)}</option>`).join("")}</select>`;
  const srcOpts = (cur) => [...d.external.map((e) => [e.id, `${e.label || e.id} (외부)`]), ...d.tiers.map((t) => [t.id, t.label || t.id])]
    .map(([id, l]) => `<option value="${esc(id)}" ${id === cur ? "selected" : ""}>${esc(l)}</option>`).join("");
  const dstOpts = (cur) => d.tiers.map((t) => `<option value="${esc(t.id)}" ${t.id === cur ? "selected" : ""}>${esc(t.label || t.id)}</option>`).join("");
  return `<div class="mcard edit"><div class="kicker">${E.mode === "create" ? "설계도 처음 확정 (v1)" : `설계도 편집 · v${designVersion()} 에서 → 저장하면 v${nextV}`}</div>
    <p class="small">필요 없는 구성요소는 지우고 필요한 건 넣으세요. 바꿀 때마다 왼쪽 그림이 '이 설계도 + 지금 코드' 로 다시 그려집니다 (저장 전에는 기준이 안 바뀜).</p>
    <div class="ed-sec"><div class="ed-h"><b>구성요소 ${d.tiers.length}</b><span>종류 · 이름 · 코드의 보안 그룹</span><button type="button" class="mini" data-ed="addTier">+ 구성요소</button></div>
      ${d.tiers.map((t, i) => `<div class="ed-row tier" data-k="tiers" data-i="${i}">${typeSel(t)}<input data-f="label" value="${esc(t.label)}" placeholder="이름 (예: 캐시)"><select data-f="sg">${sgOptions(t.security_group)}</select><button type="button" class="x" data-ed="del" title="삭제">×</button></div>`).join("")}</div>
    <div class="ed-sec"><div class="ed-h"><b>외부 출처 ${d.external.length}</b><span>이름 · IP 대역 (쉼표로)</span><button type="button" class="mini" data-ed="addExt">+ 외부 출처</button></div>
      ${d.external.map((e, i) => `<div class="ed-row ext" data-k="external" data-i="${i}"><input data-f="label" value="${esc(e.label)}" placeholder="이름"><input data-f="cidrs" value="${esc((e.cidrs_v4 || []).join(", "))}" placeholder="203.0.113.0/24"><button type="button" class="x" data-ed="del" title="삭제">×</button></div>`).join("")}</div>
    <div class="ed-sec"><div class="ed-h"><b>허용 통신 ${d.flows.length}</b><span>출발 → 도착 · 포트</span><button type="button" class="mini" data-ed="addFlow">+ 통신</button></div>
      ${d.flows.map((f, i) => { const rk = (E.risky || {})[f.id]; return `<div class="ed-row flow ${rk ? "risk" : ""}" data-k="flows" data-i="${i}" ${rk ? `title="${esc(rk)}"` : ""}><select data-f="from">${srcOpts(f.from)}</select><span class="ar">→</span><select data-f="to">${dstOpts(f.to)}</select>
        <input data-f="port" value="${esc(portText(f))}" placeholder="443" ${f.protocol === "-1" ? "disabled" : ""}><select data-f="proto"><option value="tcp" ${f.protocol === "tcp" || !f.protocol ? "selected" : ""}>TCP</option><option value="udp" ${f.protocol === "udp" ? "selected" : ""}>UDP</option><option value="-1" ${f.protocol === "-1" ? "selected" : ""}>전체</option></select>
        <button type="button" class="x" data-ed="del" title="삭제">×</button>${rk ? `<small class="rk">⚠ ${esc(rk)} — 확정 전에 확인</small>` : ""}</div>`; }).join("")}</div>
    <div id="edCheck" class="ed-check">${checkHtml()}</div>
    <label class="ed-note">${E.mode === "create" ? "확정 메모 (기록에 남음)" : "바꾼 이유 (기록에 남음)"}<input data-f="note" value="${esc(E.note)}" placeholder="${E.mode === "create" ? "예: 고객 요구사항 회의 11/1 기준" : "예: 세션을 DB 에 저장해서 Redis 안 씀"}"></label>
    <div class="mnav"><button type="button" class="mbtn primary" data-ed="save" ${E.saving ? "disabled" : ""}>${E.mode === "create" ? "확정 → v1 (지금 기준)" : `저장 → v${nextV} (지금 기준)`}</button><button type="button" class="mbtn" data-ed="cancel">취소</button></div></div>`;
}

function checkHtml() {
  const E = S.edit;
  if (!E) return "";
  if (E.errors && E.errors.length) return `<b class="bad">저장할 수 없음</b><ul>${E.errors.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`;
  const p = E.preview;
  if (!p) return `<span class="muted">지금 코드와 비교 중…</span>`;
  if (!p.computed) return `<span class="muted">${esc(p.reason || "원본 plan 없음")} — 그림만 바뀜</span>`;
  const t = p.topology || {};
  const ex = (t.excess || []).filter((e) => e.kind !== "undesigned_target").length;
  const und = (t.undesigned || []).filter((u) => u.inbound > 0).length;
  const br = (t.flows || []).filter((f) => f.status === "broken").length;
  const miss = (t.tiers || []).filter((x) => x.sg_in_code === false).length;
  const ch = (p.changes && !p.changes.empty) ? `<div class="small" style="margin-top:6px">바뀐 것: ${esc(p.changes.text)}</div>` : (E.mode === "edit" ? `<div class="small muted" style="margin-top:6px">아직 바뀐 것 없음</div>` : "");
  return `<b>이 설계도로 지금 코드를 보면</b><div class="nums four"><div class="${ex ? "bad" : ""}"><b>${ex}</b><span>설계에 없는 연결</span></div><div class="${und ? "bad" : ""}"><b>${und}</b><span>설계에 없는 리소스</span></div>
    <div class="${br ? "warn" : ""}"><b>${br}</b><span>막힌 필수 통신</span></div><div class="${miss ? "warn" : ""}"><b>${miss}</b><span>코드에 없는 구성요소</span></div></div>${ch}`;
}

export function drawEditor() {
  const E = S.edit;
  if (!E) return;
  const p = E.preview;
  if (p && p.ok && p.model) { const t = p.topology || {}; draw("tEdit", p.model, topoStates(t.flows), t.excess || []); }
}

let timer = null;
function schedule(ms = 320) {
  clearTimeout(timer);
  timer = setTimeout(async () => {
    const E = S.edit;
    if (!E) return;
    const seq = ++E.seq;
    const r = await api.post("/api/design/preview", { set_id: E.key, design: E.draft });
    if (!S.edit || seq !== S.edit.seq) return;
    if (r && r.ok) { E.preview = r; E.errors = []; drawEditor(); } else E.errors = (r && (r.errors || [r.error])) || ["미리보기 실패"];
    const box = $("#edCheck"); if (box) box.innerHTML = checkHtml();
  }, ms);
}

export function editInput(t) {
  const E = S.edit;
  if (!E) return;
  if (t.dataset.f === "note") { E.note = t.value; return; }
  const row = t.closest("[data-k]");
  if (!row) return;
  const item = E.draft[row.dataset.k][+row.dataset.i];
  const f = t.dataset.f;
  // 이름을 바꾸면 통신 줄의 출발 · 도착 고르기에도 바로 반영 (다시 그리지 않고 글자만)
  const relabel = () => document.querySelectorAll(`#edPanel select[data-f="from"] option[value="${CSS.escape(item.id)}"], #edPanel select[data-f="to"] option[value="${CSS.escape(item.id)}"]`)
    .forEach((o) => { o.textContent = row.dataset.k === "external" ? `${item.label || item.id} (외부)` : (item.label || item.id); });
  if (row.dataset.k === "tiers") {
    if (f === "label") { item.label = t.value; relabel(); }
    else if (f === "type") { if (t.value) item.type = t.value; else delete item.type; }
    else if (f === "sg") {
      if (t.value === "__new") { const inp = document.createElement("input"); inp.dataset.f = "sgnew"; inp.placeholder = "보안 그룹 이름 (예: cache)"; t.replaceWith(inp); inp.focus(); return; }
      item.security_group = t.value;
    } else if (f === "sgnew") item.security_group = t.value.trim() ? `aws_security_group.${t.value.trim()}` : "";
  } else if (row.dataset.k === "external") {
    if (f === "label") { item.label = t.value; relabel(); }
    else if (f === "cidrs") item.cidrs_v4 = t.value.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
  } else if (row.dataset.k === "flows") {
    // 사람이 고친 통신은 초안의 '확인할 통신' 표시를 지운다 (지금 값 기준 판단은 미리보기 · 저장 뒤 검사가 한다)
    if (E.risky && E.risky[item.id]) { delete E.risky[item.id]; row.classList.remove("risk"); const rk = row.querySelector(".rk"); if (rk) rk.remove(); }
    if (f === "from" || f === "to") item[f] = t.value;
    else if (f === "proto") {
      item.protocol = t.value;
      const pin = row.querySelector('[data-f="port"]');
      if (t.value === "-1") { delete item.port; delete item.from_port; delete item.to_port; if (pin) { pin.value = "전체"; pin.disabled = true; } }
      else if (pin) { pin.disabled = false; if (pin.value === "전체") pin.value = ""; }
    } else if (f === "port") {
      delete item.port; delete item.from_port; delete item.to_port;
      const m = t.value.trim().match(/^(\d+)\s*(?:-\s*(\d+))?$/);
      if (m && m[2]) { item.from_port = +m[1]; item.to_port = +m[2]; } else if (m) item.port = +m[1]; else item.port = t.value.trim();
    }
  }
  schedule();
}

export async function editAct(a, t, reload) {
  const E = S.edit, d = E && E.draft;
  if (!E) return;
  if (a === "addTier") d.tiers.push({ id: uid("c"), label: "", security_group: "" });
  else if (a === "addExt") d.external.push({ id: uid("x"), label: "", cidrs_v4: [] });
  else if (a === "addFlow") d.flows.push({ id: uid("f"), from: (d.external[0] || d.tiers[0] || {}).id, to: (d.tiers[0] || {}).id, protocol: "tcp", port: 443 });
  else if (a === "del") {
    const row = t.closest("[data-k]");
    const k = row.dataset.k, i = +row.dataset.i;
    const gone = d[k][i];
    d[k].splice(i, 1);
    if (k !== "flows") d.flows = d.flows.filter((f) => f.from !== gone.id && f.to !== gone.id);   // 지운 구성요소 · 출처의 통신도 같이
  } else if (a === "cancel") { S.edit = null; render(); return; }
  else if (a === "save") {
    E.saving = true; render();
    const r = E.mode === "create"
      ? await api.post("/api/p/design/create", { project: S.pid, design: d, note: E.note })
      : await api.post("/api/design/save", { set_id: E.key, design: d, note: E.note, base_version: designVersion() });
    if (!r || !r.ok) { E.saving = false; E.errors = (r && (r.errors || [r.error])) || ["저장 실패"]; render(); return; }
    S.edit = null;
    await reload();
    toast(`고객 설계도 v${r.version} ${E.mode === "create" ? "확정" : "저장"} — 이제부터 검사는 v${r.version} 기준${r.changes && r.changes.text ? ` (${r.changes.text})` : ""}`, "good");
    render();
    return;
  }
  render(); schedule(0);
}
