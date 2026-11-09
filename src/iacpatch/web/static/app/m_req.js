// 가상 고객 요청서 (14차, D-50 — B 11-06 "고객이 뭘 요청하는지 실제 요청한 것마냥 '이렇게 요청을 부탁했다' 하는 것도 넣어야지").
// ② 맨 위 '고객 요청' 칸 · [요청서 보기] 창 · ⑤ 고른 수정안의 조건 줄 · ⑥ ⑧ 조건별 결과.
// 결과는 서버(web/request.py)가 기록에 있는 값(V1 · V2 · V5 · V6 · 결정 · 시험 환경)을 조건대로 모은 것 그대로 — 여기서 판정하지 않는다.
import { S, esc, modal, mdLite } from "./m_core.js";

const PRI = { 긴급: "bad", 높음: "warn", 보통: "dim" };

const MARK = { good: "✓", bad: "✕", unknown: "?", wait: "…", dim: "–" };
const CHIP = { good: "ok", bad: "bad", unknown: "warn", wait: "dim", dim: "dim" };
const tag = (tone, word) => `<span class="mchip ${CHIP[tone] || "dim"}">${esc(MARK[tone] || "")} ${esc(word)}</span>`;

// ② 맨 위: 누가 · 언제 · 무엇을 요청했나 (짧게) + 조건 이름 + [요청서 보기]
// 16차 (D-52): 팀 3계층 요청은 요청함이 받은 시각 · 보낸 사람 · 중요도 · 기한을 정한다 (r.arrival). 고객 역할로 넣었으면 넣은 사람 · 메모도
// 17차 (D-53): '([지금 받기] 로 도착)' 같은 받은 방식 글은 뺐다
export function reqBanner(r) {
  if (!r) return "";
  const a = r.arrival || null;
  const who = a ? `${r.from} · ${a.sender} · ${a.channel}` : r.from;
  const when = a && a.at_text ? `받은 시각 ${a.at_text}` : r.date;
  return `<div class="mcard reqbar"><div class="rq-top"><span class="mchip warn">고객 요청${r.seq ? ` ${esc(r.seq)}` : ""} · 가상</span><b>${esc(r.title)}</b>${a ? `<span class="mchip ${PRI[a.priority] || "dim"}">${esc(a.priority)} · 기한 ${esc(a.due)}</span>` : ""}<small>${esc(who)} · ${esc(when)}</small>
      <button type="button" class="mbtn sm" data-act="request">요청서 보기</button></div>
    ${a && a.by ? `<p class="rq-by">고객 역할로 넣은 사람 <b>${esc(a.by)}</b>${a.memo ? ` — “${esc(a.memo)}”` : ""}</p>` : ""}
    <p class="rq-quote">“${esc(r.summary)}”</p>
    <p class="rq-conds"><span>요청 조건</span>${(r.items || []).map((it) => `<span class="rq-c"><em>${esc(it.n)}</em>${esc(it.short)}</span>`).join("")}</p></div>`;
}

// 자동 수정 범위 밖 → 사람에게 넘김 (15차, D-51 — 요청 2 S3 · 16차 D-52 요청 5 · 7 ~ 11). 서버(request.handoff)가 Trivy · plan · 정책 파일에서 옮긴 것 그대로
export function handoffCard(h, compact = false) {
  if (!h) return "";
  const now = (h.now || []).length ? `<p class="small hores">지금 값 · <code>${esc(h.resource)}</code></p><table class="hotab"><colgroup><col><col class="v"><col class="v"></colgroup><thead><tr><th>설정</th><th>지금 값</th><th>요청한 값</th></tr></thead><tbody>${h.now.map((x) => `<tr><td><code>${esc(x.attr)}</code></td><td class="${x.ok ? "ok" : "bad"}">${esc(String(x.value))}</td><td>${esc(String(x.want ?? ""))}</td></tr>`).join("")}</tbody></table><p class="small muted">${esc(h.plan_note || "")}</p>`
    : `<p class="small muted">${esc(h.plan_note || "")}</p>`;
  const found = (h.found || []).map((f) => `<li><span class="mchip bad">${esc(f.severity)}</span> <code>${esc(String(f.rule).replace("AVD-", ""))}</code> ${esc(f.title)} <small class="muted">${esc(f.file)}:${esc(f.line)}</small></li>`).join("");
  if (compact) {
    return `<div class="mcard handoff compact"><h3><span class="mchip warn">사람에게 넘김</span> 이 요청은 자동 수정 범위 밖입니다 <button type="button" class="linkbtn" data-go="2">② 에서 할 일 보기</button></h3>
      <p class="small">${esc((h.why || [])[0] || "")}</p></div>`;
  }
  // 17차 (D-53): 세 칸 → 두 칸(무엇이 문제 | 사람이 할 일 · 고친 뒤 확인). '왜 자동으로 고치지 않나' 는 접어 두고 누르면 펼침 (정책 파일을 읽은 이유 그대로)
  return `<div class="mcard handoff"><h3><span class="mchip warn">사람에게 넘김</span> 이 요청은 자동 수정 범위 밖입니다 — 프로그램은 찾기만 하고 고치지 않습니다</h3>
    <div class="ho-grid two"><section><h4>무엇이 문제</h4><ul class="flist small">${found || "<li class=\"muted\">Trivy 결과 없음 — 점검 필요</li>"}</ul>${now}</section>
      <section><h4>사람이 할 일</h4><ol class="small">${(h.todo || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ol>
        <h4>고친 뒤 확인</h4><ol class="small">${(h.verify || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ol></section></div>
    <details class="ho-why"><summary>왜 자동으로 고치지 않나 <small>(${esc((h.why || []).length)}가지 — 팀 정책 파일을 읽은 그대로)</small></summary><ul class="flist small">${(h.why || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
      <p class="small muted">${esc(h.policy_note || "")}</p></details></div>`;
}

// [요청서 보기] — 원문 그대로 (가상 표시)
export function openRequest() {
  const r = S.proj && S.proj.request;
  if (!r) return;
  modal(`${r.label || "고객 요청서"} (가상) — ${r.title}`, `<p class="small muted">이 예제를 위해 만든 가상의 요청서입니다 · <code>${esc(r.path || "")}</code></p><div class="mdtext reqtext">${mdLite(r.text || "")}</div>`, true);
}

// ⑤ 고른 수정안: 조건마다 한 칸 (✓ 지킴 · ✕ 어김 · ? 판정 불가 · … 아직)
export function reqRow(req) {
  if (!req || !(req.items || []).length) return "";
  return `<div class="reqrow"><span class="rq-k">고객 요청</span>${req.items.map((it) => `<span class="rqchip ${esc(it.tone)}" title="${esc([it.text, ...(it.why || [])].join("\n"))}"><em>${esc(it.n)}</em>${esc(it.short)} <b>${esc(MARK[it.tone] || "")} ${esc(it.word)}</b></span>`).join("")}</div>`;
}

// ⑥: 조건마다 결과 + 근거 줄 (어긴 것 먼저) + 확인 방법. ⑧ 은 짧게(compact) — 결정 칸이 먼저 보이게, 근거는 칸에 마우스를 올리면
// 17차 (D-53): ⑥ 에서 '지킴' 인 조건의 근거 줄 · 확인 방법은 접어 둔다 ([근거 보기]) — 어김 · 판정 불가 · 아직 은 펼친 채로
export function reqCard(req, compact = false) {
  if (!req || !(req.items || []).length) return "";
  if (compact) {
    return `<div class="mcard reqcheck compact"><h3>고객 요청을 지켰나요? <small>${esc(req.line || "")}</small> <button type="button" class="linkbtn" data-act="request">요청서 보기</button></h3>
      ${req.note ? `<p class="small rq-note">${esc(req.note)}</p>` : ""}${reqRow(req).replace('<span class="rq-k">고객 요청</span>', "")}</div>`;
  }
  return `<div class="mcard reqcheck"><h3>고객 요청을 지켰나요? <small>${esc(req.line || "")}</small></h3>
    <p class="small muted">${esc(req.from || "")} · ${esc(req.date || "")} · ${esc(req.title || "")} (가상 요청서) <button type="button" class="linkbtn" data-act="request">요청서 보기</button></p>
    ${req.note ? `<p class="small rq-note">${esc(req.note)}</p>` : ""}
    <ol class="rq-items">${req.items.map((it) => {
      const body = `<ul>${(it.lines || []).map((l) => `<li class="${esc(l.tone)}">${esc(MARK[l.tone] || "")} ${esc(l.text)}</li>`).join("")}</ul><small class="muted">확인 방법: ${esc(it.how || "")}</small>`;
      return `<li class="${esc(it.tone)}"><div class="rq-h"><em>${esc(it.n)}</em><b>${esc(it.text)}</b>${tag(it.tone, it.word)}</div>
        ${it.tone === "good" ? `<details class="rq-more"><summary>근거 보기</summary>${body}</details>` : body}</li>`;
    }).join("")}</ol></div>`;
}
