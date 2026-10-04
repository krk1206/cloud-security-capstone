(function () {
  'use strict';
  const D = JSON.parse(document.getElementById('site-data').textContent);
  const C = window.IaCPatchCalc;
  const $ = (s, el) => (el || document).querySelector(s);
  const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const b = (v, cls) => `<span class="b ${esc(cls || v)}">${esc(v ?? '-')}</span>`;
  const auto = v => v ? `<span class="b A_${esc(v)}">${esc(v)}</span>` : '<span class="b none">없음</span>';

  // ---------- tabs (deep link: #w4 / #w5 / #exp / #docs)
  const tabs = $$('.tabs button');
  function showTab(id, push) {
    tabs.forEach(t => t.classList.toggle('on', t.dataset.tab === id));
    $$('section.tab').forEach(s => { s.hidden = s.id !== 'tab-' + id; });
    if (push) { try { history.replaceState(null, '', '#' + id); } catch (e) {} }
  }
  tabs.forEach(t => t.addEventListener('click', () => showTab(t.dataset.tab, true)));
  const initial = (location.hash || '').replace('#', '');
  showTab(['w4', 'w5', 'exp', 'docs'].includes(initial) ? initial : 'w4', false);

  // ---------- 4주차: 기준표
  const rv = D.rubric;
  $('#rubric-ver').textContent = rv.version;
  $('#th-low').textContent = rv.thresholds.low_max; $('#th-med').textContent = rv.thresholds.medium_max;
  $('#rubric-points tbody').innerHTML = rv.points.map(p => `<tr><td>${esc(p.label)}</td><td><b>+${esc(p.points)}</b></td><td class="mono small">${esc(p.key)}</td></tr>`).join('');
  $('#rubric-hard').innerHTML = rv.hard_high.map(h => `<li>${h.on ? '✔' : '✖'} ${esc(h.label)} <span class="mono small">${esc(h.key)}</span>${h.on ? '' : ' <span class="small">(v2 에서 해제 — IAM 은 아래 floor 로)</span>'}</li>`).join('');
  $('#rubric-floor').innerHTML = rv.medium_floor.map(h => `<li>${h.on ? '✔' : '✖'} ${esc(h.label)} <span class="mono small">${esc(h.key)}</span></li>`).join('');
  $('#rubric-cap').innerHTML = Object.entries(rv.autonomy_cap).map(([k, v]) => `<li>위험도 ${b(k)} → 자율성 상한 ${auto(v)}</li>`).join('');
  $('#rubric-undet').innerHTML = rv.text_basis_undetermined.map(t => `<li>${esc(t)}</li>`).join('');

  // ---------- 4주차: 라벨 25건
  const L = D.labels;
  $('#labels-status').textContent = `일치 ${L.agree}/${L.judged} (라벨 ${L.total}건) · 분포 LOW ${L.distribution.LOW} / MEDIUM ${L.distribution.MEDIUM} / HIGH ${L.distribution.HIGH} · 사람 손 검산 ${L.human_verified}/${L.total}`;
  $('#labels-table tbody').innerHTML = L.rows.map(r => `<tr><td class="mono small">${esc(r.scenario)}</td><td>${b(r.expected)}</td><td>${b(r.actual)}</td><td>${r.agree ? '✔' : '✖'}</td><td>${esc(r.score)}</td>
    <td class="small">${esc(r.basis)}<br><span class="fact">${(r.factors || []).map(f => `${f.points ? '<b>+' + f.points + '</b> ' : ''}${esc(f.label)}${f.note ? ' <span class="tag">' + esc(f.note) + '</span>' : ''}`).join(' · ') || '0점 항목만'}</span></td>
    <td>${b(r.v5)}</td><td>${b(r.v6)}</td><td>${b(r.state)}</td><td class="small">${esc(r.basis_kind)}</td></tr>`).join('');

  // ---------- 4주차: 상한 강제 72
  const K = D.cap;
  $('#cap-status').innerHTML = `${K.total} 조합 · 위반 <b>${K.violations.length}</b> 건 (빌드 시 Python 으로 계산, 아래 표는 그 결과)`;
  $('#cap-inv').innerHTML = K.invariants.map(t => `<li>✔ ${esc(t)}</li>`).join('') + K.violations.map(v => `<li style="color:var(--crit)">✖ ${esc(v)}</li>`).join('');
  $('#cap-table tbody').innerHTML = K.rows.map(r => `<tr><td>${b(r.risk_level)}</td><td>${auto(r.cap)}</td><td>${auto(r.proposal)}</td><td>${b(r.validity)}</td><td>${r.policy_ok ? '통과' : '<b>위반</b>'}</td><td>${auto(r.final)}</td><td>${b(r.action)}</td><td class="small">${r.forced_down ? '<b>강제 하향</b> ' : ''}${esc(r.reasons.join(' / '))}</td></tr>`).join('');

  // ---------- 4주차: 게이트 데모 (JS 이식, 72 조합 Python 과 일치 확인됨)
  function gate() {
    const rl = $('#g-risk').value, prop = $('#g-prop').value || null, val = $('#g-val').value, ok = $('#g-pol').checked;
    const g = C.gateDecide(rl, prop, val, ok);
    const ko = { CREATE_PR_AUTO: 'PR 자동 생성 → 병합 전 경량 확인 (apply 는 사람)', CREATE_PR_APPROVAL: 'PR 생성 + 검증 표 첨부 → 사람 승인 필수', REPORT_ONLY: '패치 반영 금지, 분석 리포트만', BLOCK: '차단 (정책 위반 또는 검증 실패)', HOLD_FOR_HUMAN: '보류 — 검증이 다 끝나기 전엔 등급을 정하지 않음' };
    $('#gate-out').innerHTML = `<div class="row"><span>상한 ${auto(g.cap)}</span><span>제안 ${auto(prop)}</span><span>→ 최종 ${auto(g.final)}</span>${b(g.action)}${g.forced_down ? '<b style="color:var(--crit)">강제 하향됨</b>' : ''}</div>
      <p class="sub" style="margin-top:6px">${esc(ko[g.action] || g.action)}</p><ul class="small">${g.reasons.map(r => `<li class="mono">${esc(r)}</li>`).join('')}</ul>`;
  }
  ['#g-risk', '#g-prop', '#g-val', '#g-pol'].forEach(s => $(s).addEventListener('change', gate));
  gate();

  // ---------- 4주차: 계산기
  const FIELDS = [['target_kind', '대상 유형', 'select', ['SG', 'IAM']], ['changed_attrs', '바뀐 속성 (쉼표)', 'text', 'ingress'], ['resources_touched', '바뀐 리소스 수', 'int', 1], ['new_resources', '새로 만든 리소스 수', 'int', 0],
    ['deleted', '리소스 삭제 있음', 'bool', false], ['replaced', '리소스 교체(destroy+create)', 'bool', false], ['trust_policy', '신뢰 정책 변경 (IAM)', 'bool', false], ['provider_changed', 'provider 설정 변경', 'bool', false],
    ['attachment_points', '바뀐 SG 가 붙은 부착 지점 수', 'int', 0], ['external_sg', '부착 지점에 plan 밖 SG', 'bool', false], ['outside_family', '대상 가족 밖 리소스 타입 변경', 'bool', false], ['oracle_partial', '오라클 일부 규칙 미확정', 'bool', false],
    ['lines', 'diff 줄 수', 'int', 2], ['files', '바뀐 파일 수', 'int', 1]];
  $('#calc-form').innerHTML = FIELDS.map(([k, l, t, d]) => `<label for="calc-${k}">${esc(l)} ${t === 'select' ? `<select id="calc-${k}" data-k="${k}">${d.map(o => `<option>${o}</option>`).join('')}</select>` : t === 'bool' ? `<input type="checkbox" id="calc-${k}" data-k="${k}">` : t === 'int' ? `<input type="number" id="calc-${k}" data-k="${k}" value="${d}" min="0">` : `<input type="text" id="calc-${k}" data-k="${k}" value="${esc(d)}">`}</label>`).join('');
  const LABEL = D.factor_labels;
  function calc() {
    const inp = {}; $$('#calc-form [data-k]').forEach(el => { inp[el.dataset.k] = el.type === 'checkbox' ? el.checked : el.type === 'number' ? Number(el.value) : el.value; });
    const j = C.calcRisk(inp, D.rubric_raw);
    $('#calc-out').innerHTML = `<div class="row"><span>위험도 ${b(j.level)}</span><span>자율성 상한 ${auto(j.cap)}</span><span>점수 <b>${j.score}</b> (LOW ≤ ${rv.thresholds.low_max}, MEDIUM ≤ ${rv.thresholds.medium_max})</span></div>
      <div class="tw"><table><thead><tr><th>요인</th><th>값</th><th>점수</th><th>비고</th></tr></thead><tbody>${j.factors.map(f => `<tr${(f.points || /hard|floor/.test(f.note)) ? ' style="font-weight:600"' : ''}><td>${esc(LABEL[f.factor] || f.factor)}</td><td class="mono small">${esc(JSON.stringify(f.value))}</td><td>${f.points ? '+' + f.points : '0'}</td><td class="small">${esc(f.note)}</td></tr>`).join('')}</tbody></table></div>`;
  }
  $('#calc-form').addEventListener('change', e => { if (e.target.dataset.k === 'target_kind') { const a = $('#calc-changed_attrs'); if (a && (a.value === 'ingress' || a.value === 'policy')) a.value = e.target.value === 'IAM' ? 'policy' : 'ingress'; } calc(); });
  $('#calc-form').addEventListener('input', e => { if (e.target.type === 'text' || e.target.type === 'number') calc(); });
  calc();

  // ---------- 5주차: 예시
  const ex = D.examples;
  $('#ex-nav').innerHTML = ex.map((e, i) => `<button type="button" class="${i === 0 ? 'on' : ''}" data-i="${i}">${esc(e.title)}</button>`).join('');
  function showEx(i) {
    const e = ex[i];
    $$('#ex-nav button').forEach((bt, j) => bt.classList.toggle('on', j === i));
    $('#ex-meta').innerHTML = `<div class="grid">
      <div class="tile ${/REVIEW_REQUIRED/.test(e.state) ? 'good' : 'crit'}"><div class="n" style="font-size:18px">${esc(e.state)}</div><div class="l">상태</div><div class="m">${esc(e.scenario)}</div></div>
      <div class="tile ${/LIGHT|FULL/.test(e.level) ? 'good' : 'crit'}"><div class="n" style="font-size:18px">${esc(e.level)}</div><div class="l">검토 수준</div><div class="m">${esc(e.verification_status)}</div></div>
      <div class="tile ${e.risk === 'LOW' ? 'good' : e.risk === 'MEDIUM' ? 'warn' : 'crit'}"><div class="n" style="font-size:18px">${esc(e.risk)} <small>(${esc(e.score)}점)</small></div><div class="l">위험도 → 상한 ${esc(e.cap)}</div><div class="m">${esc(e.rubric)}</div></div>
      <div class="tile accent"><div class="n" style="font-size:18px">${e.layers.filter(l => l.verdict === 'PASS').length}/${e.layers.length}</div><div class="l">통과 계층</div><div class="m">${esc(e.tools)}</div></div></div>
      <p class="sub" style="margin-top:8px">${esc(e.desc)}</p>`;
    $('#ex-layers tbody').innerHTML = e.layers.map(l => `<tr><td><b>${esc(l.layer)}</b></td><td class="small">${esc(l.name)}</td><td>${b(l.verdict)}</td><td class="small">${esc(l.summary)}</td></tr>`).join('');
    $('#ex-factors').innerHTML = e.factors.length ? e.factors.map(f => `<li class="fact"><b>${f.points ? '+' + f.points : '·'}</b> ${esc(f.factor)}${f.note ? ' — ' + esc(f.note) : ''}</li>`).join('') : '<li class="small">0점 항목만 (가산 요인 없음)</li>';
    $('#ex-history').innerHTML = e.history.map(h => `<li><b>${esc(h.state)}</b> <span class="small">${esc(h.note)}</span></li>`).join('');
    $('#ex-diff').innerHTML = e.diff.split('\n').map(l => `<span class="${l.startsWith('+') && !l.startsWith('+++') ? 'a' : l.startsWith('-') && !l.startsWith('---') ? 'd' : l.startsWith('@@') ? 'h' : ''}">${esc(l)}</span>`).join('\n');
    $('#ex-pr').textContent = e.pr_preview;
    $('#ex-prbody').textContent = e.pr_body;
  }
  $('#ex-nav').addEventListener('click', e => { const bt = e.target.closest('button'); if (bt) showEx(Number(bt.dataset.i)); });
  showEx(0);

  // ---------- 실험 결과
  const S = D.summary;
  $('#sets-table tbody').innerHTML = S.sets.map(s => s.n ? `<tr><td class="mono">${esc(s.id)}</td><td>${s.n}</td><td>${s.agree}/${s.labeled}</td><td>${s.v1_only}</td><td>${s.gate}</td><td><b>${s.spof}</b></td><td>${s.not_run}</td></tr>` : `<tr><td class="mono">${esc(s.id)}</td><td>0</td><td colspan="5" class="small">${esc(s.note)}</td></tr>`).join('');
  const fmax = Math.max(...S.funnel.map(f => f[1]), 1);
  $('#funnel').innerHTML = S.funnel.map(([k, v]) => `<div class="r"><div>${esc(k)}</div><div><div class="bar" style="width:${(100 * v / fmax).toFixed(1)}%"></div></div><div class="n">${v}</div></div>`).join('');
  const smax = Math.max(...Object.values(S.stops), 1);
  $('#stops').innerHTML = Object.entries(S.stops).sort((a, b2) => b2[1] - a[1]).map(([k, v]) => `<div class="r"><div>${esc(k)}</div><div><div class="bar" style="width:${(100 * v / smax).toFixed(1)}%"></div></div><div class="n">${v}</div></div>`).join('');
  $('#levels').innerHTML = Object.entries(S.levels).sort((a, b2) => b2[1] - a[1]).map(([k, v]) => `<li>${b(k === 'None' ? 'none' : k)} ${v}</li>`).join('');

  // ---------- 문서
  const docs = D.docs;
  $('#docnav').innerHTML = docs.map((d, i) => `<button type="button" class="${i === 0 ? 'on' : ''}" data-i="${i}">${esc(d.title)}</button>`).join('');
  function showDoc(i) { $$('#docnav button').forEach((bt, j) => bt.classList.toggle('on', j === i)); $('#doc-body').innerHTML = docs[i].html; }
  $('#docnav').addEventListener('click', e => { const bt = e.target.closest('button'); if (bt) showDoc(Number(bt.dataset.i)); });
  showDoc(0);
})();
