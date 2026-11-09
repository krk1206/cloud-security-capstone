// 시연 화면 (2026-11-10) — 4단계: 1 문제 → 2 수정안 → 3 검사 결과 → 4 결정.
// 검사 · 판정 · 기록은 기존 서버 API 를 그대로 쓴다 (/api/case, /api/case/candidates, /api/review, /api/llm/fix, /api/record, /api/decision).
// 8단계 화면의 ③ '원하는 구조'(통신마다 허용 · 막기 편집)와 ⑦ 'AWS 시험 환경'은 이 화면에 없다.
// 설계도는 읽기 전용 + 확정 버튼 하나, 실제 AWS 확인(V7 · V8)은 GitHub Actions ② ③ 이 맡는다.
// 수정안이 맞는지 틀린지(기대 결과)는 화면에 쓰지 않는다 — 검사 결과만 보여 준다.
(function () {
  "use strict";
  var $ = function (s) { return document.querySelector(s); };
  var esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; });
  };
  var PR_LEVELS = ["FULL_REVIEW", "LIGHT_REVIEW"];
  var S = { cases: [], caseId: "", caseData: null, set: null, source: null, ai: null, rb: null, records: {}, rows: [], sel: "", job: null, logSince: 0, lastLog: "", llm: null };

  function api(path, body) {
    var opt = body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {};
    return fetch(path, opt).then(function (r) { return r.json().catch(function () { return { error: "응답을 읽지 못함 (" + r.status + ")" }; }); });
  }
  function pill(cls, t) { return '<span class="pill ' + cls + '">' + esc(t) + "</span>"; }
  function savedName() { try { return localStorage.getItem("iacpatch-demo-name") || ""; } catch (e) { return ""; } }
  function saveName(v) { try { localStorage.setItem("iacpatch-demo-name", v); } catch (e) { /* 저장 못 해도 동작에는 상관없음 */ } }
  // 엔진 문구의 8단계 화면 번호(③ 원하는 구조)를 이 화면 기준으로 바꿔 읽힌다
  function refs(s) {
    return String(s || "").replace(/③\s*원하는 구조에서/g, "1번(문제)의 설계도에서").replace(/③\s*에서/g, "1번(문제)에서").replace(/③\s*설계도/g, "1번(문제)의 설계도");
  }
  function passLevel(rec) { return !!rec && PR_LEVELS.indexOf((rec.state || {}).level) >= 0; }
  function draft(rec) { return !!(rec && rec.conclusion && rec.conclusion.draft_design); }
  function unsupported(rec) { return !!(rec && rec.candidate && rec.candidate.status === "NOT_SUPPORTED"); }
  // V6(설계도 비교) 실패 문구: IAM 은 엔진이 영어 약식(EXCESS · MISSING)으로 적어서 풀어 쓴다. 보안 그룹은 이미 한국어
  function v6text(s) {
    s = String(s || "");
    var ex = [], miss = [], m, re1 = /EXCESS [^:;]+: ([^;]+)/g, re2 = /MISSING [^:;]+: (\S+ on \S+)/g;
    while ((m = re1.exec(s))) ex.push(m[1].trim());
    while ((m = re2.exec(s))) miss.push(m[1].trim());
    if (ex.length || miss.length) return [ex.length ? "설계에 없는 권한: " + ex.join(", ") : "", miss.length ? "빠진 필수 권한: " + miss.join(", ") : ""].filter(Boolean).join(" / ");
    return s.replace(/^설계 기준과 불일치 \d+건:\s*/, "");
  }

  // ---------- 처음: 도구 · 예제 목록 ----------
  function refreshTools(first) {
    return Promise.all([api("/api/app"), api("/api/llm/status")]).then(function (r) {
      var a = r[0] || {}, t = a.tools || {}, l = r[1] || {};
      S.llm = l;
      var parts = [];
      parts.push(t.trivy && t.trivy.ok ? String(t.trivy.version || "Trivy").replace("Version: ", "Trivy ") : "Trivy 없음");
      parts.push(t.terraform && t.terraform.ok ? String(t.terraform.version || "Terraform") : "Terraform 없음");
      parts.push(l.found ? "Claude Code " + String(l.version || "").split(" ")[0] + (l.logged_in === false ? " (로그인 안 됨)" : "") : "Claude Code 없음");
      // Trivy · Terraform 이 없으면 검사 단계가 '안 함'으로 남는다 → 화면에서 바로 받게 (기존 '도구 설치/확인' 과 같은 스크립트)
      $("#tools").innerHTML = esc(parts.join(" · ")) + (a.tools_ok === false ? ' <button class="btn" type="button" data-act="tools"' + (busy() ? " disabled" : "") + ">검사 도구 준비</button>" : "");
      if (first && a.job && a.job.running) { S.job = a.job; poll(); }
      renderActions();
    });
  }
  function init() {
    refreshTools(true);
    api("/api/cases").then(function (d) {
      var all = (d.cases || []).filter(function (c) { return /^three-tier-team/.test(c.id); });
      return Promise.all(all.map(function (c) {
        return api("/api/case/candidates?id=" + encodeURIComponent(c.id)).then(function (cd) {
          var set = (cd.sets || [])[0];
          return set && (set.candidates || []).some(function (x) { return x.featured; }) ? c : null;
        });
      }));
    }).then(function (list) {
      S.cases = (list || []).filter(Boolean);
      var want = (location.hash || "").replace("#case-", "");
      var first = S.cases.filter(function (c) { return c.id === want; })[0] || S.cases[0];
      renderCases();
      if (first) loadCase(first.id);
      else $("#p-summary").textContent = "보여 줄 예제가 없다 (experiments/candidate-sets 확인).";
    });
  }

  function renderCases() {
    $("#cases").innerHTML = S.cases.map(function (c) {
      var name = String(c.name || c.id), i = name.indexOf("—");
      var title = i >= 0 ? name.slice(i + 1).trim() : name, sub = i >= 0 ? name.slice(0, i).replace("팀 3계층 · ", "").trim() : "";
      return '<button type="button" role="tab" data-case="' + esc(c.id) + '" aria-selected="' + (c.id === S.caseId) + '">' + esc(title) + "<small>" + esc(sub) + "</small></button>";
    }).join("");
  }

  // ---------- 예제 하나 읽기 ----------
  function loadCase(id) {
    if (S.caseId !== id) { S.sel = ""; }
    S.caseId = id; S.records = {};
    renderCases();
    return Promise.all([api("/api/case?id=" + encodeURIComponent(id)), api("/api/case/candidates?id=" + encodeURIComponent(id))]).then(function (r) {
      S.caseData = r[0] || {};
      S.set = ((r[1] || {}).sets || [])[0] || null;
      var sid = S.set ? S.set.set_id : "";
      return Promise.all([api("/api/candidate/source?set_id=" + encodeURIComponent(sid)), api("/api/llm/runs?set_id=" + encodeURIComponent(sid)), api("/api/records")]);
    }).then(function (r) {
      var sid = S.set ? S.set.set_id : "";
      S.source = r[0] || {};
      S.ai = ((r[1] || {}).runs || []).filter(function (x) { return x.set_id === sid; })[0] || null;
      var rbNames = ((S.set || {}).candidates || []).filter(function (c) { return c.id === "rule-based"; }).map(function (c) { return c.label; });
      S.rb = ((r[2] || {}).records || []).filter(function (x) { return x.set_id === sid && (/규칙 기반/.test(x.label || "") || rbNames.indexOf(x.label) >= 0); })[0] || null;
      return loadRecords();
    }).then(renderAll);
  }

  function featured() {
    return ((S.set || {}).candidates || []).filter(function (c) { return c.featured; })
      .sort(function (a, b) { return String(a.label).localeCompare(String(b.label), "ko", { numeric: true }); });
  }
  function loadRecords() {
    var ids = [];
    featured().forEach(function (c) { if (c.latest) ids.push(c.latest.id); });
    if (S.rb) ids.push(S.rb.id);
    if (S.ai) (S.ai.attempts || []).forEach(function (a) { if (a.record_id) ids.push(a.record_id); });
    return Promise.all(ids.filter(function (id) { return !S.records[id]; }).map(function (id) {
      return api("/api/record?id=" + encodeURIComponent(id)).then(function (rec) { if (rec && rec.id) S.records[id] = rec; });
    }));
  }

  function renderAll() { renderProblem(); renderActions(); renderCards(); buildRows(); renderResults(); renderFigs(); renderDecision(); renderJob(); }

  // ---------- 1. 문제 ----------
  function blockAround(text, line) {
    var lines = String(text || "").split("\n"), lo = line, hi = line;
    while (lo > 1 && !/^(resource|data|module)\s/.test(lines[lo - 1] || "")) lo--;
    if (line - lo > 12) lo = Math.max(1, line - 4);
    while (hi < lines.length && !/^\}/.test(lines[hi - 1] || "")) hi++;
    if (hi - lo > 24) hi = Math.min(lines.length, line + 8);
    return { lines: lines, lo: lo, hi: hi };
  }
  function renderProblem() {
    var c = S.caseData || {}, f = ((c.findings || {}).in_scope || [])[0] || {}, set = (c.sets || [])[0] || {};
    var name = String(c.name || ""), i = name.indexOf("—");
    $("#p-title").textContent = (i >= 0 ? name.slice(i + 1).trim() : name) + " 설정 오류";
    $("#p-summary").textContent = c.summary || "";
    var src = S.source || {}, line = Number(src.line || f.line || 1), b = blockAround(src.original, line), out = [];
    $("#p-file").textContent = (src.file || f.file || "") + "  " + b.lo + "~" + b.hi + "행";
    for (var n = b.lo; n <= b.hi; n++) {
      var L = b.lines[n - 1] || "";
      out.push(n === line || /0\.0\.0\.0\/0|"s3:\*"|"\*"/.test(L) ? '<span class="hl">' + esc(L) + "</span>" : esc(L));
    }
    $("#p-code").innerHTML = out.join("\n");
    $("#p-finding").innerHTML = '<div class="id">Trivy: ' + esc(f.rule_id || set.rule || "") + "</div><p>" + esc(f.message || f.title || "") + "</p>" +
      '<p class="small">Trivy가 붙인 심각도는 ' + esc(f.severity || "-") + "다. 이건 Trivy의 분류이고, 우리 프로그램이 매기는 위험도(아래 4번 결정)와는 다른 기준이다.</p>";
    var iam = set.intent_kind === "iam";
    $("#d-title").textContent = iam ? "설계도: 이 역할에 허용되는 권한" : "설계도: 허용 통신";
    $("#d-desc").textContent = iam ? "팀 설계 문서에서 옮긴 권한 목록이다. 이 밖의 권한이 있으면 설계와 다른 것이다." : "팀 설계 문서에서 옮긴 통신 목록이다. 이 밖의 통신이 열리면 설계와 다른 것이다.";
    $("#d-list").innerHTML = (set.requirements || []).map(function (r) { return "<li>" + esc(r.text || r.label) + "</li>"; }).join("");
    renderConfirm();
  }
  function confirmed() { return !!(((S.set || {}).design_confirmation) || {}).confirmed; }
  function renderConfirm() {
    var c = (S.set || {}).design_confirmation || {};
    if (!S.set) { $("#d-confirm").innerHTML = ""; return; }
    if (c.confirmed) {
      var who = c.basis === "manifest" ? "팀 작성 평가 기준" : (c.by || "");
      $("#d-confirm").innerHTML = '<p class="ok-note">확정된 설계도 v' + esc(c.version || 1) + " · " + esc(who) + (c.at ? " · " + esc(String(c.at).slice(0, 16).replace("T", " ")) : "") + "</p>";
      return;
    }
    $("#d-confirm").innerHTML = '<div class="confirm"><b>설계도 확정 전</b><p class="small">이 목록이 팀 설계 문서와 맞는지 확인한 사람이 이름을 남겨야 검사 기준이 된다. 확정 전 기준으로 검사한 결과는 승인할 수 없다.</p>' +
      '<div class="row"><input type="text" id="cf-name" placeholder="확인한 사람 이름" value="' + esc(savedName()) + '">' +
      '<button class="btn primary" id="cf-btn" type="button"' + (busy() ? " disabled" : "") + ">확정하고 수정안 검사 시작</button></div></div>";
  }

  // ---------- 2. 수정안 ----------
  function busy() { return !!(S.job && S.job.running); }
  function renderActions() {
    if (!S.set) { $("#c-actions").innerHTML = ""; return; }
    var aiOk = S.llm && S.llm.found && S.llm.logged_in !== false, dis = busy() ? " disabled" : "";
    $("#c-actions").innerHTML =
      '<button class="btn primary" type="button" data-act="ai"' + (aiOk ? dis : " disabled") + ' title="' + esc(aiOk ? "Claude Code 가 수정안을 만들고, 막히면 막힌 이유를 붙여 다시 요청한다 (최대 3번)" : "이 PC 에 Claude Code 가 없거나 로그인 안 됨") + '">AI에게 고치게 하기</button>' +
      '<button class="btn" type="button" data-act="rule"' + dis + ' title="AI 없이 정해진 규칙으로 고친다 (비교용)">규칙 기반으로 고치기</button>' +
      '<button class="btn" type="button" data-act="all"' + (confirmed() ? dis : " disabled") + ' title="' + (confirmed() ? "아직 검사 안 한 수정안을 차례로 검사" : "1번에서 설계도를 확정해야 검사할 수 있다") + '">보이는 수정안 모두 검사</button>';
  }
  function diffLines(diff) {
    var rows = String(diff || "").split("\n").filter(function (l) { return /^[+-]/.test(l) && !/^(\+\+\+|---)/.test(l); });
    var more = rows.length > 14 ? '\n<span class="ctx">… ' + (rows.length - 14) + "줄 더</span>" : "";
    return rows.slice(0, 14).map(function (l) { return '<span class="' + (l[0] === "+" ? "add" : "del") + '">' + esc(l) + "</span>"; }).join("\n") + more;
  }
  function resultPill(rec) {
    var st = (rec && rec.state) || {};
    if (!rec) return pill("mute", "검사 전");
    if (unsupported(rec)) return pill("mute", "고칠 수 없음");
    if (st.level === "BLOCKED") return pill("fail", "차단");
    if (passLevel(rec) && draft(rec)) return pill("mute", "초안 기준 통과");
    if (passLevel(rec)) return pill("warn", "통과 · 사람 검토로");
    if (st.level === "PENDING") return pill("mute", "판정 보류");
    if (st.level === "REPORT_ONLY") return pill("mute", "보고만");
    return pill("mute", st.level_ko || st.ko || "기록 있음");
  }
  function renderCards() {
    if (!S.set) { $("#c-cards").innerHTML = '<p class="empty">이 예제에는 수정안이 없다.</p>'; return; }
    var cards = featured().map(function (c) {
      var rec = c.latest ? S.records[c.latest.id] : null;
      var stale = rec && confirmed() && draft(rec);
      var body = rec ? '<div class="code"><pre>' + diffLines(rec.diff) + "</pre></div>" : '<p class="small">' + esc(c.summary || "") + " · 아직 검사 전</p>";
      var origin = (c.origin && c.origin.label) || "팀 작성";
      return '<article class="card' + (rec && rec.id === S.sel ? " sel" : "") + '"><div class="card-head"><span class="n">' + esc(c.label) + ' <span class="small">· ' + esc(origin) + "</span></span>" + resultPill(rec) + "</div>" + body +
        (stale ? '<p class="small">설계도를 확정하기 전에 검사한 결과다. 다시 검사해야 승인할 수 있다.</p>' : "") +
        '<div class="actions"><button class="btn" type="button" data-act="check" data-cid="' + esc(c.id) + '"' + (busy() ? " disabled" : "") + ">" + (rec ? "다시 검사" : "검사하기") + "</button>" +
        (rec ? '<button class="btn" type="button" data-act="pick" data-rid="' + esc(rec.id) + '">결과 보기</button>' : "") + "</div></article>";
    });
    if (S.rb) {
      var rr = S.records[S.rb.id];
      cards.push('<article class="card' + (rr && rr.id === S.sel ? " sel" : "") + '"><div class="card-head"><span class="n">규칙 기반 <span class="small">· AI 없이 정해진 규칙으로 생성</span></span>' + resultPill(rr) + "</div>" +
        (rr && rr.diff ? '<div class="code"><pre>' + diffLines(rr.diff) + "</pre></div>" : rr ? '<p class="small">' + esc(refs((rr.conclusion || {}).title || "")) + '</p><p class="small mono">' + esc((rr.conclusion || {}).reason || "") + "</p>" : "") +
        (rr ? '<div class="actions"><button class="btn" type="button" data-act="pick" data-rid="' + esc(rr.id) + '">결과 보기</button></div>' : "") + "</article>");
    }
    if (S.ai) {
      var at = S.ai.attempts || [], fin = S.ai.final_record_id ? S.records[S.ai.final_record_id] : null;
      var steps = at.map(function (a) { return "<li>시도 " + esc(a.n) + ": " + esc(refs(a.title || a.status)) + "</li>"; }).join("");
      var p = S.ai.status === "PASSED" ? pill("warn", "통과 · 사람 검토로") : S.ai.status === "UNDECIDABLE" ? pill("mute", "판정 보류") : pill("fail", String(S.ai.status_ko || S.ai.status || "").split(" — ")[0]);
      cards.unshift('<article class="card' + (fin && fin.id === S.sel ? " sel" : "") + '"><div class="card-head"><span class="n">AI 수정 <span class="small">· Claude Code · ' + esc(String(S.ai.started_at || "").slice(5, 16).replace("T", " ")) + "</span></span>" + p + "</div>" +
        (steps ? '<ul class="plain small">' + steps + "</ul>" : "") + (fin ? '<div class="code"><pre>' + diffLines(fin.diff) + "</pre></div>" : "") +
        (S.ai.status !== "PASSED" && S.ai.next ? '<p class="small">' + esc(refs(S.ai.next)) + "</p>" : "") +
        (fin ? '<div class="actions"><button class="btn" type="button" data-act="pick" data-rid="' + esc(fin.id) + '">결과 보기</button></div>' : "") + "</article>");
    }
    $("#c-cards").innerHTML = cards.join("");
  }

  // ---------- 3. 검사 결과 ----------
  function lay(rec, name) { return ((rec && rec.layers) || []).filter(function (l) { return l.layer === name; })[0] || null; }
  function group(rec, names) {
    var ls = names.map(function (n) { return lay(rec, n); }).filter(Boolean);
    if (!ls.length) return { v: "NONE" };
    var bad = ls.filter(function (l) { return l.verdict === "FAIL"; })[0];
    if (bad) return { v: "FAIL", l: bad };
    if (ls.every(function (l) { return l.verdict === "PASS" || l.verdict === "WARN"; })) return { v: "PASS" };
    if (ls.every(function (l) { return l.verdict === "NOT_RUN" || l.verdict === "SKIPPED"; })) return { v: "NOT_RUN", l: ls[0] };
    return { v: "UNKNOWN", l: ls.filter(function (l) { return l.verdict !== "PASS"; })[0] };
  }
  var CELL = { PASS: ["pass", "통과"], FAIL: ["fail", "실패"], NOT_RUN: ["mute", "안 함"], UNKNOWN: ["mute", "판정 불가"], NONE: ["mute", "안 함"] };
  function cell(g, cls, why) {
    var m = CELL[g.v] || CELL.NONE;
    var w = why != null ? why : (g.l && g.v !== "PASS" ? String(g.l.summary || "").slice(0, 160) : "");
    return '<td class="' + (cls || "") + '">' + pill(m[0], m[1]) + (w ? '<span class="why">' + esc(w) + "</span>" : "") + "</td>";
  }
  function buildRows() {
    var rows = [];
    featured().forEach(function (c) { var r = c.latest && S.records[c.latest.id]; if (r) rows.push({ label: c.label, sub: (c.origin && c.origin.label) || "팀 작성", rec: r, kind: "team" }); });
    if (S.rb && S.records[S.rb.id]) rows.push({ label: "규칙 기반", sub: "AI 없이 규칙으로 생성", rec: S.records[S.rb.id], kind: "rule" });
    if (S.ai) (S.ai.attempts || []).forEach(function (a) { var r = S.records[a.record_id]; if (r) rows.push({ label: "AI · 시도 " + a.n, sub: "Claude Code", rec: r, kind: "ai" }); });
    S.rows = rows;
  }
  function renderResults() {
    if (!S.rows.length) {
      $("#r-body").innerHTML = '<tr><td colspan="5" class="empty">아직 검사한 수정안이 없다. 1번에서 설계도를 확정하거나 2번에서 검사하기를 누른다.</td></tr>';
      $("#r-callout").innerHTML = ""; return;
    }
    $("#r-body").innerHTML = S.rows.map(function (row) {
      var rec = row.rec, pol = rec.policy || {}, c = rec.conclusion || {}, polBlock = pol.ok === false;
      var tri = group(rec, ["V1", "V2"]), mid = group(rec, ["V3", "V4", "V5"]), v6 = group(rec, ["V6"]);
      var v6why = v6.v === "PASS" ? "설계도와 같음" : v6.v === "FAIL" ? v6text((v6.l || {}).summary) : polBlock ? "정책에서 먼저 막힘" : unsupported(rec) ? "수정안이 없어 검사 안 함" : String((v6.l || {}).summary || "");
      var resWhy = unsupported(rec) ? refs(c.title || "") : polBlock ? "정책 위반: " + String((pol.violations || [])[0] || "").slice(0, 120) : draft(rec) ? "설계도 확정 전 기준" : rec.risk && rec.risk.level ? "위험도 " + (rec.risk.level_ko || rec.risk.level) + (rec.risk.score != null ? " · " + rec.risk.score + "점" : "") : refs(c.headline || "");
      return '<tr data-rid="' + esc(rec.id) + '" class="' + (rec.id === S.sel ? "sel" : "") + '" tabindex="0"><td class="cand"><b>' + esc(row.label) + "</b><span>" + esc(row.sub) + "</span></td>" +
        cell(polBlock && tri.v === "NONE" ? { v: "NOT_RUN" } : tri, "trivy", polBlock && tri.v === "NONE" ? "정책에서 먼저 막힘" : null) +
        cell(mid, "", polBlock && mid.v !== "PASS" ? "" : null) +
        cell(v6, "v6", v6why.slice(0, 200)) +
        "<td>" + resultPill(rec) + '<span class="why">' + esc(resWhy) + "</span></td></tr>";
    }).join("");
    var team = S.rows.filter(function (r) { return r.kind === "team"; }), n = team.length;
    var tp = team.filter(function (r) { return group(r.rec, ["V1", "V2"]).v === "PASS"; }).length;
    var op = team.filter(function (r) { return passLevel(r.rec); }).length;
    $("#r-callout").innerHTML = n ? '<div class="big">팀 수정안 ' + n + "개: Trivy 다시 검사만 보면 " + tp + "개 통과, 설계도 비교까지 하면 " + op + "개 통과.</div>" +
      '<p class="sub">Trivy 규칙은 정해진 위험 표기(예: 0.0.0.0/0, s3:*)가 남았는지를 본다. V6는 수정 뒤 실제로 열리는 통신 · 권한을 계산해서 설계도와 비교한다.</p>' : "";
  }
  function renderFigs() {
    var team = S.rows.filter(function (r) { return r.kind === "team"; }), n = team.length;
    if (!n) { $("#figs").innerHTML = ""; return; }
    var tp = team.filter(function (r) { return group(r.rec, ["V1", "V2"]).v === "PASS"; }).length;
    var op = team.filter(function (r) { return passLevel(r.rec); }).length;
    var ai = S.rows.filter(function (r) { return r.kind === "ai"; }), ap = ai.filter(function (r) { return passLevel(r.rec); }).length;
    var fig = function (cls, k, v, d) { return '<div class="fig ' + cls + '"><div class="k">' + esc(k) + '</div><div class="v">' + v + '</div><div class="d">' + esc(d) + "</div></div>"; };
    $("#figs").innerHTML = fig("bad", "Trivy 다시 검사만 보면", tp + " <small>/ " + n + " 통과</small>", "팀 수정안 중 Trivy 지적이 사라진 것") +
      fig("good", "설계도 비교까지 하면", op + " <small>/ " + n + " 통과</small>", (n - op) + "개는 차단 · 보류, " + op + "개만 사람 검토로") +
      fig("ai", "AI(Claude Code) 수정", ai.length ? ap + " <small>/ " + ai.length + " 시도 통과</small>" : "-", ai.length ? "가장 최근 AI 실행 (막히면 이유를 붙여 다시 요청)" : "아직 AI 실행 없음");
  }

  // ---------- 4. 결정 ----------
  function fval(v) { return Array.isArray(v) ? v.join(", ") : v === true ? "예" : v === false ? "아니오" : String(v); }
  function renderDecision() {
    var rec = S.records[S.sel];
    if (!rec) { $("#x-panel").innerHTML = '<p class="small">3번 표에서 수정안 줄을 누르면 여기에 나온다.</p>'; return; }
    var row = S.rows.filter(function (r) { return r.rec.id === rec.id; })[0] || {};
    var c = rec.conclusion || {}, r = rec.risk || {}, st = rec.state || {}, seen = {};
    var factors = (r.factors || []).filter(function (f) { var k = f.name + "|" + fval(f.value); if (!f.points || seen[k]) return false; seen[k] = 1; return true; })
      .map(function (f) { return "<li>" + esc(f.name) + ": " + esc(fval(f.value)) + " → " + esc(f.points) + "점</li>"; }).join("");
    var lv = r.level === "LOW" ? "pass" : r.level === "MEDIUM" ? "warn" : r.level === "HIGH" ? "fail" : "mute";
    var needAck = !c.can_approve && passLevel(rec) && !draft(rec) && /실제 AWS 미검증/.test(c.approve_blocked_reason || "");
    var html = '<p class="small">' + esc(row.label || rec.candidate_label || "") + "</p><h3>" + esc(refs(c.title || st.ko || "")) + "</h3><p>" + esc(refs(c.reason || c.headline || "")) + "</p>" +
      "<p>" + (r.level ? pill(lv, "위험도 " + (r.level_ko || r.level) + (r.score != null ? " · " + r.score + "점" : "")) + " " : "") + resultPill(rec) + "</p>" +
      (factors ? '<ul class="plain small">' + factors + "</ul>" : "") +
      (rec.decision_ko ? '<p class="ok-note">기록된 결정: ' + esc(rec.decision_ko) + ((rec.decision || {}).by ? " · " + esc(rec.decision.by) : "") + "</p>" : "");
    var done = ["APPROVED", "DISCARDED"].indexOf(String((rec.decision || {}).decision || "")) >= 0;
    if (done) {
      html += '<p class="small">결정이 기록됐다. 결정 기록과 PR 초안은 이 PC의 data/reviews/' + esc(rec.id) + " 에 있다.</p>";
    } else if (c.can_approve || needAck) {
      html += '<div class="confirm"><b>사람의 결정</b><div class="row"><input type="text" id="dc-name" placeholder="결정한 사람 이름" value="' + esc(savedName()) + '"></div>' +
        '<textarea id="dc-reason" placeholder="이유 (예: 바뀐 줄과 검사 표를 확인함)"></textarea>' +
        (needAck ? '<label class="small"><input type="checkbox" id="dc-ack"> 실제 AWS 확인(V7 · V8)은 하지 않았다는 걸 알고 승인한다. 이 사실은 결정 기록과 PR 초안에 남는다.</label>' : "") +
        '<div class="row"><button class="btn good" type="button" data-dec="APPROVED">승인</button><button class="btn" type="button" data-dec="CHANGES_REQUESTED">수정 요청</button>' +
        '<button class="btn bad" type="button" data-dec="DISCARDED">폐기</button></div><p class="small">승인하면 결정 기록과 PR 초안만 만든다. AWS에는 아무것도 적용하지 않는다.</p></div>';
    } else if (c.approve_blocked_reason) {
      html += '<p class="small">승인할 수 없음: ' + esc(refs(c.approve_blocked_reason)) + "</p>";
    }
    $("#x-panel").innerHTML = html;
  }

  // ---------- 작업 (검사 · AI 수정) ----------
  function startJob(path, body) {
    return api(path, body).then(function (j) {
      if (!j.started) { alertBox(j.error || ((j.job || {}).running ? "다른 작업이 진행 중이다" : "시작하지 못함")); return; }
      S.job = j.job || { running: true }; S.logSince = 0; S.lastLog = "";
      renderJob(); renderActions(); renderCards(); renderConfirm(); poll();
    });
  }
  function poll() {
    api("/api/log?since=" + S.logSince).then(function (j) {
      S.job = j; S.logSince = j.log_total || S.logSince;
      if (j.log && j.log.length) S.lastLog = String(j.log[j.log.length - 1]);
      renderJob();
      if (j.running) { setTimeout(poll, 1000); return; }
      if (j.error) alertBox("작업 실패: " + j.error);
      var rid = (j.result || {}).record_id || "";
      if (j.name === "setup_tools") refreshTools(false);
      loadCase(S.caseId).then(function () {
        if (rid && S.records[rid]) { S.sel = rid; renderAll(); }
      });
    });
  }
  function renderJob() {
    var el = $("#job"), j = S.job;
    if (!j || !j.running) { if (!el.dataset.msg) el.hidden = true; return; }
    var p = j.progress || [0, 0], pct = p[1] ? Math.max(5, Math.round(100 * p[0] / p[1])) : 8;
    var name = { review: "검사 중", llm_fix: "AI 수정 중", prefetch: "수정안 검사 중", setup_tools: "검사 도구 준비 중" }[j.name] || "작업 중";
    el.hidden = false;
    el.innerHTML = '<span class="bar"><i style="width:' + pct + '%"></i></span><span class="txt">' + esc(name + (S.lastLog ? " · " + S.lastLog : "")) + "</span>";
  }
  function alertBox(msg) {
    var el = $("#job");
    el.hidden = false; el.dataset.msg = "1";
    el.innerHTML = '<span class="txt" style="color:var(--fail)">' + esc(refs(msg)) + "</span>";
    setTimeout(function () { delete el.dataset.msg; if (!busy()) el.hidden = true; }, 9000);
  }

  // ---------- 클릭 ----------
  function pick(rid, scroll) {
    S.sel = rid; renderResults(); renderCards(); renderDecision();
    if (scroll) $("#decision").scrollIntoView({ behavior: "smooth" });
  }
  document.addEventListener("click", function (e) {
    var t = e.target.closest("button, tr[data-rid]");
    if (!t || t.disabled) return;
    if (t.dataset.case) { location.hash = "case-" + t.dataset.case; loadCase(t.dataset.case); return; }
    if (t.id === "cf-btn") {
      var nm = ($("#cf-name").value || "").trim();
      if (!nm) { $("#cf-name").focus(); return; }
      saveName(nm);
      api("/api/design/confirm", { set_id: S.set.set_id, by: nm, note: "시연 화면에서 설계도 목록을 확인하고 확정" }).then(function (r) {
        if (!r.ok) { alertBox((r.errors || [r.error || "확정 실패"]).join(" ")); return; }
        loadCase(S.caseId).then(function () { startJob("/api/review/prefetch", { case_id: S.caseId, set_id: S.set.set_id }); });
      });
      return;
    }
    if (t.dataset.act === "tools") { startJob("/api/job/setup_tools", {}); return; }
    var sid = S.set && S.set.set_id;
    if (t.dataset.act === "check") { startJob("/api/review", { case_id: S.caseId, set_id: sid, candidate_id: t.dataset.cid }); return; }
    if (t.dataset.act === "rule") { startJob("/api/review", { case_id: S.caseId, set_id: sid, generator: "rule_based" }); return; }
    if (t.dataset.act === "all") { startJob("/api/review/prefetch", { case_id: S.caseId, set_id: sid }); return; }
    if (t.dataset.act === "ai") { startJob("/api/llm/fix", { set_id: sid, context: "trivy" }); return; }
    if (t.dataset.act === "pick") { pick(t.dataset.rid, true); return; }
    if (t.tagName === "TR") { pick(t.dataset.rid, false); return; }
    if (t.dataset.dec) {
      var by = ($("#dc-name").value || "").trim(), why = ($("#dc-reason").value || "").trim(), ack = $("#dc-ack");
      if (!by) { $("#dc-name").focus(); return; }
      if (t.dataset.dec === "APPROVED" && ack && !ack.checked) { alertBox("승인하려면 '실제 AWS 확인은 하지 않았다' 확인 칸을 체크해야 한다"); return; }
      saveName(by);
      api("/api/decision", { record_id: S.sel, decision: t.dataset.dec, reason: why, by: by, ack_unverified: !!(ack && ack.checked) }).then(function (r) {
        if (!r.ok) alertBox(r.error || "결정 기록 실패");
        delete S.records[S.sel];
        loadRecords().then(function () { buildRows(); renderResults(); renderCards(); renderDecision(); });
      });
    }
  });
  document.addEventListener("keydown", function (e) {
    var t = e.target;
    if ((e.key === "Enter" || e.key === " ") && t && t.matches && t.matches("tr[data-rid]")) { e.preventDefault(); pick(t.dataset.rid, false); }
  });

  // 서버가 화면이 열려 있는 걸 알게 (기존 화면과 같은 방식) — 화면을 닫으면 잠시 뒤 서버가 끝난다
  function beat() { fetch("/api/heartbeat", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }).catch(function () {}); }
  setInterval(beat, 30000); beat();
  init();
})();
