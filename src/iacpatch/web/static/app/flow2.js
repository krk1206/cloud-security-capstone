// 실제 AWS 검사(5단계) 진행 안내 — 지금 시험 환경 상태에서 '다음 작업' 하나를 정한다.
// 화면(DOM)을 다루지 않는 순수 함수 — tests/unit/test_flow2_js.py 가 node 로 직접 부른다.
// 안내가 고르는 동작: plan 계산(반영 준비) · plan 확인 · 측정 · 확인 창 열기 · 후보 선택 화면 이동.
// apply · destroy 실행은 하지 않는다 — 확인 창에서 사람이 plan 을 검토하고 [실행] 을 눌러야 반영된다 (D-19).
// 9차(D-43): 흐름 화면 ⑦ 도 이 함수로 '다음 작업' 을 정한다. 문장은 전문가 화면 말(후보 · 배포)이라, 흐름 화면은 key 로 자기 말(수정안 · 반영)을 고른다.

export const STEPS = ["원본 배포", "수정 전 측정", "후보 반영", "수정 후 측정", "시험 환경 삭제"];
export const WAIT_BEFORE_S = 180;   // 원본 apply 뒤 수정 전 측정까지 (서버 시작·측정 지점 출력에 배포 설정이 반영되는 시간)
export const WAIT_AFTER_S = 130;    // 후보 apply 뒤 수정 후 측정까지 (서버 기준 최소 120초 + 여유)
export const ACTIONS = ["s2-deploy", "s2-measure", "s2-cand", "s2-open-apply", "s2-destroy", "s2-pick", "s2-decide"];

export const mmss = (s) => { const v = Math.max(0, Math.ceil(Number(s) || 0)); return `${Math.floor(v / 60)}:${String(v % 60).padStart(2, "0")}`; };

const RESULT_WORD = { VERIFIED: "통과", DEPLOY_FAILED: "실패", PLAN_BLOCKED: "차단", UNVERIFIED: "판정 불가" };

// cur: 지금 단계(1~5, 0 = 해당 없음, 6 = 모두 끝남) · marks: 진행하지 않은 단계 표시 {단계: "bad"(차단) | "skip"(미실행)}
// 진행 표시의 ✓ 는 '단계 진행' 이지 '통과' 가 아니다. 차단·미실행 단계는 ✓ 로 그리지 않는다.
// key: 상황 이름 (화면이 자기 말로 문장을 고를 때 씀) — 같은 cur · act 라도 상황이 다르면 key 가 다르다
function plan(cur, title, text, primary = null, extra = {}) {
  return { cur, title, text, primary, secondary: extra.secondary || [], wait: extra.wait || null, tone: extra.tone || "", marks: extra.marks || {}, key: extra.key || "", result: extra.result || "" };
}
const BLOCKED_MARKS = { 3: "bad", 4: "skip" };

// m: /api/measure/setup 응답 · rec: 열린 기록 (없으면 null) · passed: 배포 전 검사 통과 여부 · post: 실제 AWS 검사 결과 요약 {before, after}
// running: 실행 중인 작업 {kind, label} · now: 지금 시각(ms) · fetchedAt: m 을 받은 시각(ms)
export function stage2Plan({ m, rec = null, passed = false, post = {}, running = null, now = Date.now(), fetchedAt = now }) {
  const base = core({ m, rec, passed, post: post || {}, now, fetchedAt });
  if (running && m && !m.error) {
    return { ...base, title: `작업 실행 중 — ${running.label || running.kind || ""}`, text: "진행 상황은 실행 로그에 표시. 완료 후 다음 작업 안내", primary: null, secondary: [], wait: null, tone: "", key: "running" };
  }
  return base;
}

function core({ m, rec, passed, post, now, fetchedAt }) {
  if (!m) return plan(0, "시험 환경 상태 확인 중", "시험 환경 폴더와 상태 파일 조회 중", null, { key: "checking" });
  if (m.error) return plan(0, "시험 환경 상태 조회 실패", String(m.error), null, { tone: "bad", key: "error" });
  if (!m.exists) return plan(0, "시험 환경 폴더 없음", `${m.testbed || "시험 환경"} 폴더가 없어 실제 AWS 검사 진행 불가`, null, { tone: "bad", key: "no_folder" });
  if (!m.tf_inited) return plan(1, "terraform init 필요", "시험 환경 폴더에서 terraform init 1회 실행 필요 (사람이 PowerShell 에서 실행 — 명령은 '수동 조작' 참고)", null, { tone: "warn", key: "need_init" });

  const since = m.since_apply_s == null ? null : Number(m.since_apply_s) + Math.max(0, (now - fetchedAt) / 1000);
  const applyAt = since == null ? null : now - since * 1000;
  const afterApply = (iso) => !!iso && applyAt != null && Date.parse(iso) >= applyAt - 2000;
  const settle = Number(m.settle_s || 120);
  const cand = !!(rec && passed && m.record_case_ok !== false);
  const pa = (post && post.after) || {};
  const recBlocked = pa.status === "PLAN_BLOCKED" || ((rec && rec.post_deploy) || {}).status === "PLAN_BLOCKED";
  const pick = { act: "s2-pick", label: rec ? "다른 후보 선택" : "후보 선택 (3단계)" };
  const destroy = { act: "s2-destroy", label: "시험 환경 삭제 (destroy)", danger: true };
  const deploy = (label = "원본 배포 시작") => ({ act: "s2-deploy", label });
  const measureBtn = (kind, ready) => ({ act: "s2-measure", kind, label: kind === "before" ? "수정 전 측정" : "수정 후 측정",
    disabled: !ready || !m.aws_cli, why: !m.aws_cli ? "AWS CLI 없음 — 측정 불가" : !ready ? `apply 후 ${settle}초 경과 전 측정 불가` : "" });

  // 1) 배포 없음 (상태 파일 없음 · 리소스 0개)
  if (!m.deployed_state_file) {
    if (rec && pa.dir && pa.status) {
      const w = RESULT_WORD[pa.status] || pa.status;
      return plan(6, `실제 AWS 검사 완료 — ${w}`, "시험 환경 삭제 상태. 재측정이 필요하면 원본 배포부터 다시 진행",
        pa.status === "VERIFIED" ? { act: "s2-decide", label: "승인 결정으로 →" } : pick,
        { secondary: [deploy("원본 배포 (재측정)")], tone: pa.status === "VERIFIED" ? "ok" : "bad", marks: pa.status === "PLAN_BLOCKED" ? BLOCKED_MARKS : {}, key: "done", result: pa.status });
    }
    return plan(1, m.destroyed ? "시험 환경 삭제 상태 — 원본 배포 필요" : "원본 배포 필요",
      "원본 보안 그룹으로 시험 환경 배포. plan 계산 후 확인 창 표시 — 사람이 plan 을 검토하고 [apply 실행]을 눌러야 반영", deploy(), { key: "deploy" });
  }
  // 2) 파일 내용이 배포 상태와 다름 (apply 전) — 같은 내용으로 다시 쓴 경우는 서버가 내용으로 판단해 여기 오지 않는다
  if (!m.applied_after_change) {
    const pre = afterApply((post.before || {}).at) ? {} : { 2: "skip" };
    if (m.is_record_candidate && cand) {
      if (m.plan_blocked) return plan(5, "후보 반영 차단 — plan 에 교체·삭제 포함", "이 후보는 반영하지 않음 (실제 AWS 검사 결과: 차단). 시험 환경 삭제 후 다른 후보 선택", destroy, { secondary: [pick], tone: "bad", marks: { ...pre, ...BLOCKED_MARKS }, key: "cand_blocked" });
      if (m.plan_ready) return plan(3, "후보 반영 — 사람 확인 대기", "plan 확인 결과: 보안 그룹 제자리 수정만 포함. 확인 창에서 plan 검토 후 실행", { act: "s2-open-apply", label: "후보 반영 확인 창 열기" }, { marks: pre, key: "cand_open_apply" });
      return plan(3, "후보 반영", "이 기록의 후보 파일로 plan 확인 실행 → 보안 그룹 제자리 수정만 포함되면 확인 창 표시", { act: "s2-cand", label: "후보 반영 시작" }, { marks: pre, key: "cand_start" });
    }
    // 다른 파일(다른 기록의 후보 등)이 들어 있음 — 이 기록이 배포 전 검사 통과 후보면 이 후보로 교체해 진행 (plan 은 실제 배포 상태 기준)
    if (cand && recBlocked) return plan(5, "후보 반영 차단 기록 있음", "이 후보는 plan 확인에서 교체·삭제가 나와 반영하지 않음 (실제 AWS 검사 결과: 차단). 시험 환경 삭제 후 다른 후보 선택", destroy, { secondary: [pick], tone: "bad", marks: BLOCKED_MARKS, key: "rec_blocked" });
    if (cand) return plan(3, "후보 반영", "시험 환경 파일이 배포 상태와 다름 (apply 전). 이 기록의 후보 파일로 교체 후 plan 확인 실행 → 보안 그룹 제자리 수정만 포함되면 확인 창 표시", { act: "s2-cand", label: "후보 반영 시작" }, { secondary: [deploy("원본 재배포")], marks: pre, key: "cand_start" });
    return plan(1, "배포 상태와 다른 파일", "시험 환경 파일이 배포 상태와 다름 (apply 전). 원본 재배포 또는 시험 환경 삭제 필요", deploy("원본 재배포"), { secondary: [destroy], tone: "warn", key: "file_differs" });
  }
  // 3) 원본 배포 상태
  if (m.is_original) {
    if (!afterApply((post.before || {}).at)) {
      const left = WAIT_BEFORE_S - (since || 0);
      const btn = measureBtn("before", (since || 0) >= settle);
      if (left > 0) return plan(2, "수정 전 측정 대기", `원본 배포 직후 — 측정 지점 결과에 배포 설정이 반영되도록 ${WAIT_BEFORE_S / 60}분 대기 (${settle}초 경과 후 수동 측정 가능)`, btn, { wait: { left, total: WAIT_BEFORE_S, kind: "before" }, key: "measure_before_wait" });
      return plan(2, "수정 전 측정", "원본 배포 상태의 AWS 적용 규칙(V7)과 통신 시험(V8) 측정. 설정 변경 없음", btn, { key: "measure_before" });
    }
    if (rec && recBlocked) return plan(5, "후보 반영 차단 기록 있음", "이 후보는 plan 확인에서 교체·삭제가 나와 반영하지 않음 (실제 AWS 검사 결과: 차단). 시험 환경 삭제 후 다른 후보 선택", destroy, { secondary: [pick], tone: "bad", marks: BLOCKED_MARKS, key: "rec_blocked" });
    if (cand) return plan(3, "후보 반영", "수정 전 측정 완료. 이 기록의 후보 파일을 시험 환경에 넣고 plan 확인 실행 → 보안 그룹 제자리 수정만 포함되면 확인 창 표시", { act: "s2-cand", label: "후보 반영 시작" }, { secondary: [destroy], key: "cand_start" });
    if (rec && !passed) return plan(3, "실제 AWS 검사 대상 아님", "배포 전 검사 미통과 후보는 시험 환경에 반영하지 않음. 다른 후보 선택 또는 시험 환경 삭제", pick, { secondary: [destroy], tone: "warn", key: "pick_not_passed" });
    return plan(3, "후보 선택 필요", "수정 전 측정 완료. 배포 전 검사를 통과한 후보 기록을 열면 후보 반영 단계로 진행", pick, { secondary: [destroy], key: "pick" });
  }
  // 4) 이 기록의 후보 배포 상태
  if (m.is_record_candidate && cand) {
    if (!(afterApply(pa.at) && pa.status !== "PLAN_BLOCKED")) {
      const left = WAIT_AFTER_S - (since || 0);
      const btn = measureBtn("after", (since || 0) >= settle);
      if (left > 0) return plan(4, "수정 후 측정 대기", `후보 반영 직후 — 변경된 보안 그룹이 측정 지점 결과에 반영되도록 대기 (${settle}초 경과 후 수동 측정 가능)`, btn, { wait: { left, total: WAIT_AFTER_S, kind: "after" }, key: "measure_after_wait" });
      return plan(4, "수정 후 측정", "후보 반영 상태의 AWS 적용 규칙(V7)과 통신 시험(V8) 측정. 설정 변경 없음", btn, { key: "measure_after" });
    }
    const w = RESULT_WORD[pa.status] || pa.status || "기록 없음";
    return plan(5, "시험 환경 삭제", `수정 후 측정 완료 (결과: ${w}). 비용 발생 방지를 위해 시험 환경 삭제`, destroy, { tone: pa.status === "VERIFIED" ? "ok" : pa.status ? "bad" : "", key: "destroy", result: pa.status || "" });
  }
  // 5) 다른 파일 배포 상태
  if (cand && !m.plan_blocked && !recBlocked) {
    return plan(3, "후보 반영", "다른 파일이 배포된 상태. 이 기록의 후보 파일로 plan 확인 후 반영", { act: "s2-cand", label: "후보 반영 시작" }, { secondary: [destroy], key: "cand_start" });
  }
  return plan(5, "다른 파일이 배포된 상태", "이 기록과 무관한 파일이 배포됨. 시험 환경 삭제 또는 원본 재배포", destroy,
    { secondary: [deploy("원본 재배포")], tone: "warn", marks: cand && (m.plan_blocked || recBlocked) ? BLOCKED_MARKS : { 3: "skip", 4: "skip" }, key: "other_file" });
}
