"""화면용 설명문 — 코드가 낸 판정(계층 결과·오라클 결과·검토 수준)을 사용자가 읽는 문장으로 바꾼다.

이 모듈은 판정을 **바꾸지 않는다**. 입력은 기록 파일(verification.json / risk.json / policy.json / state.json)의 값이고,
출력은 그 값을 가리키는 문장과 표시명이다. 코드 상태 이름은 details 로 함께 넘겨 상세 화면에서 원문을 볼 수 있게 한다.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# ----------------------------------------------------------------------------- 표시명
VERDICT_KO = {
    "PASS": "통과", "WARN": "통과(경고)", "FAIL": "실패", "UNKNOWN": "판정 불가",
    "SKIPPED": "건너뜀", "ERROR": "오류", "NOT_RUN": "미실행",
}

LAYER_QUESTION = {
    "V1": "원본 Trivy 탐지 항목이 해소되었는가",
    "V2": "신규 보안 문제가 생기지 않았는가",
    "V3": "Terraform 구문·속성·참조가 유효한가",
    "V4": "실행 계획(plan)을 생성할 수 있는가",
    "V5": "허용 범위 내 변경인가",
    "V6": "허용 통신이 설계 기준과 일치하는가",
    "V7": "AWS 적용 규칙이 설계 기준과 일치하는가",
    "V8": "통신 시험 결과가 기대와 일치하는가",
}


def _plain_summary(layer: str, summary: Any) -> str:
    """검사 단계 요약(영어 위반 문장 포함) → 화면 문장. 판정 값은 그대로."""
    t = str(summary or "")
    if layer == "V5":
        from ..proof.cards import violation_ko
        return "; ".join(violation_ko(x.strip(), None) for x in t.split(";") if x.strip())
    if layer in ("V3", "V4"):      # terraform 오류 원문(영어) → 요약 한 줄
        from ..proof.plain import tf_error_ko
        return tf_error_ko(t)
    return t
# 결론 한 줄에 쓰는 단계 이름 (짧게)
LAYER_SHORT = {"V1": "기존 보안 문제 해결", "V2": "새 보안 문제", "V3": "코드 작성 오류", "V4": "변경 예정 계산", "V5": "수정 허용 범위", "V6": "고객 설계 일치",
               "V7": "시험 환경 적용", "V8": "시험 환경 연결 시험"}
LAYER_PHASE = {"V1": "배포 전", "V2": "배포 전", "V3": "배포 전", "V4": "배포 전", "V5": "배포 전", "V6": "배포 전", "V7": "배포 후", "V8": "배포 후"}
LAYER_TOOL = {"V1": "Trivy", "V2": "Trivy", "V3": "Terraform", "V4": "Terraform", "V5": "plan 비교", "V6": "허용 집합 계산", "V7": "AWS 조회", "V8": "통신 시험"}

ORIGIN_KO = {
    "rule_based": ("규칙 기반", "정해진 규칙으로 생성한 수정안 (AI 아님)"),
    "manual": ("팀 작성", "팀원이 미리 작성한 수정안 (AI 생성 아님)"),
    "seeded": ("팀 작성", "팀원이 미리 작성한 수정안 (AI 생성 아님)"),
    "mock": ("팀 작성", "미리 작성한 고정 응답 (AI 생성 아님)"),
    "paste": ("직접 제출", "화면에서 제출한 수정 코드 (사람 작성 · AI 출력 모두 가능)"),
    "llm": ("AI 수정안", "AI(Claude) 생성 수정안 — 동일 검증 적용"),
}
_AI_CODES = ("llm", "claude-code", "claude", "ai")

RISK_KO = {"LOW": "낮음", "MEDIUM": "중간", "HIGH": "높음"}

STATE_KO = {
    "INPUT_ERROR": "검토 시작 불가 — 입력 오류",
    "NO_FINDING": "검토 시작 불가 — 대상 없음",
    "AMBIGUOUS_FINDING": "검토 시작 불가 — 대상 복수",
    "CANDIDATE_INVALID": "수정안 사용 불가",
    "INFO_INSUFFICIENT": "수정안 사용 불가 — 정보 부족",
    "POLICY_BLOCKED": "차단 — 정책 허용 범위 밖",
    "VALIDATION_FAILED": "차단 — 검증 실패",
    "REVIEW_REQUIRED": "검토 자료 준비 완료",
    "INPUT_READY": "진행 중", "CANDIDATE_READY": "진행 중", "VALIDATION_PENDING": "진행 중",
}
LEVEL_KO = {
    "LIGHT_REVIEW": "통과 — 경량 검토",
    "FULL_REVIEW": "통과 — 정식 검토",
    "REPORT_ONLY": "리포트만 — 반영 금지",
    "PENDING": "판정 불가 — 미검증 단계 존재",
    "BLOCKED": "차단",
}
POST_KO = {
    "VERIFIED": "AWS 시험 환경 검사 통과 (운영 반영 후 확인 아님)",
    "DEPLOY_FAILED": "AWS 시험 환경 검사 실패",
    "UNVERIFIED": "AWS 시험 환경 검사 판정 불가",
    "PLAN_BLOCKED": "AWS 시험 환경 검사 차단 — 시험 환경 상태 기준 plan 에 교체·삭제 포함, apply 미실행",
}
DECISION_KO = {
    "APPROVED": "적용 승인 — PR 초안 생성",
    "CHANGES_REQUESTED": "수정 요청",
    "REGENERATE": "수정안 재생성 요청",
    "DISCARDED": "폐기",
    "APPLY_FAILED": "배포(apply) 실패 기록",
}


RESOURCE_KO = {
    "aws_instance.web": "웹 서버", "aws_instance.app": "앱 서버", "aws_security_group.web": "웹 서버 보안 그룹", "aws_security_group.app": "앱 서버 보안 그룹",
    "aws_iam_role.web": "웹 서버 역할", "aws_iam_policy.web_assets": "웹 서버 역할의 권한 정책", "aws_s3_bucket.assets": "자산 버킷",
}
DISCLAIMER_KO = {
    "Proves the effective ALLOW set at security-group level only. Real reachability (NACL, routing, public IP, host firewall, listening service) is not proven here.":
        "보안 그룹 규칙상 허용 집합만 증명. 실제 도달 가능성(NACL, 라우팅, 공인 IP, 호스트 방화벽, 서비스 수신)은 증명하지 않음 — 배포 후 통신 시험(V8)에서 일부 확인.",
    "Proves the ALLOW set of the evaluated policy documents only (Tier 1: Allow statements, '*' wildcards). Deny/NotAction/Condition/managed policies are UNKNOWN, never PASS. Effective permissions in the account (SCP, permission boundary, resource policies) are not evaluated.":
        "평가한 정책 문서의 Allow 집합만 증명(Allow 문과 '*' 와일드카드). Deny·NotAction·Condition·관리형 정책은 판정 불가로 두며 통과로 처리하지 않음. 계정 수준 실효 권한(SCP, 권한 경계, 리소스 정책)은 평가하지 않음.",
}


def pretty(addr: str) -> str:
    """리소스 주소 → 화면 이름 + 주소. 모르는 주소는 그대로."""
    a = str(addr or "")
    base = a.split(" ")[0]
    ko = RESOURCE_KO.get(base)
    return f"{ko}({a})" if ko else a


def disclaimer_ko(text: str) -> str:
    return DISCLAIMER_KO.get(str(text or "").strip(), str(text or ""))


def verdict_ko(v: Optional[str]) -> str:
    return VERDICT_KO.get(str(v or "").upper(), str(v or "-"))


def origin_label(origin: Optional[str], generator: Optional[str] = None, provenance: str = "") -> Dict[str, str]:
    o = str(origin or "").lower()
    if o in ("manual", "upload") and ("붙여넣" in (provenance or "") or "직접 제출" in (provenance or "")):
        o = "paste"
    if o == "upload":
        o = "paste"
    if o in _AI_CODES or str(provenance or "").startswith(("AI 후보", "AI 수정안")):   # 예전 기록의 출처 글(AI 후보 …)도 읽는다
        o = "llm"
    label, desc = ORIGIN_KO.get(o, (o or "알 수 없음", ""))
    return {"code": o, "label": label, "desc": desc}


# ----------------------------------------------------------------------------- 요구사항 문장
def _cidr_desc(c: str) -> str:
    if c in ("0.0.0.0/0", "::/0"):
        return "인터넷 전체"
    return f"{c} 대역"


def _sg_desc(ref: str) -> str:
    name = ref.split(".")[-1] if "." in ref else ref
    return f"{name} 보안 그룹 연결 서버"


def _svc_name(label: str, proto: str, from_port: int, to_port: int) -> str:
    port = f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
    names = {"ssh": "SSH", "rdp": "원격 데스크톱(RDP)", "public-http": "HTTP", "http": "HTTP", "admin-ssh": "SSH", "app-8080": "앱 포트"}
    base = names.get(label, label)
    return f"{base}({port})"


def sg_requirements(intent: Any) -> List[Dict[str, Any]]:
    """IntentSpec → 요구사항 행. kind: limit(제한) / keep(유지)."""
    rows: List[Dict[str, Any]] = []
    targets = list(getattr(intent, "target_security_groups", []) or [])
    for gs in intent.guarded_services:
        svc = gs.service
        ap = gs.approved
        srcs = [_cidr_desc(c) for c in ap.cidrs_v4] + [_cidr_desc(c) for c in ap.cidrs_v6] + [_sg_desc(r) for r in ap.security_group_refs]
        name = _svc_name(svc.label or svc.id, svc.protocol, svc.from_port, svc.to_port)
        if srcs:
            text = f"{name}: {', '.join(srcs)}에서만 허용"
        else:
            text = f"{name}: 모든 출발지 차단"
        rows.append({"id": f"limit:{svc.label or svc.id}", "kind": "limit", "label": svc.label or svc.id, "service": name,
                     "text": text, "approved": srcs, "targets": targets,
                     "approved_raw": {"cidrs_v4": list(ap.cidrs_v4), "cidrs_v6": list(ap.cidrs_v6), "security_group_refs": list(ap.security_group_refs)}})
    for req in intent.required_access:
        svc = req.service
        name = _svc_name(req.label or svc.id, svc.protocol, svc.from_port, svc.to_port)
        tg = list(req.targets) or targets
        text = f"{name}: {_cidr_desc(req.source_cidr)} 접근 유지 필수 (필수 통신)"
        rows.append({"id": f"keep:{req.label or svc.id}", "kind": "keep", "label": req.label or svc.id, "service": name,
                     "text": text, "source": req.source_cidr, "targets": tg})
    return rows


def iam_requirements(intent: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    roles = list(getattr(intent, "target_roles", []) or [])
    pols = list(getattr(intent, "target_policies", []) or [])
    who = (roles[0].split(".")[-1] + " 역할") if roles else (pols[0] if pols else "역할")
    for i, ap in enumerate(getattr(intent, "approved", []) or []):
        acts = ", ".join(ap.actions)
        res = ", ".join(ap.resources)
        rows.append({"id": f"limit:iam-{i}", "kind": "limit", "label": f"iam-{i}", "service": "IAM 권한",
                     "text": f"{who}: {acts} 권한은 {res} 에만 허용 — 그 외 권한 없음",
                     "approved": [f"{a} on {r}" for a in ap.actions for r in ap.resources], "targets": roles + pols})
    for rp in getattr(intent, "required", []) or []:
        rows.append({"id": f"keep:{rp.label or rp.action}", "kind": "keep", "label": rp.label or rp.action, "service": "IAM 권한",
                     "text": f"{rp.action} on {rp.resource}: 유지 필수", "source": rp.resource, "targets": roles + pols})
    return rows


# ----------------------------------------------------------------------------- 오라클 결과 → 요구사항별 상태
def _scope_name(scope_id: str) -> str:
    if scope_id.startswith("standalone:"):
        return pretty(scope_id.split(":", 1)[1]) + " (단독 평가)"
    return pretty(scope_id)


def sg_oracle_rows(details: Dict[str, Any], intent_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """sg_oracle 의 details(to_dict) → 요구사항 행마다 상태·실제값·근거."""
    by_label: Dict[str, Dict[str, Any]] = {}
    for row in intent_rows:
        by_label[row["id"]] = {**row, "verdict": None, "where": [], "effective": [], "excess": [], "evidence": [], "reasons": []}
    order = {"FAIL": 3, "UNKNOWN": 2, "PASS": 1, None: 0}
    for t in details.get("targets") or []:
        if t.get("reason") and not t.get("scopes"):
            # 대상 SG 자체가 사라짐 → 모든 유지 요구가 확인 불가, 제한 요구는 FAIL 로 본다
            for row in by_label.values():
                row["verdict"] = "FAIL"
                row["reasons"].append(f"{pretty(t.get('target'))}: 대상 보안 그룹 제거 — 요구사항 확인 불가")
            continue
        for sc in t.get("scopes") or []:
            where = _scope_name(sc.get("scope_id", ""))
            for s in sc.get("services") or []:
                key = f"limit:{s.get('label')}"
                row = by_label.get(key)
                if row is None:
                    continue
                v = s.get("verdict")
                if order.get(v, 0) >= order.get(row["verdict"], 0):
                    row["verdict"] = v
                eff = list(s.get("effective_v4") or []) + list(s.get("effective_v6") or []) + [f"sg:{r}" for r in s.get("effective_sg_refs") or []]
                exc = list(s.get("excess_v4") or []) + list(s.get("excess_v6") or []) + [f"sg:{r}" for r in s.get("excess_sg_refs") or []]
                if eff or v != "PASS":
                    row["where"].append(where)
                row["effective"] = sorted(set(row["effective"]) | set(eff))
                row["excess"] = sorted(set(row["excess"]) | set(exc))
                row["evidence"] += list(s.get("contributing_rules") or [])
                if v == "FAIL":
                    if s.get("covers_entire_internet_v4"):
                        row["reasons"].append(f"{where}: 실제 허용 출발지가 인터넷 전체(0.0.0.0/0) — 승인 범위 밖")
                    elif exc:
                        row["reasons"].append(f"{where}: 승인 범위 밖 출발지 잔존: {', '.join(exc[:4])}")
                    else:
                        row["reasons"].append(f"{where}: 승인 범위 밖 출발지 잔존")
                elif v == "UNKNOWN":
                    row["reasons"] += [f"{where}: {u}" for u in (s.get("unknown_reasons") or [])[:2]]
            for r in sc.get("required") or []:
                key = f"keep:{r.get('label')}"
                row = by_label.get(key)
                if row is None:
                    continue
                v = r.get("verdict")
                if order.get(v, 0) >= order.get(row["verdict"], 0):
                    row["verdict"] = v
                row["where"].append(where)
                if v == "FAIL":
                    row["reasons"].append(f"{where}: 필수 통신 허용 규칙 없음 — 출발지 {r.get('source_cidr')}")
                elif v == "UNKNOWN":
                    row["reasons"].append(f"{where}: {r.get('reason')}")
    out = []
    for row in by_label.values():
        if row["verdict"] is None:
            row["verdict"] = "PASS" if row["kind"] == "limit" else "UNKNOWN"
            if row["kind"] == "keep":
                row["reasons"].append("이 요구사항의 평가 대상 없음")
        row["status_ko"] = {"PASS": "충족", "FAIL": "위반", "UNKNOWN": "판정 불가"}.get(row["verdict"], row["verdict"])
        row["where"] = sorted(set(row["where"]))
        row["evidence"] = sorted(set(row["evidence"]))
        out.append(row)
    return out


def iam_oracle_rows(details: Dict[str, Any], intent_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """iam_oracle 의 details → 요구사항 행. scopes[].excess / missing / unknown_reasons 를 모은다 (판정은 verdict 값 그대로)."""
    verdict = str(details.get("verdict") or "UNKNOWN")
    excess: List[str] = []
    missing: List[str] = []
    unknown: List[str] = []
    where: List[str] = []
    for sc in details.get("scopes") or []:
        where.append(pretty(str(sc.get("scope_id"))))
        excess += [str(x) for x in sc.get("excess") or [] if str(x) not in excess]
        missing += [str(x) for x in sc.get("missing") or [] if str(x) not in missing]
        unknown += [str(x) for x in sc.get("unknown_reasons") or [] if str(x) not in unknown]
    rows = []
    for row in intent_rows:
        r = {**row, "where": where, "effective": [], "excess": [], "evidence": [], "reasons": []}
        if row["kind"] == "limit":
            if excess:
                r["verdict"] = "FAIL"
                r["excess"] = excess[:8]
                r["reasons"].append("승인 범위 밖 권한 잔존: " + "; ".join(excess[:3]))
            elif verdict == "UNKNOWN" or unknown:
                r["verdict"] = "UNKNOWN"
                r["reasons"] += unknown[:2] or [str(details.get("summary", ""))[:200]]
            else:
                r["verdict"] = "PASS"
        else:
            mine = [m for m in missing if (row.get("label") and row["label"] in m)] or ([] if not missing else missing)
            if mine:
                r["verdict"] = "FAIL"
                r["reasons"].append("필수 권한 누락: " + "; ".join(mine[:2]))
            elif verdict == "UNKNOWN" or unknown:
                r["verdict"] = "UNKNOWN"
                r["reasons"] += unknown[:2]
            else:
                r["verdict"] = "PASS"
        r["status_ko"] = {"PASS": "충족", "FAIL": "위반", "UNKNOWN": "판정 불가"}.get(r["verdict"], r["verdict"])
        rows.append(r)
    return rows


# ----------------------------------------------------------------------------- 후보 분류 / 결론
def classify_candidate(state: Dict[str, Any], verification: Optional[Dict[str, Any]], policy: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """기록 하나를 '통과 / 과도한 허용 잔존 / 필수 접근 허용 규칙 누락 / 판정 불가 / 차단(정책 허용 범위 밖 · 실행 전 안전 점검) / 후보 사용 불가' 로.
    V6 는 보안 그룹 인바운드 규칙만 본다 — '허용 규칙 누락' 은 규칙이 없다는 뜻이지, 실제 접속 실패를 확인한 것이 아니다 (실제 접속은 V8)."""
    st = str(state.get("state") or "")
    if st in ("CANDIDATE_INVALID", "INFO_INSUFFICIENT"):
        return {"code": "invalid", "label": "수정안 사용 불가", "tone": "muted"}
    if st in ("INPUT_ERROR", "NO_FINDING", "AMBIGUOUS_FINDING"):
        return {"code": "input", "label": "검토 시작 불가", "tone": "muted"}
    if st == "POLICY_BLOCKED" or (policy and policy.get("ok") is False):
        if any(str(v).startswith("exec_guard:") for v in (policy or {}).get("violations") or []):
            return {"code": "exec_guard", "label": "차단 — 실행 전 안전 점검 (도구 실행 안 함)", "tone": "bad"}
        return {"code": "policy", "label": "차단 — 정책 허용 범위 밖", "tone": "bad"}
    layers = ((verification or {}).get("report") or {}).get("layers") or []
    v6 = next((l for l in layers if l.get("layer") == "V6"), None)
    excess = missing = unknown = False
    if v6 and isinstance(v6.get("details"), dict):
        for t in v6["details"].get("targets") or []:
            if t.get("reason") and not t.get("scopes"):
                missing = True
            for sc in t.get("scopes") or []:
                for s in sc.get("services") or []:
                    if s.get("verdict") == "FAIL":
                        excess = True
                    elif s.get("verdict") == "UNKNOWN":
                        unknown = True
                for r in sc.get("required") or []:
                    if r.get("verdict") == "FAIL":
                        missing = True
                    elif r.get("verdict") == "UNKNOWN":
                        unknown = True
        if v6["details"].get("kind") == "topology":   # 설계도 기준: 설계 외 허용 경로 = 과도한 허용, 필수 통신 누락 = 필요한 기능 차단
            if v6["details"].get("excess"):
                excess = True
            for f in v6["details"].get("flows") or []:
                if f.get("status") == "broken":
                    missing = True
                elif f.get("status") == "unknown":
                    unknown = True
            if v6.get("verdict") == "UNKNOWN":
                unknown = True
        if v6["details"].get("kind") == "iam":
            for sc in v6["details"].get("scopes") or []:
                if sc.get("excess"):
                    excess = True
                if sc.get("missing"):
                    missing = True
                if sc.get("verdict") == "UNKNOWN":
                    unknown = True
    other_fail = [l["layer"] for l in layers if l.get("verdict") == "FAIL" and l.get("layer") != "V6"]
    topo = bool(v6 and isinstance(v6.get("details"), dict) and v6["details"].get("kind") == "topology")
    if excess and missing:
        return {"code": "excess_missing", "label": "설계 외 허용 경로 + 필수 통신 허용 규칙 누락" if topo else "과도한 허용 잔존 + 필수 접근 허용 규칙 누락", "tone": "bad"}
    if excess:
        return {"code": "excess", "label": "설계 외 허용 경로" if topo else "과도한 허용 잔존", "tone": "bad"}
    if missing:
        return {"code": "missing", "label": "필수 통신 허용 규칙 누락" if topo else "필수 접근 허용 규칙 누락", "tone": "bad"}
    if other_fail:
        return {"code": "fail_other", "label": "검증 실패 (" + ", ".join(other_fail) + ")", "tone": "bad"}
    validity = str(((verification or {}).get("report") or {}).get("validity") or "")
    if validity == "INCOMPLETE" or unknown:
        return {"code": "unknown", "label": "판정 불가", "tone": "warn"}
    if validity == "PASS":
        return {"code": "ok", "label": "통과 — 배포 전 검사 요구사항 충족", "tone": "good"}
    return {"code": "unknown", "label": "판정 불가", "tone": "warn"}


def conclusion(state: Dict[str, Any], verification: Optional[Dict[str, Any]], risk: Optional[Dict[str, Any]],
               policy: Optional[Dict[str, Any]], req_rows: List[Dict[str, Any]], testbed: Optional[bool] = None) -> Dict[str, Any]:
    """맨 위 결론. title = 처음 보는 사람이 읽는 한 문장 (교수 피드백 2026-10-31), status = 지금 상태 · 승인 가능 여부,
    headline = 짧은 분류(기록 목록 · 로그용), reason = 근거 한 줄, next = 다음에 할 수 있는 것. 판정 값은 기록 그대로.
    testbed = 이 기록의 묶음에 실제 AWS 시험 환경이 있는가 (False 면 '다음: 실제 AWS 검사' 대신 '실제 AWS 미검증' 안내, None = 모름 · 예전 문구)."""
    st = str(state.get("state") or "")
    level = str(state.get("review_level") or "")
    rep = (verification or {}).get("report") or {}
    validity = str(rep.get("validity") or "")
    layers = rep.get("layers") or []
    dec = (risk or {}).get("decision") or {}
    rl = str(dec.get("risk_level") or "")
    violated = [r for r in req_rows if r.get("verdict") == "FAIL"]
    unknown_rows = [r for r in req_rows if r.get("verdict") == "UNKNOWN"]
    fails = [l for l in layers if l.get("verdict") == "FAIL"]
    pend = [l for l in layers if l.get("verdict") in ("NOT_RUN", "UNKNOWN", "SKIPPED", "ERROR")]

    if st in ("INPUT_ERROR", "NO_FINDING", "AMBIGUOUS_FINDING"):
        from ..proof.plain import legacy as _lg   # 기록에 저장된 옛 오류 문장 → 지금 용어 (표시만)
        return {"tone": "muted", "title": "검사를 시작할 수 없습니다", "status": "검사 안 함 · 승인 불가", "headline": STATE_KO.get(st, st),
                "reason": "; ".join(_lg(x) for x in state.get("errors") or []) or _lg(_last_note(state)),
                "next": ["입력(원본 · 점검 결과 · 설계도) 확인 후 다시 검사"], "can_approve": False}
    if st in ("CANDIDATE_INVALID", "INFO_INSUFFICIENT"):
        from ..proof.plain import legacy as _lg
        return {"tone": "muted", "title": "제출한 코드를 검사에 쓸 수 없습니다", "status": "검사 안 함 · 승인 불가", "headline": STATE_KO.get(st, st),
                "reason": "; ".join(_lg(x) for x in state.get("errors") or []) or _lg(_last_note(state)),
                "next": ["수정 코드를 고쳐 다시 제출하거나 다른 수정안 선택"], "can_approve": False}
    if st == "POLICY_BLOCKED" or (policy and policy.get("ok") is False):
        from ..proof.cards import policy_ko
        raw = (policy or {}).get("violations") or []
        vio = [policy_ko(v) for v in raw]
        guard = any(str(v).startswith("exec_guard:") for v in raw)
        return {"tone": "bad", "title": "실행하면 위험한 구문이 있어 검사를 멈췄습니다" if guard else "허용되지 않은 부분까지 수정했습니다",
                "status": "차단 · 승인 불가", "headline": "차단 — 실행 전 안전 점검" if guard else "차단 — 정책 허용 범위 밖 수정",
                "reason": "; ".join(vio[:3]) or _last_note(state),
                "next": ["문제가 된 구문 · 변경을 빼고 다시 제출", "재생성 요청", "폐기"], "can_approve": False}
    if validity == "FAIL" or st == "VALIDATION_FAILED":
        v1 = next((l for l in layers if l.get("layer") == "V1"), None)
        v6 = next((l for l in layers if l.get("layer") == "V6"), None)
        if violated:
            # 불일치 내용 한 줄씩 (예: '웹 서버 → Redis 6379 — 설계 외 허용 경로')
            why = "; ".join(x for r in violated for x in r.get("reasons", [])[:1]) or " / ".join(f"'{r['text']}' 위반" for r in violated[:2])
        else:
            why = "; ".join(f"{l['layer']} {LAYER_QUESTION.get(l['layer'], '')} → 실패: {_plain_summary(str(l.get('layer')), l.get('summary'))[:120]}" for l in fails[:2])
        note = ""
        if v1 and v1.get("verdict") == "PASS" and v6 and v6.get("verdict") == "FAIL":
            # 차단한 단계를 모두 적는다 (예: V2 도 실패했으면 'Trivy 미탐지'로 읽히지 않게)
            caught = [f"{LAYER_SHORT.get(str(l.get('layer')), '')}({l.get('layer')})" for l in fails if l.get("layer") in ("V2", "V3", "V4", "V5", "V6")]
            note = f" — Trivy 재검사(V1)는 통과했으나 {' · '.join(caught) or '고객 설계 일치(V6)'}에서 차단"
        failed = {str(l.get("layer")) for l in fails}
        title = ("기존 보안 문제가 해결되지 않았습니다" if "V1" in failed else "수정하면서 새로운 보안 문제가 생겼습니다" if "V2" in failed
                 else "Terraform 코드 오류로 검사를 끝까지 하지 못했습니다" if "V3" in failed
                 # V4 만 실패: 코드 문제(기본값 없는 변수 등)일 수도, 검사 환경 문제일 수도 있다 — 원인을 단정하지 않는다
                 else "실행 계획(plan)을 만들지 못해 검사를 끝까지 하지 못했습니다" if "V4" in failed
                 else "허용되지 않은 부분까지 수정했습니다" if "V5" in failed
                 else "수정한 코드가 고객 설계와 일치하지 않습니다" if ("V6" in failed or violated) else "검증에 실패했습니다")
        return {"tone": "bad", "title": title, "status": "검증 실패 · 승인 불가",
                "headline": "차단 — 설계 기준과 불일치" if violated else "차단 — 검사 실패",
                "reason": why + note,
                "next": ["문제를 고쳐 다시 제출", "재생성 요청", "폐기"], "can_approve": False}
    if validity == "INCOMPLETE" or level == "PENDING":
        what = ", ".join(f"{l['layer']}({verdict_ko(l['verdict'])})" for l in pend[:4])
        why = f"결과가 없는 검사가 있어 통과 판정 불가: {what}"
        if unknown_rows:
            why += " · 판정 불가 요구사항: " + ", ".join(r["label"] for r in unknown_rows[:3])
        return {"tone": "warn", "title": "판정할 수 없습니다 — 확인하지 못한 검사가 있습니다", "status": "판정 불가 · 승인 불가",
                "headline": "판정 불가 — 미검증 단계 존재", "reason": why,
                "next": ["이 PC 에 Trivy · Terraform 설치 후 다시 검사", "입력 · 설계도 보완", "폐기"], "can_approve": False}
    if level == "REPORT_ONLY":
        return {"tone": "warn", "title": "자동 수정 대상이 아닙니다 — 사람이 직접 고쳐야 합니다", "status": "보고서만 · 승인 불가",
                "headline": "보고서만 — 자동 수정 금지", "reason": f"위험도 {RISK_KO.get(rl, rl)} 또는 위험도 근거 부족 — 사람이 직접 수정 필요",
                "next": ["보고서 검토 후 사람이 직접 수정", "폐기"], "can_approve": False}
    if level in ("LIGHT_REVIEW", "FULL_REVIEW"):
        head = "배포 전 검사 통과"
        des = state.get("design") if isinstance(state.get("design"), dict) else {}
        conf = des.get("confirmation") if isinstance(des.get("confirmation"), dict) else None
        if conf is not None and not conf.get("confirmed"):
            # D-38: 설계도(또는 IAM 요구사항, D-40)가 초안이면 검사는 통과해도 '고객 요구 충족' 을 말하지 않는다 — 확정 뒤 다시 검사
            iam = str(conf.get("kind") or "") == "iam"
            w, wg = ("IAM 요구사항", "IAM 요구사항이") if iam else ("설계도", "설계도가")
            how = ("올렸지만 아직 확정하지 않은 판" if iam else "프로그램이 지금 코드에서 자동으로 만든 초안" if conf.get("auto")
                   else "확정이 풀린 수정본" if conf.get("by") else "저장만 하고 아직 확정하지 않은 초안")
            return {"tone": "warn", "title": f"배포 전 검사는 통과했지만, {wg} 아직 초안입니다", "status": f"승인 불가 · {w} 확정 필요", "headline": head + " (초안 기준)",
                    "reason": f"코드 검사 6개(V1~V6) 통과 — 단 {'권한 비교' if iam else '고객 구조 비교'}(V6)의 기준인 {w} v{des.get('intent_version') or conf.get('version') or '?'} 가/이 "
                              f"{how}입니다. 담당자가 ③ 에서 확정해야 '고객 요구 충족' 으로 볼 수 있고, 확정한 뒤 다시 검사해야 승인할 수 있습니다",
                    "next": [f"③ 원하는 구조에서 담당자가 {w} 확정 (이름 · 메모 기록)", f"확정한 {w}로 다시 검사", "폐기"], "can_approve": False, "draft_design": True}
        # 실제 AWS 검사 결과가 이미 있으면 그 결과를 적는다 (문구만 — 승인 가능 여부 · 판정은 그대로)
        pst = str(((state.get("post_deploy") or {}) if isinstance(state.get("post_deploy"), dict) else {}).get("status") or "")
        if pst == "VERIFIED":
            return {"tone": "good", "title": "배포 전 검사 · AWS 시험 환경 검사를 모두 통과했습니다", "status": "승인 결정 가능 (사람) · 운영 반영 전", "headline": head,
                    "reason": "코드 검사 6개(V1~V6) 통과 · AWS 시험 환경 검사(V7 · V8) 통과 — 시험 환경(샌드박스)에서 확인한 것이지 운영 반영 후 확인이 아님. 다음: 사람이 승인 결정",
                    "next": ["승인 결정: 사람 최종 승인", "수정 요청", "폐기"], "can_approve": True}
        if pst in ("DEPLOY_FAILED", "UNVERIFIED", "PLAN_BLOCKED"):
            return {"tone": "good", "title": "AWS 시험 환경 검사에서 문제가 나왔습니다", "status": "적용 승인 불가", "headline": head,
                    "reason": f"코드 검사 6개(V1~V6) 통과 · {POST_KO[pst].split(' — ')[0]} — 적용 승인 불가 (다른 수정안 선택 또는 수정 요청)",
                    "next": ["다른 수정안 선택", "수정 요청", "폐기"], "can_approve": True}
        if testbed is False:
            # 실제 AWS 시험 환경이 없는 프로젝트 (D-32): V7 · V8 을 할 수 없다 — '다음: 실제 AWS 검사' 로 안내하지 않는다
            return {"tone": "good", "title": "배포 전 검사를 모두 통과했습니다", "status": "승인 판단 가능 · 실제 AWS 미검증", "headline": head,
                    "reason": "코드 검사 6개(V1~V6) 통과 — 이 프로젝트에는 AWS 시험 환경이 없어 V7 · V8 은 하지 않음 (실제 AWS 미검증: 시험 환경에 반영해 재지 않음)",
                    "next": ["승인 판단: '실제 AWS 미검증' 을 알고 승인하면 그 사실이 결정 기록 · PR 에 남음", "수정 요청", "폐기"], "can_approve": True}
        return {"tone": "good", "title": "배포 전 검사를 모두 통과했습니다", "status": "다음: AWS 시험 환경 검사", "headline": head,
                "reason": "코드 검사 6개(V1~V6) 통과 — 배포 전(코드만) 통과이지 배포 성공이 아님. 다음: AWS 시험 환경 검사 (시험 환경 반영 → V7 → V8)",
                "next": ["AWS 시험 환경 검사: 시험 환경 반영 → V7 · V8 측정 → 시험 환경 삭제", "수정 요청", "폐기"], "can_approve": True}
    return {"tone": "muted", "title": STATE_KO.get(st, st) or "상태 없음", "status": "", "headline": STATE_KO.get(st, st) or "상태 없음",
            "reason": _last_note(state), "next": [], "can_approve": False}


def _last_note(state: Dict[str, Any]) -> str:
    h = state.get("history") or []
    return str(h[-1].get("note", "")) if h else ""


def layers_table(verification: Optional[Dict[str, Any]], post_deploy: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    rep = (verification or {}).get("report") or {}
    by = {l.get("layer"): l for l in rep.get("layers") or []}
    post_layers = {}
    if post_deploy and isinstance(post_deploy.get("layers"), dict):
        post_layers = post_deploy["layers"]
    rows = []
    for name in ("V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8"):
        l = by.get(name)
        if l is None and name in post_layers:
            l = {"layer": name, "verdict": post_layers[name], "summary": "", "tool": ""}
        verdict = (l or {}).get("verdict") or ("NOT_RUN" if name in ("V7", "V8") else "NOT_RUN")
        rows.append({"layer": name, "phase": LAYER_PHASE[name], "question": LAYER_QUESTION[name], "tool": LAYER_TOOL[name],
                     "verdict": verdict, "verdict_ko": verdict_ko(verdict) if l else ("AWS 시험 환경 검사 대상" if name in ("V7", "V8") else "미실행"),
                     "summary": (l or {}).get("summary", ""), "tool_used": (l or {}).get("tool", ""), "name": (l or {}).get("name", "")})
    return rows


def risk_summary(risk: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    dec = (risk or {}).get("decision") or {}
    factors = [f for f in dec.get("factors") or [] if f.get("points") or ("hard" in str(f.get("note", ""))) or ("floor" in str(f.get("note", ""))) or f.get("factor") == "undetermined"]
    names = {"attachment_points": "변경 보안 그룹이 연결된 서버 수", "resources_touched": "변경 리소스 수", "new_resources_created": "신규 생성 리소스 수",
             "outside_target_family_touched": "대상 외 종류의 리소스 변경", "attachment_has_external_or_unknown_sg": "미확인 보안 그룹 동시 연결",
             "egress_changed": "아웃바운드 규칙 변경", "non_core_attribute_changed": "핵심 외 속성 변경", "oracle_partial_rules_or_caveats": "허용 집합 계산에 미확정 요소",
             "patch_lines": "변경 행 수", "files_changed": "변경 파일 수", "deleted_resources": "리소스 삭제", "replaced_resources": "리소스 교체",
             "trust_policy_changed": "신뢰 정책 변경", "iam_change": "IAM 변경", "undetermined": "미확정 항목", "insufficient_basis": "근거 부족",
             # 텍스트 근거로 매기는 요인 (plan 없이) — 이름이 없으면 화면에 영어 키가 그대로 보였다
             "new_resource_blocks": "신규 resource 블록 수 (텍스트 근거)", "resource_blocks_touched": "변경 resource 블록 수 (텍스트 근거)",
             "non_resource_block_changed": "resource 외 블록 변경 (variable/locals/data 등)", "replace_forcing_attribute_changed": "교체 유발 속성 변경 의심"}

    def fname(k: Any) -> str:
        """요인 키 → 화면 이름. 이 표에 없으면 기준표 설명(rubric_demo)에서, 그래도 없으면 키 그대로."""
        if k in names:
            return names[k]
        try:
            from ..rubric_demo import FACTOR_KO, HARD_KO
            return FACTOR_KO.get(str(k)) or HARD_KO.get(str(k)) or str(k)
        except Exception:  # 설명 표를 못 읽어도 키는 보인다
            return str(k)
    return {"level": dec.get("risk_level"), "level_ko": RISK_KO.get(str(dec.get("risk_level")), dec.get("risk_level")), "score": dec.get("score"),
            "rubric": dec.get("rubric_version"), "autonomy_cap": dec.get("autonomy_cap"),
            "factors": [{"name": fname(f.get("factor")), "value": f.get("value"), "points": f.get("points"), "note": f.get("note", ""), "basis": f.get("basis", "")} for f in factors],
            "all_factors": dec.get("factors") or []}


def human_checks(req_rows: List[Dict[str, Any]], state: Dict[str, Any], risk: Optional[Dict[str, Any]], candidate: Optional[Dict[str, Any]]) -> List[str]:
    items = []
    items.append("4단계 변경 내용(diff) 검토 완료 — 탐지 항목 수정에 필요한 행만 변경됨")
    items.append("배포 전 검사(V1~V6)와 AWS 시험 환경 검사(시험 환경 반영 · V7 · V8) 모두 통과 확인")
    items.append("판정 기준(설계도·허용 대역)이 팀 지정 값과 일치 — 프로그램 추정값 아님 확인")
    for need in (candidate or {}).get("needs_info") or []:
        if "rationale" in str(need):
            items.append("수정안에 수정 근거 미기재 — 아래 사유 칸에 사람이 작성 완료")
        else:
            from ..proof.plain import legacy as _lg   # 예전 기록의 문장 → 지금 용어 (표시만)
            items.append(f"수정안 누락 항목 확인 완료 — {_lg(need)}")
    dec = (risk or {}).get("decision") or {}
    if any(f.get("factor") == "undetermined" for f in dec.get("factors") or []):
        items.append("위험도 미확정 항목(같은 서버의 다른 보안 그룹, 삭제·교체 여부) 확인 완료")
    items.append("승인 시 PR 초안만 생성 — push·리뷰·병합·실제 terraform apply 는 사람이 직접 수행")
    return items


def diff_summary(diff_text: str) -> List[Dict[str, str]]:
    """unified diff → 바뀐 줄 쌍 (최대 6개). '-' 줄과 '+' 줄을 순서대로 짝지어 보여 준다."""
    minus, plus = [], []
    for line in (diff_text or "").splitlines():
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
            continue
        if line.startswith("-"):
            minus.append(line[1:].strip())
        elif line.startswith("+"):
            plus.append(line[1:].strip())
    out = []
    for i in range(max(len(minus), len(plus))):
        out.append({"before": minus[i] if i < len(minus) else "", "after": plus[i] if i < len(plus) else ""})
        if len(out) >= 6:
            break
    return out


# ----------------------------------------------------------------------------- 설계도(토폴로지) 기준 구조 검사 (2026-10-20)
_PORT_NAMES = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 6379: "Redis", 8080: "API", 3389: "RDP"}


def _flow_service(protocol: str, from_port: int, to_port: int) -> str:
    if protocol == "-1":
        return "전체 통신"
    if from_port == to_port:
        name = _PORT_NAMES.get(from_port)
        return f"{name}({from_port})" if name else f"{protocol.upper()} {from_port}"
    return f"{protocol.upper()} {from_port}-{to_port}"


def topology_requirements(intent: Any) -> List[Dict[str, Any]]:
    """설계도 의도 → 요구사항 행. 설계 기준 경로마다 '허용 유지'(keep) + '설계 외 통신 차단'(limit) 한 줄."""
    rows: List[Dict[str, Any]] = []
    for f in intent.flows:
        svc = _flow_service(f.protocol, f.from_port, f.to_port)
        rows.append({"id": f"flow:{f.id}", "kind": "keep", "label": f.id, "service": svc,
                     "text": f"{intent.label_of(f.src)} → {intent.label_of(f.dst)} : {svc}",
                     "src": f.src, "dst": f.dst, "targets": [t.security_group for t in intent.tiers if t.id == f.dst]})
    rows.append({"id": "deny:other", "kind": "limit", "label": "deny-other", "service": "설계 외 통신",
                 "text": "설계 외 통신은 모두 차단", "targets": list(intent.target_security_groups)})
    return rows


def topology_oracle_rows(details: Dict[str, Any], intent_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    from ..proof.plain import legacy          # 기록에 저장된 옛 문구 → 지금 용어 (표시만)
    flows = {f"flow:{f['id']}": f for f in (details.get("flows") or [])}
    excess = details.get("excess") or []
    unknown = str(details.get("verdict") or "") == "UNKNOWN"
    out: List[Dict[str, Any]] = []
    for r in intent_rows:
        if r["id"] == "deny:other":
            if excess:
                v = "FAIL"
                reasons = [f"{legacy(e['src_label'])} → {e['dst_label']} {e['ports']} — {legacy(e['detail'])}" for e in excess]
            else:
                v = "UNKNOWN" if unknown else "PASS"
                reasons = list(details.get("notes") or [])[:3] if unknown else []
            out.append({**r, "verdict": v, "status_ko": verdict_ko(v), "excess": [f"{legacy(e['src_label'])} → {e['dst_label']} {e['ports']}" for e in excess],
                        "effective": [], "where": [], "evidence": [], "reasons": reasons, "edges": excess})
            continue
        f = flows.get(r["id"])
        if f is None:
            v, reasons = "UNKNOWN", ["검사 결과에 이 경로 없음"]
        elif f["status"] == "ok":
            v, reasons = "PASS", []          # 보안 그룹은 허용만 더한다 — 다른 규칙을 몰라도 이미 열린 통신은 열린 것
        elif f["status"] == "unknown":
            v, reasons = "UNKNOWN", [legacy(x) for x in f.get("reasons") or []]
        else:
            v, reasons = "FAIL", [legacy(x) for x in f.get("reasons") or []]
        out.append({**r, "verdict": v, "status_ko": verdict_ko(v), "excess": [], "effective": [], "where": [], "evidence": [], "reasons": reasons})
    return out


def requirements_for(kind: Optional[str], spec: Any) -> List[Dict[str, Any]]:
    if kind == "iam":
        return iam_requirements(spec)
    if kind == "topology":
        return topology_requirements(spec)
    return sg_requirements(spec)


def oracle_rows(kind: Optional[str], details: Dict[str, Any], intent_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if kind == "iam":
        return iam_oracle_rows(details, intent_rows)
    if kind == "topology":
        return topology_oracle_rows(details, intent_rows)
    return sg_oracle_rows(details, intent_rows)
