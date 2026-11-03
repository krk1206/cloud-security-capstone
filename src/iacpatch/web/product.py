"""새 프로그램 화면 자료 (2026-11-01 갈아엎기 3차 — B 문서 '취약점 검사 범위 확대 + 스토리 중심 UI').

화면 흐름: ① 시작(프로젝트) → ② 현재 인프라(코드에서 그림) → ③ 고객 설계 → ④ 보안 문제 → ⑤ 수정 후보(설계도 vs 후보 그림)
          → ⑥ 적용 판단(V1~V6) → ⑦ 실제 AWS(V7 · V8) → ⑧ 최종 결정 · PR
판정을 새로 만들지 않는다. Trivy 결과 · 자체 보안 그룹 검사(verify/sg_scan) · 설계 비교(V6 오라클) · IAM 오라클 · 검사 기록을 모아 보여 준다.
지원하지 않는 것 · 분석 못 한 것은 '판정 불가 · 미지원 · 미검증' 으로 그대로 보여 준다 (숨기지 않는다).
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import cases as cs
from . import archmap, codetopo

TESTBED_SET = "arch-3tier-sg"          # 실제 AWS 시험 환경이 있는 묶음 (proof_api.TESTBED_SET 과 같음)

# 사용자에게 보여 주는 문제 묶음 (B 문서 화면 4 예시 순서)
GROUP_KO = {
    "public_mgmt": "외부에 공개된 관리 포트",
    "public_risky": "외부에 공개된 위험 포트",
    "design_extra": "고객이 허용하지 않은 서버 간 통신",
    "design_missing": "서비스에 필요한 허용 규칙의 누락",
    "broad_access": "과도하게 넓은 접근 권한",
    "storage": "저장소(S3) 설정",
    "logging": "기록 · 모니터링 미설정",
    "encryption": "암호화 설정",
    "network": "네트워크 설정 (NACL · 아웃바운드 등)",
    "other": "그 밖의 설정",
    "undecidable": "판정할 수 없는 설정",
}
GROUP_ORDER = list(GROUP_KO)
SG_KIND_GROUP = {"mgmt_public": "public_mgmt", "highrisk_public": "public_risky", "all_ports_public": "public_risky", "split_any": "public_risky",
                 "ipv6_any": "public_risky", "vpc_wide": "broad_access", "undecidable": "undecidable"}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

# Trivy 체크 제목 한국어 (화면용). 메타데이터(0.74.0) 원문 제목을 확인한 룰만 옮겼다 — 없는 룰은 원문 제목을 그대로 보여 준다.
TITLE_KO = {
    "AVD-AWS-0010": "CloudFront 접근 기록(Access Logging)이 꺼져 있음",
    "AVD-AWS-0011": "CloudFront 앞에 WAF 가 없음",
    "AVD-AWS-0017": "CloudWatch 로그 그룹을 고객 관리 키(CMK)로 암호화하지 않음",
    "AVD-AWS-0028": "EC2 메타데이터(IMDS)가 토큰(IMDSv2)을 요구하지 않음",
    "AVD-AWS-0034": "ECS 클러스터의 Container Insights 가 꺼져 있음",
    "AVD-AWS-0052": "로드밸런서가 잘못된 HTTP 헤더를 버리지 않음",
    "AVD-AWS-0053": "로드밸런서가 인터넷에 공개됨",
    "AVD-AWS-0054": "로드밸런서 리스너가 암호화 없는 HTTP 를 씀",
    "AVD-AWS-0080": "RDS 인스턴스 암호화가 꺼져 있음",
    "AVD-AWS-0077": "RDS 백업 보존 기간이 기본값(1일)",
    "AVD-AWS-0086": "S3 퍼블릭 액세스 차단: 공개 ACL 을 막지 않음",
    "AVD-AWS-0087": "S3 퍼블릭 액세스 차단: 공개 버킷 정책을 막지 않음",
    "AVD-AWS-0089": "S3 버킷 접근 기록(로깅)이 꺼져 있음",
    "AVD-AWS-0090": "S3 버전 관리가 꺼져 있음",
    "AVD-AWS-0091": "S3 퍼블릭 액세스 차단: 공개 ACL 을 무시하지 않음",
    "AVD-AWS-0092": "S3 버킷이 ACL 로 공개됨",
    "AVD-AWS-0093": "S3 퍼블릭 액세스 차단: 공개 버킷 접근을 제한하지 않음",
    "AVD-AWS-0094": "S3 버킷에 퍼블릭 액세스 차단 설정이 없음",
    "AVD-AWS-0099": "보안 그룹 설명(description)이 없음",
    "AVD-AWS-0101": "기본 VPC 를 사용함",
    "AVD-AWS-0102": "NACL 규칙이 모든 포트를 허용함",
    "AVD-AWS-0104": "보안 그룹 아웃바운드(egress)가 모든 IP 로 열려 있음",
    "AVD-AWS-0105": "NACL 이 SSH · RDP 를 모든 IP 에서 받음",
    "AVD-AWS-0107": "보안 그룹이 SSH · RDP 를 모든 IP 에서 받음",
    "AVD-AWS-0124": "보안 그룹 규칙 설명(description)이 없음",
    "AVD-AWS-0131": "EC2 디스크(블록 디바이스)가 암호화되지 않음",
    "AVD-AWS-0132": "S3 암호화에 고객 관리 키(CMK)를 쓰지 않음",
    "AVD-AWS-0133": "RDS 성능 개선 도우미(Performance Insights)가 꺼져 있음",
    "AVD-AWS-0164": "서브넷이 인스턴스에 공인 IP 를 자동으로 줌",
    "AVD-AWS-0176": "RDS IAM 데이터베이스 인증이 꺼져 있음",
    "AVD-AWS-0177": "RDS 삭제 방지(Deletion Protection)가 꺼져 있음",
    "AVD-AWS-0178": "VPC 흐름 로그(Flow Logs)가 꺼져 있음",
    "AVD-AWS-0342": "iam:PassRole 을 제한 없이 허용 (권한 상승 위험)",
    "AVD-AWS-0345": "IAM 정책이 S3 권한을 제한 없이(s3:*) 허용",
}


def title_ko(rule_id: str, title: str = "") -> str:
    return TITLE_KO.get(rule_id) or title or rule_id


def _port_txt(p: Any) -> str:
    """'MySQL(3306)' · '3306' · '전체' → 화면 제목용 ':3306' 꼴."""
    s = str(p or "").strip()
    m = re.search(r"(\d+(?:-\d+)?)\)?$", s)
    return f":{m.group(1)}" if m else s


def _root() -> Path:
    return cs._root()


@lru_cache(maxsize=1)
def trivy_meta() -> Dict[str, Any]:
    """Trivy 0.74.0 내장 AWS 체크 메타데이터 (scripts/trivy_check_meta.py 가 바이너리에서 뽑은 것). 없으면 빈 dict."""
    p = _root() / "experiments" / "trivy-check-metadata" / "trivy-0.74.0-aws.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def trivy_group(rule_id: str, title: str = "") -> Tuple[str, str]:
    """Trivy 룰 → (화면 묶음, 서비스). 메타데이터의 service · 제목 낱말로만 정한다."""
    m = (trivy_meta().get("checks") or {}).get(rule_id) or {}
    svc = str(m.get("service") or "")
    t = f"{title} {m.get('title', '')}".lower()
    if rule_id == "AVD-AWS-0107":
        return "public_mgmt", svc or "ec2"
    if "egress" in t or "outbound" in t:
        return "network", svc
    if "security group" in t and "ingress" in t:
        return "public_risky", svc
    if svc == "iam" or "iam" in t and "polic" in t:
        return "broad_access", svc or "iam"
    if svc == "s3":
        return "storage", svc
    if "encrypt" in t or svc == "kms" or "plain http" in t or " tls" in t:   # 'CloudWatch log groups should be encrypted' 은 암호화 문제 — 로그보다 먼저
        return "encryption", svc
    if "log" in t or "monitor" in t or "trac" in t or svc in ("cloudtrail", "cloudwatch"):
        return "logging", svc
    if "network acl" in t or "egress" in t or "security group" in t or "description" in t and svc == "ec2":
        return "network", svc
    return "other", svc


def projects_sg_target(resource: str) -> bool:
    """연결한 프로젝트에서 고칠 대상으로 받는 리소스 = 보안 그룹 (규칙 리소스 포함). 판정 기준 = 고객 설계도(통신 구조, V6)."""
    t = str(resource or "").split(".")[-2] if "." in str(resource or "") else ""
    return t.startswith(("aws_security_group", "aws_vpc_security_group"))


def _supported_rules() -> List[str]:
    from ..config import load_json
    try:
        return list((load_json(_root() / "policy" / "patch_policy.json") or {}).get("supported_target_rules") or [])
    except Exception:  # noqa: BLE001
        return []


# ----------------------------------------------------------------------------- 프로젝트
def _sets(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    return cs._sets(case)


def design_set(case: Dict[str, Any], sets: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """이 프로젝트의 고객 설계도(토폴로지)를 담은 묶음 — 없으면 None (설계도 초안부터)."""
    return next((s for s in (sets if sets is not None else _sets(case)) if s.get("intent_kind") == "topology"), None)


def _plan(case: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Dict[str, str], str]:
    from ..evidence import read_tf_files
    from ..verify.plan_model import PlanParseError, load_plan
    pp, src = cs._baseline_plan_path(case)
    if pp is None:
        return None, {}, src
    try:
        plan = load_plan(pp)
    except PlanParseError as e:
        return None, {}, f"원본 plan 조회 실패: {e}"
    try:
        sources = read_tf_files(_root() / case["tf_dir"])
    except Exception:  # noqa: BLE001
        sources = {}
    return plan, sources, src


def _trivy(case: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    from ..review.inputs import load_trivy_report
    p = _root() / case["trivy_json"]
    if not p.exists():
        return None
    try:
        return load_trivy_report(p)
    except Exception:  # noqa: BLE001
        return None


def projects() -> Dict[str, Any]:
    """예제 + 사용자가 연결한 프로젝트 (web/projects.py). 연결한 프로젝트가 먼저."""
    from ..review.inputs import list_findings
    out = []
    for c in cs.all_cases():
        sets = _sets(c)
        ds = design_set(c, sets)
        rep = _trivy(c)
        pp, _src = cs._baseline_plan_path(c)
        n_res = None
        if pp:
            try:
                n_res = len([r for r in json.loads(pp.read_text(encoding="utf-8")).get("resource_changes") or [] if r.get("mode") == "managed"])
            except (OSError, ValueError):
                n_res = None
        tf_root = _root() / c["tf_dir"]
        scan = c.get("scan") or {}
        out.append({"id": c["id"], "name": c["name"], "summary": c["summary"], "kind": c.get("kind", "example"), "tf_dir": c["tf_dir"],
                    "files": len(list(tf_root.glob("*.tf"))) if tf_root.is_dir() else None, "folder_ok": tf_root.is_dir(),
                    "resources": n_res, "scanned": rep is not None, "planned": pp is not None, "scanned_at": scan.get("at"), "scan_why": scan.get("why") or [],
                    "trivy_findings": len([f for f in list_findings(rep) if f.status == "FAIL"]) if rep else None,
                    "design": {"set_id": ds["set_id"], "version": ds.get("design_version", 1)} if ds else None,
                    "requirements": [{"set_id": s["set_id"], "label": s["label"], "kind": s.get("intent_kind"), "rule": s.get("rule"), "resource": s.get("resource")}
                                     for s in sets if s.get("rule") or c.get("kind", "example") == "example"],
                    "testbed": any(s["set_id"] == TESTBED_SET for s in sets)})
    out.sort(key=lambda x: (x["kind"] != "user", x.get("scanned_at") is None, x["name"]))
    return {"projects": out}


def has_testbed(set_id: str) -> bool:
    """실제 AWS 시험 환경(V7 · V8)이 있는 묶음인가. 지금은 3계층 예제 하나."""
    return str(set_id or "") == TESTBED_SET


# ----------------------------------------------------------------------------- ② 현재 인프라 (코드에서)
def infra(pid: str) -> Dict[str, Any]:
    from ..verify.plan_model import PlanParseError, build_world
    from ..verify.sg_scan import scan
    c = cs.get_case(pid)
    if c is None:
        return {"ok": False, "reason": f"프로젝트 없음: {pid}"}
    plan, sources, src = _plan(c)
    files = sorted((_root() / c["tf_dir"]).glob("*.tf"))
    last = c.get("scan") or {}          # 연결한 프로젝트의 마지막 점검 (projects.job_scan 의 last.json)
    base = {"project": {"id": c["id"], "name": c["name"], "tf_dir": c["tf_dir"], "kind": c.get("kind", "example")}, "files": [p.name for p in files],
            "plan_source": src, "scan": {"at": last.get("at"), "why": last.get("why") or []}, "trivy_ok": _trivy(c) is not None}
    if plan is None:
        return {**base, "ok": False, "need_scan": not last.get("at"), "reason": src}
    try:
        world = build_world(plan, sources)
    except PlanParseError as e:
        return {**base, "ok": False, "reason": f"plan 해석 실패: {e}"}
    sc = scan(world, codetopo.vpc_cidr(plan))
    model = codetopo.build(plan, sources, sc["findings"])
    arch = archmap.build(plan, sources, sc["findings"])
    return {**base, "ok": True, "model": model, "arch": arch, "sg_scan": sc}


def _req_versions(set_id: str) -> Dict[str, Any]:
    """요구사항 파일(IAM 등)의 버전 · 확정 상태 (D-40) — ③ '그 밖의 고객 요구사항' 칸과 ⑤ 머리에 쓴다. 못 읽으면 빈 값."""
    from . import designs
    try:
        vs = designs.versions(set_id)
        act = designs.active_version(set_id)
        return {"version": act, "versions": vs, "confirmation": designs.confirmation(set_id, act), "importable": designs.base_path(set_id) is not None,
                "sha256": next((v.get("sha256") for v in vs if v.get("active")), None)}
    except (ValueError, OSError):
        return {"version": 1, "versions": [], "confirmation": None, "importable": False, "sha256": None}


# ----------------------------------------------------------------------------- ③ 고객 설계 (지금 코드와 비교)
def design(pid: str) -> Dict[str, Any]:
    """③ 원하는 구조 (D-33): 지금 코드 구성도 + 원하는 구조(설계도)를 겹친 것. 설계도가 없으면 자동 기준(저장 전)을 같이 준다."""
    from . import designs, structure
    c = cs.get_case(pid)
    if c is None:
        return {"ok": False, "reason": f"프로젝트 없음: {pid}"}
    sets = _sets(c)
    ds = design_set(c, sets)
    reqs = [{"set_id": s["set_id"], "label": s["label"], "kind": s.get("intent_kind"), "rows": s.get("requirements") or [], **_req_versions(s["set_id"])} for s in sets
            if s.get("intent_kind") != "topology"]
    cur = structure.code(pid)
    arch = cur.get("arch") if cur.get("ok") else None
    if ds is None:
        a = structure.auto_design(pid, cur) if cur.get("ok") else {"ok": False, "reason": cur.get("reason")}
        can = bool(a.get("ok") and a["design"]["flows"])
        return {"ok": True, "exists": False, "project": pid, "requirements": reqs, "arch": arch, "plan_ok": bool(cur.get("ok")),
                "can_auto": can, "auto_info": {k: a.get(k) for k in ("excluded", "notes")} if a.get("ok") else None,
                "compare": structure.compare(pid, a["design"], cur, auto=True) if can else None,
                "reason": cur.get("reason") if not cur.get("ok") else (None if can else (a.get("reason") or "위험한 통신을 빼면 남는 통신이 없음 — 그림에서 원하는 통신을 정하세요"))}
    pay = designs.payload(ds["set_id"])
    d = pay.get("design") or {}
    if cur.get("ok") and d.get("kind") == "topology":
        cmp = structure.compare(pid, d, cur)
    else:
        cmp = {"ok": False, "reason": cur.get("reason") if not cur.get("ok") else "통신 구조(토폴로지) 형식 설계도가 아님 — 그림 비교 없음"}
    return {"ok": True, "exists": True, "project": pid, "set_id": ds["set_id"], "design": pay, "requirements": reqs, "arch": arch,
            "plan_ok": bool(cur.get("ok")), "auto": bool(d.get("auto")), "auto_info": d.get("auto"), "compare": cmp}


# ----------------------------------------------------------------------------- ④ 보안 문제 (Trivy + 자체 검사 + 설계 위반 + IAM)
def _trivy_text(rep: Optional[Dict[str, Any]]) -> Dict[Tuple[str, str, int], str]:
    """Trivy JSON 원문의 Description — (룰, 리소스, 시작 줄) 로 찾는다 (Finding 에는 Description 이 없다)."""
    out: Dict[Tuple[str, str, int], str] = {}
    for res in (rep or {}).get("Results") or []:
        for m in res.get("Misconfigurations") or []:
            rid = str(m.get("AVDID") or m.get("ID") or "").strip()
            rid = rid if rid.startswith("AVD-") else f"AVD-{rid}"
            cm = m.get("CauseMetadata") or {}
            out.setdefault((rid, str(cm.get("Resource") or ""), int(cm.get("StartLine") or 0)), str(m.get("Description") or "").strip())
    return out


def _line_of(sources: Dict[str, str], address: str) -> Tuple[str, int]:
    """'aws_security_group.db' → (파일, 줄). 못 찾으면 ('', 0)."""
    import re
    parts = address.split(".")
    if len(parts) < 2:
        return "", 0
    t, n = parts[-2], parts[-1].split("[")[0]
    pat = re.compile(r'^\s*resource\s+"' + re.escape(t) + r'"\s+"' + re.escape(n) + r'"')
    for fn, text in sorted(sources.items()):
        for i, line in enumerate(text.splitlines(), 1):
            if pat.match(line):
                return fn, i
    return "", 0


def issues(pid: str) -> Dict[str, Any]:
    from ..review.inputs import list_findings
    from ..verify.plan_model import PlanParseError, build_world
    from ..verify.sg_scan import scan
    from .problems import _v6_problems, _design_name
    c = cs.get_case(pid)
    if c is None:
        return {"ok": False, "reason": f"프로젝트 없음: {pid}"}
    sets = _sets(c)
    user = c.get("kind") == "user"
    supported = set(_supported_rules())
    target_of = {(s.get("rule"), s.get("resource")): s for s in sets if s.get("rule")}
    ds = design_set(c, sets)
    # 예제: 설계 위반 · 자체 검사 문제는 그 세트(대상 Trivy 지적 + 설계도 V6)로 고친다. 연결한 프로젝트: 아래 대표 대상(같은 방식)
    sg_set = None if user else (ds or next((s for s in sets if s.get("intent_kind") in ("sg", "security_group", None) and s.get("rule") == "AVD-AWS-0107"), None))
    out: List[Dict[str, Any]] = []
    notes: List[str] = []
    plan, sources, psrc = _plan(c)
    model = None
    arch = None
    node_of_sg: Dict[str, str] = {}
    if plan is not None:
        try:
            world = build_world(plan, sources)
            sc = scan(world, codetopo.vpc_cidr(plan))
            model = codetopo.build(plan, sources, sc["findings"])
            arch = archmap.build(plan, sources, sc["findings"])
            for n in model.get("nodes") or []:
                for s in n.get("security_groups") or []:
                    node_of_sg[s] = n["id"]
            notes += sc["notes"]
        except PlanParseError as e:
            sc = {"findings": []}
            notes.append(f"plan 해석 실패 — 자체 보안 그룹 검사 · 설계 비교 판정 불가: {e}")
    else:
        sc = {"findings": []}
        notes.append(f"원본 plan 없음 ({psrc}) — 자체 보안 그룹 검사 · 설계 비교를 하지 못함 (판정 불가)")

    # 1) Trivy
    rep = _trivy(c)
    trivy_by_res: Dict[str, List[Dict[str, Any]]] = {}
    if rep is None:
        notes.append("Trivy 결과 없음 — '원본 점검' 을 먼저 실행")
    desc = _trivy_text(rep)
    meta = trivy_meta().get("checks") or {}
    for f in (list_findings(rep) if rep else []):
        if f.status != "FAIL":
            continue
        grp, svc = trivy_group(f.rule_id, f.title)
        s = target_of.get((f.rule_id, f.resource))
        fw = (meta.get(f.rule_id) or {}).get("frameworks") or {}
        top_level = "/" not in f.filename.replace("\\", "/").strip("/")
        no_plan = user and plan is None          # 연결한 프로젝트에 원본 plan 이 없으면 수정 검사(V3~V6)를 할 수 없다 — 고치기를 내놓지 않는다
        # 연결한 프로젝트는 보안 그룹 대상만 고친다: IAM 은 '이 역할에 꼭 필요한 권한(요구사항)' 을 정하는 화면이 없어서, 고친 뒤 필요한 권한까지
        # 지웠는지 판정할 수 없다 (Trivy 재검사만 통과하는 '권한 전부 삭제' 를 막을 기준 없음) → 탐지만 (예제 2계층은 IAM 요구사항이 있어 고침)
        iam_only = user and not projects_sg_target(f.resource)
        can = f.rule_id in supported and top_level and not no_plan and not iam_only
        how = ("AI 수정 · 직접 고친 파일 → 8개 관문" if can else
               "원본 plan 이 없어 수정 검사를 할 수 없음 — 탐지만 (② 현재 인프라의 이유 참고)" if no_plan and f.rule_id in supported else
               ("탐지만 — 연결한 프로젝트의 IAM 수정은 아직 검사 기준이 없음: 이 역할에 꼭 필요한 권한(요구사항)을 정하는 기능이 없어, "
                "고친 뒤 서비스에 필요한 권한까지 지웠는지 판정할 수 없음") if iam_only and f.rule_id in supported and top_level else
               "하위 폴더(모듈) 파일 — 지원 범위 밖 (탐지만)" if f.rule_id in supported else
               "자동 수정 · 검사 미지원 — 탐지만 (정책상 SG · IAM 일부 룰만 수정 검사)")
        it = {"id": f"trivy:{f.rule_id}:{f.resource}:{f.start_line}", "sources": ["trivy"], "group": grp, "severity": f.severity,
              "title": title_ko(f.rule_id, f.title), "title_en": f.title, "what": f.message or f.title, "resource": f.resource,
              "file": Path(f.filename).name if top_level else f.filename, "line": f.start_line, "rule": f.rule_id, "service": svc,
              "node": node_of_sg.get(f.resource), "flow": None,
              "fix": {"set_id": s["set_id"] if s else None, "auto": can,
                      "target": {"rule": f.rule_id, "resource": f.resource} if (can and not s and user) else None, "how": how},
              "why": desc.get((f.rule_id, f.resource, f.start_line)) or "", "how": f.resolution or "", "text_lang": "en",
              "frameworks": [f"{k.replace('cis-aws-', 'CIS AWS ').replace('default', '').strip()}: {', '.join(v)}" for k, v in fw.items() if v]}
        out.append(it)
        trivy_by_res.setdefault(f.resource, []).append(it)

    # 연결한 프로젝트: 자체 검사 · 설계 위반 문제는 대표 대상(고칠 수 있는 Trivy 지적, SSH · RDP 공개 우선)을 고치는 수정으로 같이 검사한다
    # — 예제 3계층과 같은 방식 (대상 Trivy 지적 V1 + 고객 설계도 V6). 대표 대상이 없으면 '수정 검사 기준(V1)이 없음' 으로 둔다
    rep = None
    if user:
        cands_ = [x for x in out if x["fix"]["auto"]]
        rep = next((x for x in cands_ if x["rule"] == "AVD-AWS-0107"), None) or (cands_[0] if cands_ else None)

    def via_rep(base_how: str) -> Dict[str, Any]:
        if rep is None:
            return {"set_id": None, "target": None, "auto": False,
                    "how": "직접 고친 뒤 다시 점검 — 이 프로젝트에는 고칠 수 있는 Trivy 지적이 없어 수정 검사의 기준(V1)이 없음"}
        return {"set_id": rep["fix"]["set_id"], "target": rep["fix"].get("target"), "auto": True, "via": rep["id"],
                "how": f"{base_how} — '{rep['title']}' 을 고치는 수정으로 같이 검사 (고객 설계 비교 V6 포함)"}

    # 2) 자체 보안 그룹 검사 — 같은 보안 그룹 · 같은 관리 포트를 Trivy 도 찾았으면 한 항목으로 합친다
    for f in sc["findings"]:
        grp = SG_KIND_GROUP.get(f["kind"], "other")
        flow = next((fl["id"] for fl in (model or {}).get("flows") or [] if fl.get("risk_id") == f["id"]), None)
        node = node_of_sg.get(f["security_group"])
        twin = None
        if f["kind"] == "mgmt_public":
            twin = next((t for t in trivy_by_res.get(f["security_group"], []) if t["rule"] == "AVD-AWS-0107"), None)
        file, line = _line_of(sources, f["security_group"])
        what = f"{', '.join(f['resources'][:3])}{' 외' if len(f['resources']) > 3 else ''} ({codetopo.short(f['security_group'])} 보안 그룹): {f['detail']}"
        if twin is not None:
            # 같은 문제를 두 도구가 찾음 → 한 항목. 설명은 자체 검사(한국어), Trivy 원문은 따로 남긴다
            twin["sources"].append("sg")
            twin.update(group=grp, flow=flow, node=node or twin["node"], sg_detail=f["detail"], what=what, sg_id=f["id"],
                        trivy_why=twin["why"], trivy_how=twin["how"], why=_sg_why(f), how=_sg_how(f), text_lang="ko",
                        port_range=[f.get("from_port"), f.get("to_port")])
            continue
        s = target_of.get(("AVD-AWS-0107", f["security_group"])) if f["kind"] == "mgmt_public" else None
        out.append({"id": f["id"], "sg_id": f["id"], "sources": ["sg"], "group": grp, "severity": f["severity"], "title": f["title"], "what": what,
                    "resource": f["security_group"], "file": file, "line": line, "rule": f["kind"], "service": "ec2", "node": node, "flow": flow,
                    "fix": (via_rep("AI(설계도 포함) · 직접 수정") if user and f["kind"] != "undecidable" else
                            {"set_id": s["set_id"] if s else (sg_set["set_id"] if sg_set and f["kind"] != "undecidable" else None),
                             "auto": False, "how": "직접 수정 또는 AI(설계도 포함) → 8개 관문" if f["kind"] != "undecidable" else "판정 불가 — 사람이 확인"}),
                    "why": _sg_why(f), "how": _sg_how(f), "trivy_sees": f["kind"] in ("mgmt_public",) and "0.0.0.0/0" in f["sources"]})

    # 3) 설계 위반 (V6 오라클, 지금 코드 vs 지금 기준 설계도)
    if ds is not None and plan is not None:
        cur = cs.current_state(pid)
        s = next((x for x in cur.get("sets", []) if x.get("set_id") == ds["set_id"]), {}) if cur.get("ok") else {}
        det = s.get("topology") or {}
        dview = ds.get("design") or {}
        design_raw = _design_raw(ds)
        dname = _design_name(None, design_raw)
        flows_by = {}
        for fl in (model or {}).get("flows") or []:
            flows_by.setdefault(fl["dst"], []).append(fl)
        for p in _v6_problems({"details": {"kind": "topology", **det}}, design_raw, dname):
            fl = p.get("flow") or {}
            dst_sg = next((t.get("security_group") for t in dview.get("tiers") or [] if t.get("id") == fl.get("dst_id")), None)
            src_sg = next((t.get("security_group") for t in dview.get("tiers") or [] if t.get("id") == fl.get("src_id")), None)
            node = node_of_sg.get(dst_sg) if dst_sg else None
            if node is None and str(fl.get("dst_id") or "").startswith("res:"):          # 설계도에 없는 리소스 → 그 리소스가 든 묶음
                addr = str(fl["dst_id"])[4:]
                node = next((n["id"] for n in (model or {}).get("nodes") or [] if addr in (n.get("resources") or [])), None)
                dst_sg = next((n.get("security_group") for n in (model or {}).get("nodes") or [] if n["id"] == node), None)
            flow = None
            if node and src_sg and node_of_sg.get(src_sg):
                flow = next((x["id"] for x in flows_by.get(node, []) if x["src"] == node_of_sg[src_sg]), None)
            grp = "design_missing" if p["kind"] == "design_missing" else "design_extra"
            title = f"{fl.get('src')} → {fl.get('dst')} {_port_txt(fl.get('ports'))} — {p['tag']}" if fl.get("src") else p["tag"]
            # 인터넷 → 관리 포트처럼 Trivy · 자체 검사가 이미 같은 규칙을 잡은 것은 한 항목으로 (출처만 더한다)
            #  - 인터넷 · 허용 대역 밖 → 공개 포트 항목 (public_mgmt · public_risky)
            #  - VPC 대역 전체 → 자체 검사의 'VPC 안 모든 서버' 항목 (broad_access) — 고객 설계가 금지한 통신이므로 설계 위반 제목 · 묶음으로 올린다
            src_id = str(fl.get("src_id"))
            if src_id in ("internet", "vpc") or (design_raw and src_id in {str(e.get("id")) for e in design_raw.get("external") or []}):
                port = str(fl.get("ports") or "").split("(")[-1].rstrip(")")
                kinds = ("broad_access",) if src_id == "vpc" else ("public_mgmt", "public_risky")
                twin = next((x for x in out if x["resource"] == dst_sg and x["group"] in kinds and "design" not in x["sources"]
                             and port in str(x.get("what")) + str(x.get("sg_detail") or "")), None)
                if twin is not None:
                    twin["sources"].append("design")
                    twin["design_detail"] = p["what"]
                    if twin["group"] == "broad_access" and "trivy" not in twin["sources"]:
                        twin.update(title=title, group=grp, flow=twin.get("flow") or flow,
                                    severity=min(twin["severity"], "HIGH", key=lambda v: SEV_ORDER.get(v, 9)))
                    continue
            out.append({"id": f"design:{fl.get('src_id')}:{fl.get('dst_id')}:{fl.get('ports')}:{p['kind']}", "sources": ["design"], "group": grp,
                        "severity": "HIGH" if grp == "design_extra" else "MEDIUM", "title": title, "what": p["what"], "why": p["why"], "how": p["how"],
                        "resource": dst_sg or "", "file": _line_of(sources, dst_sg)[0] if dst_sg else "", "line": _line_of(sources, dst_sg)[1] if dst_sg else 0,
                        "rule": f"설계도 v{ds.get('design_version', 1)}", "service": "ec2", "node": node, "flow": flow, "flow_rule": fl.get("rule") or "",
                        "missing": bool(fl.get("missing")),
                        "fix": via_rep("AI(설계도 포함) · 직접 수정") if user else {"set_id": ds["set_id"], "auto": False, "how": "AI(설계도 포함) · 직접 수정 → 8개 관문"},
                        "trivy_sees": False})
    # 4) 보안 그룹 · IAM 요구사항(구버전 형식) 위반 — 지금 코드
    cur2 = cs.current_state(pid) if any(s.get("intent_kind") in ("iam", "sg", "security_group") for s in sets) else {"sets": []}
    for s in cur2.get("sets", []):
        si = next((x for x in sets if x["set_id"] == s.get("set_id")), {})
        if si.get("intent_kind") == "topology":
            continue
        for r in s.get("rows") or []:
            if r.get("verdict") != "FAIL":
                continue
            iam = si.get("intent_kind") == "iam"
            src = "iam" if iam else "requirement"
            text = str(r.get("text") or "")
            why = "; ".join(str(x) for x in (r.get("reasons") or [])[:3])
            # 같은 리소스의 같은 룰을 Trivy 가 이미 찾았으면 한 항목으로 (요구사항 근거만 더한다)
            #  - IAM: 묶음의 대상 룰(예: AVD-AWS-0345)이 요구사항 대상 리소스에서 나옴
            #  - 보안 그룹: 대상 룰(0107) 항목이 있고, 요구사항 줄의 포트가 그 항목이 연 포트와 같음
            twin = None
            if si.get("rule"):
                cands = [x for x in out if x.get("rule") == si["rule"] and x["resource"] in (si.get("targets") or [si.get("resource")]) and src not in x["sources"]]
                if iam:
                    twin = cands[0] if cands else None
                else:
                    pm = re.search(r"\((\d+)(?:-(\d+))?\)", text)
                    if pm:
                        lo, hi = int(pm.group(1)), int(pm.group(2) or pm.group(1))
                        twin = next((x for x in cands if (x.get("port_range") or [None])[0] is not None
                                     and x["port_range"][0] <= lo and hi <= x["port_range"][1]), None)
            if twin is not None:
                twin["sources"].append(src)
                twin["req_detail"] = f"{si.get('label')}: {text}" + (f" — {why}" if why else "")
                continue
            out.append({"id": f"req:{s['set_id']}:{r.get('id')}", "sources": [src], "group": "broad_access" if iam else "design_extra",
                        "severity": "HIGH", "title": f"{'요구사항보다 넓은 권한' if iam else '고객 요구사항 위반'}: {text}"[:120], "what": text,
                        "why": why, "how": "요구사항 범위로 좁히고 다시 검사",
                        "resource": ", ".join((si.get("targets") or [])[:2]), "file": "", "line": 0, "rule": si.get("label"), "service": "iam" if iam else "ec2",
                        "node": None, "flow": None, "fix": {"set_id": s["set_id"], "auto": si.get("rule") in supported, "how": "AI · 직접 수정 → 8개 관문"},
                        "trivy_sees": False})
    out.sort(key=lambda x: (GROUP_ORDER.index(x["group"]) if x["group"] in GROUP_ORDER else 99, SEV_ORDER.get(x["severity"], 9), x["resource"]))
    for x in out:                          # 그림(구성도)에서 이 문제의 자리
        x["focus"] = archmap.focus_for(arch, x) if arch else {"nodes": [], "edges": []}
    counts: Dict[str, int] = {}
    for x in out:
        counts[x["group"]] = counts.get(x["group"], 0) + 1
    return {"ok": True, "project": pid, "issues": out, "groups": [{"key": k, "label": GROUP_KO[k], "count": counts[k]} for k in GROUP_ORDER if counts.get(k)],
            "by_source": {k: sum(1 for x in out if k in x["sources"]) for k in ("trivy", "sg", "design", "iam", "requirement")},
            "only_ours": sum(1 for x in out if "trivy" not in x["sources"] and x["group"] != "undecidable"),
            "design_version": ds.get("design_version", 1) if ds else None, "notes": notes, "model": model, "arch": arch,
            "badges": archmap.badges(out)}


def _design_raw(ds: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    p = ds.get("intent_path")
    if not p:
        return None
    try:
        return json.loads((_root() / p).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _sg_why(f: Dict[str, Any]) -> str:
    k = f["kind"]
    if k == "mgmt_public":
        return "관리 포트(SSH · RDP)가 인터넷 전체에 열려 있으면 누구나 로그인을 시도할 수 있습니다 (무차별 대입 · 취약점 공격 대상)."
    if k in ("highrisk_public", "all_ports_public"):
        return "데이터베이스 · 파일 공유 · 개발 서버 같은 포트는 인터넷에 열려 있으면 바로 공격 대상이 됩니다 (AWS Security Hub EC2.19 의 고위험 포트)."
    if k == "split_any":
        return "대역을 쪼개 적으면 '0.0.0.0/0' 문자열을 찾는 검사기는 못 보지만, 합치면 인터넷 전체에 열린 것과 같습니다."
    if k == "ipv6_any":
        return "IPv4 만 막고 IPv6 전체(::/0)를 열어 두면 IPv6 로 인터넷 어디서나 들어올 수 있습니다."
    if k == "vpc_wide":
        return "출발지를 VPC 대역(IP)으로 열면 VPC 안의 모든 서버(웹 · 관리 서버 포함)가 접근할 수 있습니다. 보안 그룹으로 출발지를 좁혀야 어느 서버인지 구분됩니다."
    return "plan 에서 출처를 확정할 수 없어 안전한지 판단하지 않았습니다 (안전하다고 보지 않음)."


def _sg_how(f: Dict[str, Any]) -> str:
    k = f["kind"]
    if k == "mgmt_public":
        return f"{codetopo.short(f['security_group'])} 보안 그룹의 {f['ports']} 출발지를 관리자 IP 대역(사무실 · VPN)으로 좁히세요."
    if k in ("highrisk_public", "all_ports_public", "split_any", "ipv6_any"):
        return f"{codetopo.short(f['security_group'])} 보안 그룹의 {f['ports']} 규칙 출발지를 필요한 서버의 보안 그룹이나 승인된 대역으로 좁히세요."
    if k == "vpc_wide":
        return f"VPC 대역 대신 접근해야 하는 서버의 보안 그룹을 출발지로 적으세요 ({codetopo.short(f['security_group'])} 보안 그룹)."
    return "plan 값을 확정할 수 있게 코드를 고치거나 사람이 직접 확인하세요."


# ----------------------------------------------------------------------------- 검사 범위 표 (B 문서 1 '검사 범위 매트릭스')
def coverage() -> Dict[str, Any]:
    """리소스 · 유형마다 Trivy 탐지 / 자체 검사 / 자동 수정 / 실제 AWS / 판정 불가 조건. 구현 · 시험된 것만 '지원'.
    Trivy 숫자는 내장 체크 메타데이터(0.74.0)에서 센다 — 탐지 지원이지 수정 지원이 아니다."""
    meta = (trivy_meta().get("checks") or {})
    live = {k: v for k, v in meta.items() if not v.get("deprecated")}
    by_svc: Dict[str, int] = {}
    for v in live.values():
        by_svc[v.get("service") or "?"] = by_svc.get(v.get("service") or "?", 0) + 1
    sg_rules = sorted(k for k, v in live.items() if "security group" in str(v.get("title", "")).lower())
    nacl_rules = sorted(k for k, v in live.items() if "network acl" in str(v.get("title", "")).lower() or "nacl" in str(v.get("title", "")).lower())
    sup = set(_supported_rules())
    Y, N, P = "지원", "미지원", "일부"
    rows = [
        {"resource": "보안 그룹", "type": "관리 포트(SSH 22 · RDP 3389) 인터넷 공개", "trivy": f"{Y} (AVD-AWS-0107)", "ours": f"{Y} (IPv4 대역 합집합 · IPv6 포함)",
         "fix": f"{Y} (AI · 규칙 기반 · 직접 — AVD-AWS-0107)", "aws": f"{P} (3계층 시험 환경만: V7 규칙 조회 · V8 연결 측정)",
         "undecidable": "출처가 plan 시점 미확정 · plan 밖 보안 그룹 ID · 펼칠 수 없는 prefix list"},
        {"resource": "보안 그룹", "type": "고위험 포트 인터넷 공개 (AWS Security Hub EC2.19 포트 24개)", "trivy": f"{P} (SSH · RDP 만 — 0107)",
         "ours": Y, "fix": "직접 수정 · AI(설계도 포함)", "aws": f"{P} (3계층 시험 환경만)", "undecidable": "위와 같음"},
        {"resource": "보안 그룹", "type": "모든 포트 인터넷 공개", "trivy": f"{P} (SSH · RDP 포함 범위면 0107)", "ours": Y, "fix": "직접 수정 · AI", "aws": f"{P} (3계층만)", "undecidable": "위와 같음"},
        {"resource": "보안 그룹", "type": "IP 대역을 쪼개 합치면 인터넷 전체 (0.0.0.0/1 + 128.0.0.0/1)", "trivy": f"{N} (문자열 0.0.0.0/0 만 봄 — 실측: 변형 59개 중 44개 놓침)",
         "ours": Y, "fix": "직접 수정 · AI", "aws": f"{P} (3계층만)", "undecidable": "—"},
        {"resource": "보안 그룹", "type": "IPv6 전체(::/0) 허용", "trivy": "확인 필요", "ours": Y, "fix": "직접 수정 · AI", "aws": f"{P} (3계층만)", "undecidable": "—"},
        {"resource": "보안 그룹", "type": "VPC 대역 전체가 고위험 포트에 접근", "trivy": N, "ours": f"{Y} (주의 등급)", "fix": "직접 수정 · AI", "aws": f"{P} (3계층만)", "undecidable": "VPC 대역을 plan 에서 못 읽으면 검사 안 함"},
        {"resource": "보안 그룹", "type": "고객 설계에 없는 서버 간 통신 (보안 그룹 참조 · IP 대역)", "trivy": N, "ours": f"{Y} (V6 — 설계도 기준)",
         "fix": "AI(설계도 포함) · 직접 수정", "aws": f"{P} (3계층만, V8 차단 측정)", "undecidable": "설계도가 없으면 판정 안 함 · 출처 미확정"},
        {"resource": "보안 그룹", "type": "서비스에 필요한 허용 규칙 누락", "trivy": N, "ours": f"{Y} (V6 — 설계도 기준)", "fix": "AI · 직접 수정", "aws": f"{P} (3계층만, V8 연결 측정)", "undecidable": "같은 포트에 출처 미확정 규칙이 있으면 판정 불가"},
        {"resource": "보안 그룹", "type": "설계도에 없는 리소스로 들어오는 통신", "trivy": N, "ours": f"{Y} (V6 2판)", "fix": "설계도에 추가하거나 코드에서 제거", "aws": N, "undecidable": "—"},
        {"resource": "보안 그룹", "type": "수정으로 새로 생긴 허용 통신 · 허용 범위 밖 리소스 변경", "trivy": N, "ours": f"{Y} (V2 새 지적 · V5 변경 범위 · 후보 영향 분석)",
         "fix": "—", "aws": N, "undecidable": "plan 실패 시"},
        {"resource": "보안 그룹", "type": "아웃바운드(egress) 규칙", "trivy": f"{Y} (AVD-AWS-0104)", "ours": N, "fix": N, "aws": N, "undecidable": "V6 는 인바운드만 봄"},
        {"resource": "보안 그룹", "type": f"그 밖의 보안 그룹 체크 ({len(sg_rules)}개, 설명 누락 등)", "trivy": Y, "ours": N, "fix": "직접 수정만", "aws": N, "undecidable": "—"},
        {"resource": "IAM", "type": "s3:* 무제한 S3 권한", "trivy": f"{Y} (AVD-AWS-0345)", "ours": f"{Y} (V6-IAM: 요구사항이 있을 때 Allow 집합 비교)",
         "fix": (f"{P} (예제 2계층 — IAM 요구사항 있음. 연결한 프로젝트는 탐지만: 요구사항을 정하는 기능 없음)" if "AVD-AWS-0345" in sup else "직접"),
         "aws": f"{N} (V7-IAM 미구현 → 미검증)", "undecidable": "Deny · NotAction · Condition · 관리형 정책 · 미확정 값"},
        {"resource": "IAM", "type": "iam:PassRole 제한 없음", "trivy": f"{Y} (AVD-AWS-0342)", "ours": f"{Y} (V6-IAM)",
         "fix": (f"{P} (요구사항이 있는 예제만 · 연결한 프로젝트는 탐지만)" if "AVD-AWS-0342" in sup else "직접"),
         "aws": f"{N} (미검증)", "undecidable": "위와 같음"},
        {"resource": "IAM", "type": "Action \"*\" (전체 권한)", "trivy": f"{N} (AVD-AWS-0057 deprecated — 0.74.0 에서 안 잡힘)", "ours": f"{Y} (V6-IAM, 요구사항 있을 때)",
         "fix": "직접 · AI", "aws": f"{N} (미검증)", "undecidable": "위와 같음"},
        {"resource": "IAM", "type": "신뢰 정책 Principal \"*\"", "trivy": "확인 필요", "ours": f"{Y} (V6-IAM: Condition 없는 '*' 는 FAIL)", "fix": "직접", "aws": N, "undecidable": "Condition 이 있으면 판정 불가"},
        {"resource": "IAM", "type": f"그 밖의 IAM 체크 ({by_svc.get('iam', 0)}개 중 위 외)", "trivy": Y, "ours": N, "fix": "직접 수정만", "aws": N, "undecidable": "—"},
        {"resource": "S3", "type": f"공개 · 암호화 · 로그 · 버전 관리 등 ({by_svc.get('s3', 0)}개)", "trivy": Y, "ours": N, "fix": f"{N} (탐지만)", "aws": N, "undecidable": "설계 비교(V6) 미지원"},
        {"resource": "NACL · 라우팅", "type": f"NACL 체크 ({len(nacl_rules)}개) · 라우팅", "trivy": f"{Y} (NACL)" if nacl_rules else N, "ours": N, "fix": N,
         "aws": f"{P} (V8 실제 연결 측정에 결과가 섞여 나옴 — 원인 분리 못 함)", "undecidable": "V6 는 보안 그룹 규칙만 봄"},
        {"resource": "그 밖의 AWS 서비스", "type": f"RDS · ELB · CloudFront · 로그 등 ({sum(v for k, v in by_svc.items() if k not in ('ec2', 'iam', 's3'))}개 체크)",
         "trivy": Y, "ours": N, "fix": f"{N} (탐지만)", "aws": N, "undecidable": "—"},
    ]
    return {"trivy_version": trivy_meta().get("trivy_version"), "trivy_checks": len(live), "trivy_by_service": dict(sorted(by_svc.items(), key=lambda kv: -kv[1])),
            "rows": rows, "supported_target_rules": sorted(sup),
            "notes": ["'탐지 지원' 과 '수정 지원' 은 다르다 — Trivy 가 찾는 것을 이 프로그램이 다 고치는 것이 아니다.",
                      "검사 범위를 넓히는 것과 정확도를 높이는 것은 따로 잰다. 같은 문제를 여러 모양으로 바꾼 것을 서로 다른 문제로 세지 않는다.",
                      "AWS 시험 환경 검사(V7 · V8)는 시험 환경이 있는 3계층 예제에서만 한다. 그 밖에는 '미검증' 이다. 운영 환경에는 반영하지 않는다.",
                      "연결한 프로젝트(내 Terraform 폴더)는 보안 그룹 문제만 고치고 검사한다 (기준 = 고객 설계도). AWS 를 조회하는 data 소스 · 모듈이 있으면 plan 을 못 만들어 탐지만 한다.",
                      "IPv6 · 신뢰 정책의 Trivy 지원 여부는 아직 실측하지 않아 '확인 필요' 로 둔다."]}


# ----------------------------------------------------------------------------- ⑤ 후보 영향 (설계도 vs 후보 적용 후 그림)
def _edge_keys(model: Dict[str, Any]) -> Dict[Tuple, Dict[str, Any]]:
    """선 → 비교용 키 (출발 · 도착을 보안 그룹 조합 / 외부 출처 id 로, 포트 범위 하나씩)."""
    nodes = {n["id"]: n for n in model.get("nodes") or []}

    def canon(nid: str) -> str:
        n = nodes.get(nid) or {}
        return "+".join(n.get("security_groups") or []) if n.get("kind") == "tier" else nid
    out: Dict[Tuple, Dict[str, Any]] = {}
    for f in model.get("flows") or []:
        for p, lo, hi in f.get("port_ranges") or []:
            out[(canon(f["src"]), canon(f["dst"]), p, lo, hi)] = f
    return out


def impact(rid: str) -> Dict[str, Any]:
    """검사 기록 하나 → 후보 적용 전 · 후 그림(코드 기반), 추가 · 삭제된 통신, 해결 · 새 문제, 설계 일치."""
    from ..verify.plan_model import PlanParseError, build_world
    from ..verify.sg_scan import scan
    from .server import _read, reviews_root, record_view
    d = reviews_root() / rid
    if ".." in rid or "/" in rid or "\\" in rid or not d.is_dir():
        return {"ok": False, "reason": f"기록 없음: {rid}"}
    lv = d / "local_verify"
    srcs = {p.name: _read(p) for p in sorted((d / "original").glob("*.tf"))}
    after_srcs = dict(srcs)
    after_srcs.update({p.name: _read(p) for p in sorted((d / "candidate").glob("*.tf"))})

    plans: Dict[str, Any] = {}
    archs: Dict[str, Any] = {}

    def model_of(pfile: str, sources: Dict[str, str]) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]], str]:
        p = lv / pfile
        if not p.exists():
            return None, [], "plan 없음 (V4 전에 멈춤)"
        try:
            plan = json.loads(_read(p, 30_000_000))
            sc = scan(build_world(plan, sources), codetopo.vpc_cidr(plan))
            plans[pfile] = plan
            archs[pfile] = archmap.build(plan, sources, sc["findings"])
            return codetopo.build(plan, sources, sc["findings"]), sc["findings"], ""
        except (ValueError, PlanParseError) as e:
            return None, [], f"plan 해석 실패: {e}"
    before, f_before, why_b = model_of("plan_baseline.json", srcs)
    after, f_after, why_a = model_of("plan_candidate.json", after_srcs)
    rv = record_view(rid)
    out: Dict[str, Any] = {"ok": True, "record": rid, "label": rv.get("candidate_label"), "before": before, "after": after,
                           "reason": why_a or why_b, "design_model": rv.get("topology_model"), "design": rv.get("design")}
    # 구성도 (D-33): 적용 전 · 후 그림 + 이 기록의 설계도(원하는 구조)로 본 V6 결과를 겹친다. 판정은 기록 그대로 (다시 판정하지 않음)
    a_b, a_a = archs.get("plan_baseline.json"), archs.get("plan_candidate.json")
    out["arch_before"], out["arch_after"] = a_b, a_a
    try:
        dsg = json.loads((d / "input" / "design.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        dsg = None
    if dsg is None:
        # 설계도 사본이 없는 예전 기록(10-31 이전)은 기록 화면(record_view)과 같게 그 세트의 지금 설계도 파일로 해석한다
        from .server import _set_for_scenario
        try:
            st = json.loads((d / "state.json").read_text(encoding="utf-8"))
            _c, sinfo, _cid = _set_for_scenario(st.get("scenario", ""))
            ip = (sinfo or {}).get("intent_path")
            if ip and (_root() / ip).is_file():
                dsg = json.loads((_root() / ip).read_text(encoding="utf-8"))
                out["design_fallback"] = True
        except (OSError, ValueError):
            dsg = None
    v6det: Dict[str, Any] = {}
    try:
        vj = json.loads((d / "verification.json").read_text(encoding="utf-8"))
        v6det = next((l.get("details") or {} for l in (vj.get("report") or {}).get("layers") or [] if l.get("layer") == "V6"), {}) or {}
    except (OSError, ValueError):
        v6det = {}
    topo_kind = isinstance(dsg, dict) and dsg.get("kind") == "topology"
    if a_a is not None and topo_kind and v6det.get("kind") == "topology":
        out["overlay_after"] = archmap.overlay(a_a, v6det, dsg)
    if a_b is not None and topo_kind and "plan_baseline.json" in plans:
        try:
            from ..topology_intent import parse_topology_intent
            from ..verify.v6 import v6_intent_oracle
            lr = v6_intent_oracle(plans["plan_baseline.json"], srcs, parse_topology_intent(dsg))
            out["overlay_before"] = archmap.overlay(a_b, lr.details if isinstance(lr.details, dict) else {}, dsg)
        except Exception as e:  # noqa: BLE001 — 적용 전 겹쳐 보기는 설명용, 실패는 그대로 알린다
            out["overlay_before_error"] = f"적용 전 비교 실패: {type(e).__name__}"
    if topo_kind and (a_b is not None or a_a is not None):
        # ⑤ 왼쪽 '설계도' 그림 (6차 · D-34): 이 기록을 검사한 설계도만 그린다 — 상자 자리는 적용 전 코드 그림 그대로
        out["design_view"] = archmap.design_view(a_b if a_b is not None else a_a, dsg)
        # 같은 출처는 두 그림에서 같은 이름으로 (대역이 똑같은 외부 출처만)
        out["arch_before"], out["arch_after"] = archmap.name_externals(a_b, dsg), archmap.name_externals(a_a, dsg)
    if a_b is not None and a_a is not None:
        out["arch_diff"] = archmap.diff(out["arch_before"], out["arch_after"])
    if before and after:
        kb, ka = _edge_keys(before), _edge_keys(after)
        names_b = {n["id"]: n["label"] for n in before["nodes"]}
        names_a = {n["id"]: n["label"] for n in after["nodes"]}

        def txt(k, f, names):
            return {"src": names.get(f["src"], f["src"]), "dst": names.get(f["dst"], f["dst"]), "port": "전체" if k[2] == "-1" else (f"{k[3]}" if k[3] == k[4] else f"{k[3]}-{k[4]}"),
                    "flow": f["id"]}
        out["added"] = [txt(k, f, names_a) for k, f in ka.items() if k not in kb]
        out["removed"] = [txt(k, f, names_b) for k, f in kb.items() if k not in ka]
        ib, ia = {f["id"]: f for f in f_before}, {f["id"]: f for f in f_after}
        out["sg_resolved"] = [{"title": f["title"], "detail": f["detail"]} for k, f in ib.items() if k not in ia]
        out["sg_new"] = [{"title": f["title"], "detail": f["detail"]} for k, f in ia.items() if k not in ib]
        out["sg_remaining"] = [{"title": f["title"], "detail": f["detail"]} for k, f in ia.items() if k in ib]
        # 그림용: 후보 그림에 '새로 생긴 선' 표시, 없어진 선은 흐리게 덧그린다
        for f in after["flows"]:
            f["change"] = "added" if any(k[0:2] for k, x in ka.items() if x is f and k not in kb) else None
        gone = []
        anodes = {n["id"] for n in after["nodes"]}
        for k, f in kb.items():
            if k in ka:
                continue
            s, t = f["src"], f["dst"]
            if s in anodes and t in anodes and not any(g["src"] == s and g["dst"] == t for g in gone):
                gone.append({**f, "id": f"gone-{f['id']}", "change": "removed", "risk": None})
        after["flows"] = after["flows"] + gone
    lay = {l.get("layer"): l for l in rv.get("layers") or []}
    out["changes"] = _changes(d)
    out["trivy"] = _trivy_delta(d)
    out["v6"] = {"verdict": (lay.get("V6") or {}).get("verdict"), "summary": (lay.get("V6") or {}).get("summary")}
    out["conclusion"] = rv.get("conclusion")
    return out


def _changes(d: Path) -> Dict[str, Any]:
    """V5 구조 비교: 바뀐 · 추가 · 삭제 리소스 (예상 Terraform 리소스 변경)."""
    try:
        v = json.loads((d / "verification.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    v5 = next((l for l in (v.get("report") or {}).get("layers") or [] if l.get("layer") == "V5"), {}) or {}
    det = v5.get("details") or {}
    return {k: det.get(k) or [] for k in ("changed", "added", "removed", "plan_actions_delete", "plan_actions_replace")} | {"verdict": v5.get("verdict")}


def _trivy_delta(d: Path) -> Dict[str, Any]:
    try:
        v = json.loads((d / "verification.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    L = {l.get("layer"): l for l in (v.get("report") or {}).get("layers") or []}
    v1, v2 = (L.get("V1") or {}).get("details") or {}, (L.get("V2") or {}).get("details") or {}
    def one(f: Any) -> str:
        if isinstance(f, dict):
            return f"{title_ko(str(f.get('rule_id') or ''), str(f.get('title') or ''))} — {f.get('resource')} ({f.get('rule_id')})"
        return str(f)
    tgt = str(v1.get("target_key") or "")
    trule = tgt.split("|")[0] if tgt else ""
    return {"target": f"{title_ko(trule)} — {tgt.split('|')[-1]} ({trule})" if tgt else None, "target_key": tgt or None,
            "target_before": v1.get("present_before"), "target_after": v1.get("present_after"),
            "v1": (L.get("V1") or {}).get("verdict"), "v2": (L.get("V2") or {}).get("verdict"),
            "new": [one(f) for f in v2.get("new") or []], "resolved": [one(f) for f in v2.get("resolved") or []],
            "before": v2.get("before_count"), "after": v2.get("after_count")}


# ----------------------------------------------------------------------------- ⑥ 적용 판단 질문 5개 · ⑧ 최종 정리
QUESTIONS = [("fixed", "기존 문제가 해결됐나요?", ["V1"]), ("new", "새로운 문제가 생겼나요?", ["V2"]), ("valid", "수정 코드가 올바른가요?", ["V3", "V4"]),
             ("scope", "관련 없는 설정까지 바꿨나요?", ["V5"]), ("design", "고객이 원하는 통신 구조를 지키나요?", ["V6"])]


def verdict_view(rid: str) -> Dict[str, Any]:
    """⑥ — 핵심 질문 5개에 대한 답 (기록 값 그대로). 답: 예 · 아니오 · 판정 불가 · 검사 못 함. V 번호는 '자세히' 용으로만 같이 준다."""
    from .server import record_view
    rv = record_view(rid)
    if rv.get("error"):
        return {"ok": False, "reason": rv["error"]}
    lay = {l.get("layer"): l for l in rv.get("layers") or []}
    pol_ok = (rv.get("policy") or {}).get("ok")
    qs = []
    for key, q, layers in QUESTIONS:
        vs = [(lay.get(x) or {}).get("verdict") for x in layers]
        if any(v in (None, "NOT_RUN", "SKIPPED") for v in vs):
            ans, tone = "검사 못 함", "skip"
        elif any(v in ("UNKNOWN", "ERROR") for v in vs):
            ans, tone = "판정 불가", "unknown"
        elif all(v == "PASS" for v in vs):
            ans, tone = {"fixed": ("예, 해결됨", "good"), "new": ("아니오, 새 문제 없음", "good"), "valid": ("예, 올바름", "good"),
                         "scope": ("아니오, 허용 범위 안", "good"), "design": ("예, 지킴", "good")}[key]
        else:
            ans, tone = {"fixed": ("아니오, 남아 있음", "bad"), "new": ("예, 새 문제 있음", "bad"), "valid": ("아니오, 오류", "bad"),
                         "scope": ("예, 범위 밖 변경", "bad"), "design": ("아니오, 어김", "bad")}[key]
        if key == "scope" and pol_ok is False:
            ans, tone = "예, 정책 위반", "bad"
        probs = [p for p in rv.get("problems") or [] if p.get("layer") in layers or (key == "scope" and p.get("layer") in ("정책", "입력"))]
        row = {"key": key, "question": q, "answer": ans, "tone": tone, "layers": layers,
               "summary": " · ".join(str((lay.get(x) or {}).get("summary") or "") for x in layers)[:300], "problems": probs}
        if key == "design":
            # D-38: 비교 기준인 설계도가 초안(확정 전)이면 '예, 지킴' 이라도 고객 요구 충족이 아니다 — 답에 표시하고 확정 뒤 재검사를 안내
            conf = (((rv.get("design") or {}).get("recorded") or {}).get("confirmation")) or None
            if isinstance(conf, dict):
                w = "IAM 요구사항" if str(conf.get("kind") or "") == "iam" else "설계도"      # D-40: IAM 요구사항 파일도 같은 규칙
                row["design_basis"] = conf.get("basis")
                if not conf.get("confirmed"):
                    row["answer"] = f"{ans} — 초안 기준"
                    row["tone"] = "unknown" if tone == "good" else tone
                    row["note"] = (f"비교 기준인 {w}가 아직 초안(확정 전)입니다. 프로그램이 만든 자동 기준 · 저장만 한 수정본 · 올리기만 한 파일은 고객 의도가 아니므로 "
                                   "'고객 요구 충족' 으로 보지 않습니다. ③ 에서 담당자가 확정한 뒤 다시 검사하세요.")
                elif conf.get("basis") == "manifest":
                    row["note"] = f"비교 기준 = 팀이 작성한 평가 기준 {w} (실험 세트). 고객이 확정한 {w}와 구분해서 읽어야 합니다."
                else:
                    row["note"] = f"비교 기준 = {conf.get('by') or '담당자'} 가 확정한 {w} v{conf.get('version') or ''}" + (f" ({str(conf.get('at') or '')[:16].replace('T', ' ')})" if conf.get("at") else "")
        qs.append(row)
    from .decision import can_approve
    from .server import reviews_root
    try:
        st = json.loads((reviews_root() / rid / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        st = {}
    ok, why = can_approve(st)
    ok2, why2 = (True, "") if ok else can_approve(st, True)
    return {"ok": True, "record": rid, "label": rv.get("candidate_label"), "conclusion": rv.get("conclusion"), "questions": qs,
            "approve": {"ok": ok, "why": why, "needs_ack": (not ok) and ok2, "ack_note": why2 if (not ok and ok2) else ""},
            "unchecked": rv.get("unchecked"), "post_deploy": rv.get("post_deploy"), "design": rv.get("design"), "set": rv.get("set"),
            "decision": rv.get("decision"), "decision_ko": rv.get("decision_ko"), "pr_draft": rv.get("pr_draft"),
            "testbed": ((rv.get("set") or {}).get("set_id") == TESTBED_SET)}


def _trivy_rest(d: Path, tr: Dict[str, Any]) -> Optional[int]:
    """수정 뒤에도 그대로인 Trivy 지적 수 (이번 수정의 대상 · 새로 생긴 것 제외). 파일이 없으면 None."""
    from ..review.inputs import list_findings
    p = d / "local_verify" / "trivy_after.json"
    if not p.exists():
        return None
    try:
        rep = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    keys = {f.key for f in list_findings(rep) if f.status == "FAIL"}
    keys.discard(str(tr.get("target_key") or ""))
    return max(0, len(keys) - len(tr.get("new") or []))


def _design_delta(d: Path) -> Optional[Dict[str, List[str]]]:
    """원본 코드에서 이미 있던 설계 위반(같은 기록의 설계도 사본 input/design.json 기준) 중 후보가 없앤 것 · 그대로 둔 것.
    설계도 사본 · 원본 plan · 후보 V6 결과 중 하나라도 없으면 None (비교 안 함)."""
    from ..iam_intent import try_load_any_intent
    from ..verify.plan_model import PlanParseError, load_plan
    from ..verify.v6 import v6_intent_oracle
    dj, pb = d / "input" / "design.json", d / "local_verify" / "plan_baseline.json"
    try:
        v = json.loads((d / "verification.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    v6 = next((x for x in (v.get("report") or {}).get("layers") or [] if x.get("layer") == "V6"), {}) or {}
    if not dj.exists() or not pb.exists() or v6.get("verdict") not in ("PASS", "FAIL"):
        return None
    spec, kind, err = try_load_any_intent(dj)
    if kind != "topology" or spec is None:
        return None
    try:
        plan = load_plan(pb)
    except PlanParseError:
        return None
    srcs = {p.name: p.read_text(encoding="utf-8", errors="replace") for p in sorted((d / "original").glob("*.tf"))}
    base = v6_intent_oracle(plan, srcs, spec, err)
    bdet = base.details if isinstance(base.details, dict) else {}

    def keys(det: Dict[str, Any]) -> Dict[Tuple[str, str, str], str]:
        out = {}
        for e in det.get("excess") or []:
            out[(str(e.get("src")), str(e.get("dst")), str(e.get("ports")))] = f"{e.get('src_label') or e.get('src')} → {e.get('dst_label') or e.get('dst')} :{e.get('ports')}"
        for f in det.get("flows") or []:
            if f.get("status") == "broken":
                out[("missing", str(f.get("src")), str(f.get("dst")) + str(f.get("ports")))] = f"{f.get('src_label')} → {f.get('dst_label')} :{f.get('ports')} (허용 규칙 없음)"
        return out
    kb, kc = keys(bdet), keys(v6.get("details") or {})
    return {"resolved": [t for k, t in kb.items() if k not in kc], "kept": [t for k, t in kb.items() if k in kc],
            "new": [t for k, t in kc.items() if k not in kb]}


def final_view(rid: str) -> Dict[str, Any]:
    """⑧ — 해결된 문제 / 남아 있는 문제 / 새로 생긴 문제 / 고객 설계 위반 / 검증하지 못한 부분 / 실제 AWS 결과.
    계산하지 못한 칸은 빈 목록이 아니라 None(= '검사 못 함')으로 준다 — '0개' 와 '안 봄' 을 섞지 않는다."""
    from .server import reviews_root
    vv = verdict_view(rid)
    if not vv.get("ok"):
        return vv
    im = impact(rid)
    tr = im.get("trivy") or {}
    q = {x["key"]: x for x in vv["questions"]}
    have_after = im.get("after") is not None
    resolved = [f"Trivy: {x}" for x in (tr.get("resolved") or [])][:8] + [f"자체 검사: {x['title']} — {x['detail']}" for x in im.get("sg_resolved") or []]
    remaining = ([f"Trivy: {tr.get('target')} — 이번 수정의 대상인데 남음"] if tr.get("v1") == "FAIL" else []) + \
        [f"자체 검사: {x['title']} — {x['detail']}" for x in im.get("sg_remaining") or []]
    rest = _trivy_rest(reviews_root() / rid, tr)
    dd = _design_delta(reviews_root() / rid)
    if dd:
        resolved += [f"고객 설계 위반 해결: {x}" for x in dd["resolved"]]
    new = [f"Trivy: {x}" for x in (tr.get("new") or [])] + [f"자체 검사: {x['title']} — {x['detail']}" for x in im.get("sg_new") or []]
    v6 = (q.get("design") or {}).get("answer")
    design = [p["what"] for p in (q.get("design") or {}).get("problems") or []] if v6 not in ("검사 못 함", None) else None
    unverified = [f"{x['question']} — {x['answer']}" for x in vv["questions"] if x["tone"] in ("skip", "unknown")]
    if not have_after:
        unverified.append("자체 보안 그룹 검사(수정 뒤) — 수정안 plan 이 없어 계산 못 함")
    if dd is None and design is not None:
        unverified.append("원본 대비 고객 설계 위반 변화 — 이 기록에 설계도 사본이 없어 비교 안 함 (지금 결과만 표시)")
    unverified += list(vv.get("unchecked") or [])
    post = vv.get("post_deploy") or {}
    # 글자 규칙 (검토 문서 11-02): 'AWS 시험 환경(샌드박스)에서 확인' 이지 운영 반영 후 확인이 아니다 — 통과 문장에 그 사실을 같이 적는다
    aws = {"status": post.get("status"), "text": {"VERIFIED": "AWS 시험 환경에서 확인됨 — 운영 반영 후 확인 아님", "DEPLOY_FAILED": "AWS 시험 환경 적용 실패",
                                                  "PLAN_BLOCKED": "AWS 시험 환경 반영 전 차단", "UNVERIFIED": "AWS 시험 환경 판정 불가"}.get(str(post.get("status")),
                                                  "미검증 — AWS 시험 환경 검사(V7 · V8)를 하지 않음" if vv.get("testbed") else "미검증 — 이 프로젝트에는 AWS 시험 환경이 없음")}
    if not post.get("status") and (vv.get("decision") or {}).get("aws_unverified_ack"):
        aws["text"] += " · 승인한 사람이 미검증을 확인하고 승인함"
    # 이 판정을 만든 판 (D-37): 기록의 provenance(검사 당시) + 도구 · 정책 · 설계도 버전 — ⑧ 아래 '이 판정의 버전' 칸
    try:
        st_json = json.loads((reviews_root() / rid / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        st_json = {}
    prov = st_json.get("provenance") if isinstance(st_json.get("provenance"), dict) else None
    try:                                                   # 예전 기록(버전 묶음 없음)도 정책 판은 policy.json 에 있다
        pol_json = json.loads((reviews_root() / rid / "policy.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pol_json = {}
    versions = {"program": (prov or {}).get("program_version"), "commit": ((prov or {}).get("build") or {}).get("sha") or ((prov or {}).get("git_head") or {}).get("sha"),
                "src_fingerprint": ((prov or {}).get("build") or {}).get("src_fingerprint") or (prov or {}).get("src_fingerprint"),
                "policy": (prov or {}).get("policy_version") or (pol_json.get("policy_version") if isinstance(pol_json, dict) else None),
                "rubric": (prov or {}).get("rubric_version"), "prompt": (prov or {}).get("prompt_version"),
                "tools": st_json.get("local_tools") or {}, "design": vv.get("design"), "recorded": bool(prov)}
    new_out = new if (tr or have_after) else None
    return {**vv, "resolved": resolved, "remaining": remaining, "remaining_other_trivy": rest, "new": new_out,
            "design_delta": dd, "versions": versions,
            "sg_computed": have_after, "design_violations": design, "aws": aws, "unverified": unverified,
            "opened": [f"{a['src']} → {a['dst']} :{a['port']}" for a in im.get("added") or []],
            "closed": [f"{a['src']} → {a['dst']} :{a['port']}" for a in im.get("removed") or []],
            "closing": _closing(vv, resolved, remaining, new_out, design, unverified, aws)}


# ----------------------------------------------------------------------------- ⑦ AWS 시험 환경 (9차, D-43): 전문가 화면 5단계와 같은 API 를 새 화면에서
def testbed_view(rid: str) -> Dict[str, Any]:
    """⑦ 의 재료: 시험 환경 상태(measure_setup) + 측정 요약(post before/after) + 이 기록의 시험 환경 결과. 판정은 만들지 않는다 —
    '다음 작업' 은 화면의 stage2Plan(flow2.js, 전문가 화면과 같은 함수)이 이 값으로 정한다. 반영 · 측정은 POST /api/testbed/* · /api/measure (사람 확인 창)."""
    from .proof_api import _record_dir, measure_setup
    from ..proof.postcards import _j, find_measurements
    rd = _record_dir(rid) if rid else None
    if rid and rd is None:
        return {"ok": False, "reason": f"기록 없음: {rid}"}
    try:
        m = measure_setup(rid or "")
    except Exception as e:           # 설정 · 폴더 문제는 화면에 글자로
        m = {"error": str(e)}
    st = (_j(rd / "state.json") or {}) if rd is not None else {}
    post = {"before": {"dir": None, "status": None, "at": None}, "after": {"dir": None, "status": None, "at": None}}
    try:
        base = rd if rd is not None else (_root() / "data" / "reviews" / "__none__")
        mm = find_measurements(base, _root())
        bdir, adir = mm.get("before"), mm.get("after")
        bdoc = _j(bdir / "measure.json") if bdir else None
        adoc = _j(adir / "measure.json") if adir else None
        post["before"] = {"dir": bdir.name if bdir else None, "status": (bdoc or {}).get("status"), "at": (bdoc or {}).get("started_at")}
        pd = st.get("post_deploy") if isinstance(st.get("post_deploy"), dict) else {}
        if pd.get("status") == "PLAN_BLOCKED":
            post["after"] = {"dir": pd.get("path"), "status": "PLAN_BLOCKED", "at": pd.get("at")}
        else:
            post["after"] = {"dir": adir.name if adir else None, "status": (adoc or {}).get("status"), "at": (adoc or {}).get("started_at")}
    except Exception:
        pass
    pd = st.get("post_deploy") if isinstance(st.get("post_deploy"), dict) else None
    return {"ok": True, "record": rid or None, "m": m, "post": post, "post_deploy": pd,
            "passed": bool(m.get("record_passed")) if isinstance(m, dict) else False,
            "steps": ["원본 반영", "수정 전 측정", "수정안 반영", "수정 후 측정", "시험 환경 삭제"]}


def _closing(vv: Dict[str, Any], resolved: List[str], remaining: List[str], new: Optional[List[str]], design: Optional[List[str]],
             unverified: List[str], aws: Dict[str, Any]) -> Dict[str, Any]:
    """기록의 끝맺음 세 줄 (검토 문서 11-02: 모든 시나리오는 '무엇을 확인했고 · 누가 어떤 결정을 했고 · 무엇이 남았는지' 로 끝난다).
    새로 판정하지 않는다 — 결론 · 결정 기록 · 미검증 목록을 문장으로 옮길 뿐."""
    c = vv.get("conclusion") or {}
    n = lambda xs: "검사 못 함" if xs is None else f"{len(xs)}개"
    checked = (f"배포 전 검사(V1~V6): {c.get('status') or c.get('title') or '결과 없음'} — 해결 {n(resolved)} · 남음 {n(remaining)} · 새 문제 {n(new)} · 고객 설계 위반 {n(design)}. "
               f"AWS 시험 환경: {aws.get('text') or '기록 없음'}")
    dec = vv.get("decision") or {}
    if dec.get("decision"):
        at = str(dec.get("at") or "")[:16].replace("T", " ")
        decided = f"{vv.get('decision_ko') or dec.get('decision')} — {dec.get('by') or '이름 없음'}{' · ' + at if at else ''}" + (f" · 이유: {dec.get('reason')}" if dec.get("reason") else "")
        if dec.get("aws_unverified_ack"):
            decided += " · 실제 AWS 미검증을 알고 승인"
    else:
        decided = "아직 결정 없음 — 사람이 ⑧ 에서 승인 · 수정 요청 · 재생성 · 폐기 중 하나를 기록"
    left = list(unverified or [])
    if dec.get("decision") == "APPROVED":
        left.append("PR 만들기(확인 문구) → GitHub 에서 검토 · 병합 → 운영 반영은 이 프로그램 밖 (사람)")
    elif not dec.get("decision"):
        left += [x for x in (c.get("next") or []) if x and "폐기" not in x][:3]
    return {"checked": checked, "decided": decided, "left": left}
