"""사례(case) — 화면이 다루는 단위. 원본 Terraform 폴더 하나 + 사람이 적은 요구사항(intent) + 수정 후보 세트.

화면 흐름 6단계가 전부 이 모듈의 자료로 돈다.
  1. 요구사항 확인      case_summary()      요구사항 문장, Trivy 가 찾은 것 중 검토 대상/판단 안 함 분류, 아키텍처 요약
  2. 현재 설정의 문제   current_state()     원본 plan 에 요구사항을 대입 (verify/v6 의 같은 오라클)
  3. 수정 후보 비교     candidates()        후보 목록 + 후보별 최신 기록 + 분류
  4~6 은 기록(record) 단위 — server.py 의 record_view() 가 explain 과 함께 만든다.

사례 정의: 예제는 아래 CASES (후보 세트·요구사항 파일은 experiments/candidate-sets 의 manifest 그대로),
사용자가 연결한 프로젝트는 data/projects/<id>/ (web/projects.py — 폴더를 경로로 연결, 복사 · 쓰기 없음, 2026-11-01 D-32).
프로젝트의 세트 id 는 '<프로젝트>.<이름>' (점이 있음 — 예제 세트 id 에는 점이 없다).
AWS·LLM 호출 없음. terraform 은 원본 plan 이 어디에도 없을 때만(도구가 있으면) 오프라인 plan 을 만든다.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..evidence import read_tf_files
from ..iam_intent import try_load_any_intent
from ..review.inputs import list_findings, load_trivy_report
from ..verify.plan_model import PlanParseError, load_plan
from ..verify.v6 import v6_intent_oracle
from . import explain

CASES: List[Dict[str, Any]] = [
    {
        "id": "webapp-3tier",
        "name": "3계층 웹 서비스",
        "summary": "사용자 → CloudFront·WAF → ALB → 웹 서버 → NLB → API 서버 → Redis·MySQL(주·복제). 관리자는 Bastion 경유로 서버 접속. 가용 영역 2곳, 공개·비공개 서브넷 분리.",
        "tf_dir": "scenarios/arch/webapp-3tier",
        "trivy_json": "experiments/arch-webapp-3tier/trivy-scan.json",
        "sets": [
            {"set_id": "arch-3tier-sg", "role": "primary", "label": "계층 간 통신 (보안 그룹)"},
        ],
    },
    {
        "id": "webapp-2tier",
        "name": "공개 웹 서버 + 앱 서버",
        "summary": "인터넷 공개 웹 서버(공개 서브넷), 웹 서버만 호출 가능한 앱 서버(비공개 서브넷), 정적 자산 버킷, 웹 서버의 버킷 조회용 역할로 구성된 소규모 서비스.",
        "tf_dir": "scenarios/arch/webapp-2tier",
        "trivy_json": "experiments/arch-webapp-2tier/trivy-scan.json",
        "sets": [
            {"set_id": "arch-webapp-sg", "role": "primary", "label": "네트워크 접근 (보안 그룹)"},
            {"set_id": "arch-webapp-iam", "role": "secondary", "label": "웹 서버 역할의 권한 (IAM)"},
        ],
    },
]


def _root() -> Path:
    from .. import app as _app
    return _app.ROOT


def _read_json(p: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")


def projects_root() -> Path:
    """사용자가 연결한 프로젝트의 기록 (data/projects). 시험은 IACPATCH_PROJECTS_DIR 로 바꾼다."""
    env = os.environ.get("IACPATCH_PROJECTS_DIR")
    return Path(env) if env else _root() / "data" / "projects"


def _project_case(d: Path) -> Optional[Dict[str, Any]]:
    meta = _read_json(d / "project.json")
    if not meta or not PROJECT_ID_RE.match(str(meta.get("id") or "")) or meta.get("id") != d.name or not meta.get("path"):
        return None
    sets = []
    for m in sorted((d / "sets").glob("*/manifest.json")) if (d / "sets").is_dir() else []:
        man = _read_json(m) or {}
        sets.append({"set_id": m.parent.name, "role": "primary" if not man.get("rule") else "target", "label": man.get("label") or m.parent.name})
    scan = _read_json(d / "scan" / "last.json") or {}
    return {"id": meta["id"], "name": meta.get("name") or meta["id"], "kind": "user", "path": meta["path"],
            "summary": meta.get("summary") or f"연결한 Terraform 폴더 — {meta['path']}",
            "tf_dir": meta["path"], "trivy_json": str(d / "scan" / "trivy.json"), "plan_json": str(d / "scan" / "plan_baseline.json"),
            "created_at": meta.get("created_at"), "scan": scan, "sets": sets}


def user_projects() -> List[Dict[str, Any]]:
    root = projects_root()
    if not root.is_dir():
        return []
    return [c for d in sorted(root.iterdir(), key=lambda x: x.name) if d.is_dir() for c in [_project_case(d)] if c]


def all_cases() -> List[Dict[str, Any]]:
    """예제(CASES) + 사용자가 연결한 프로젝트."""
    return [dict(c, kind=c.get("kind", "example")) for c in CASES] + user_projects()


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    for c in all_cases():
        if c["id"] == case_id:
            return c
    return None


def case_of_set(set_id: str) -> Optional[Dict[str, Any]]:
    return next((c for c in all_cases() if any(s["set_id"] == set_id for s in c.get("sets", []))), None)


def list_cases() -> List[Dict[str, Any]]:
    return [{"id": c["id"], "name": c["name"], "summary": c["summary"]} for c in all_cases()]


# ----------------------------------------------------------------------------- 세트 / 요구사항
def _manifest_path(set_id: str) -> Path:
    """예제 세트 = experiments/candidate-sets/<세트>/manifest.json, 프로젝트 세트('<프로젝트>.<이름>') = data/projects/<프로젝트>/sets/<세트>/manifest.json."""
    sid = str(set_id or "")
    if "." in sid:
        pid = sid.split(".", 1)[0]
        if PROJECT_ID_RE.match(pid) and "/" not in sid and "\\" not in sid:
            return projects_root() / pid / "sets" / sid / "manifest.json"
    return _root() / "experiments" / "candidate-sets" / sid / "manifest.json"


def _manifest(set_id: str) -> Tuple[Optional[Dict[str, Any]], Path]:
    p = _manifest_path(set_id)
    return _read_json(p), p.parent


def project_of_set(set_id: str) -> Optional[str]:
    """프로젝트 세트면 그 프로젝트 id (설계도는 프로젝트 하나에 하나 — 세트마다 따로 두지 않는다)."""
    if "." not in str(set_id or ""):
        return None
    man, _ = _manifest(set_id)
    pid = (man or {}).get("project")
    return pid if isinstance(pid, str) and PROJECT_ID_RE.match(pid) else None


def _resolve(rel: Optional[str], set_dir: Path) -> Optional[Path]:
    if not rel:
        return None
    p = Path(rel)
    if p.is_absolute():
        return p
    cand = _root() / rel
    if cand.exists():
        return cand
    cand2 = set_dir / rel
    return cand2 if cand2.exists() else cand


def load_set(case: Dict[str, Any], set_ref: Dict[str, Any]) -> Dict[str, Any]:
    man, set_dir = _manifest(set_ref["set_id"])
    out: Dict[str, Any] = {"set_id": set_ref["set_id"], "role": set_ref.get("role", "primary"), "label": set_ref.get("label", set_ref["set_id"]),
                           "ok": man is not None, "intent": None, "intent_kind": None, "intent_error": None, "requirements": [],
                           "rule": None, "resource": None, "intent_path": None, "manifest": man}
    if man is None:
        out["intent_error"] = "후보 세트 없음"
        return out
    out["rule"], out["resource"] = man.get("rule"), man.get("resource")
    ipath = _resolve(man.get("intent"), set_dir)
    # 지금 기준 설계도 (D-30): 화면에서 고친 버전이 있으면 그것 — 없으면 manifest 의 설계도(v1)
    from . import designs
    try:
        act = designs.active_path(set_ref["set_id"])
        out["design_version"] = designs.active_version(set_ref["set_id"]) if act is not None and act != ipath else 1
        out["design_versions"] = len(designs.versions(set_ref["set_id"]))
    except ValueError:
        act = None
    if act is not None:
        ipath = act
    out["intent_path"] = str(ipath.relative_to(_root())) if ipath and str(ipath).startswith(str(_root())) else (str(ipath) if ipath else None)
    if ipath is None or not ipath.exists():
        out["intent_error"] = "요구사항 파일 없음"
        return out
    spec, kind, err = try_load_any_intent(ipath)
    out["intent_kind"], out["intent_error"] = kind, err
    if spec is None:
        return out
    out["intent"] = spec
    out["intent_status"] = getattr(spec, "status", "")
    out["description"] = getattr(spec, "description", "")
    out["requirements"] = explain.requirements_for(kind, spec)
    out["targets"] = list(getattr(spec, "target_security_groups", []) or []) + list(getattr(spec, "target_roles", []) or []) + list(getattr(spec, "target_policies", []) or [])
    if kind == "topology":   # 화면이 설계도(외부 출발지·계층·VPC 대역)를 그대로 보여 줄 수 있게
        out["design"] = {"vpc_cidr": spec.vpc_cidr,
                         "external": [{"id": e.id, "label": e.label, "cidrs_v4": list(e.cidrs_v4)} for e in spec.external],
                         "tiers": [{"id": t.id, "label": t.label, "security_group": t.security_group,
                                    "type": next((x.get("type") for x in spec.raw.get("tiers") or [] if x.get("id") == t.id), None)} for t in spec.tiers],
                         "flows": [{"id": f.id, "from": f.src, "to": f.dst, "protocol": f.protocol, "ports": f.ports, "label": f.label} for f in spec.flows]}
    return out


def _sets(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [load_set(case, s) for s in case.get("sets", [])]


# ----------------------------------------------------------------------------- Trivy finding 분류
def findings_classified(case: Dict[str, Any], sets: List[Dict[str, Any]]) -> Dict[str, Any]:
    p = _root() / case["trivy_json"]
    if not p.exists():
        return {"ok": False, "need_scan": True, "error": "원본 점검 결과 없음 — '원본 점검 실행' 시 이 PC 의 Trivy·Terraform 으로 생성",
                "in_scope": [], "out_of_scope": [], "total": 0}
    try:
        report = load_trivy_report(p)
    except Exception as e:  # 점검 결과가 없으면 그대로 말한다
        return {"ok": False, "error": f"점검 결과 조회 실패: {e}", "in_scope": [], "out_of_scope": [], "total": 0}
    # 설계도(토폴로지) 의도가 '인터넷 전체 → 이 계층' 을 허용하는 보안 그룹이면, 그 공개 입구에 대한 지적은 설계상 허용으로 분류한다
    public_entry: Dict[str, str] = {}
    for s in sets:
        spec = s.get("intent")
        if s.get("intent_kind") == "topology" and spec is not None:
            wide = {e.id for e in spec.external if "0.0.0.0/0" in e.cidrs_v4}
            for f in spec.flows:
                if f.src in wide:
                    sg = next((t.security_group for t in spec.tiers if t.id == f.dst), None)
                    if sg:
                        public_entry[sg] = f"설계도의 공개 진입 경로({spec.label_of(f.src)} → {spec.label_of(f.dst)} {f.ports}) — 설계상 허용"
    findings = list_findings(report)
    covered = {}
    for s in sets:
        if s.get("rule") and s.get("resource"):
            covered[(s["rule"], s["resource"])] = s
    in_scope, out_scope = [], []
    for f in findings:
        d = {"rule_id": f.rule_id, "severity": f.severity, "resource": f.resource, "file": f.filename, "line": f.start_line, "title": f.title, "message": f.message}
        s = covered.get((f.rule_id, f.resource))
        if s is not None:
            d["set_id"], d["set_label"] = s["set_id"], s["label"]
            in_scope.append(d)
        else:
            d["why"] = public_entry.get(f.resource) if f.rule_id == "AVD-AWS-0107" and f.resource in public_entry else "이 설정에 대한 요구사항 없음 → 판정 대상 아님"
            out_scope.append(d)
    return {"ok": True, "total": len(findings), "in_scope": in_scope, "out_of_scope": out_scope,
            "scan_created_at": report.get("CreatedAt"), "trivy_version": (report.get("Trivy") or {}).get("Version")}


# ----------------------------------------------------------------------------- 원본 plan 찾기 / 아키텍처 요약
def _baseline_plan_path(case: Dict[str, Any]) -> Tuple[Optional[Path], str]:
    root = _root()
    tf_dir = case["tf_dir"]
    if case.get("plan_json"):          # 연결한 프로젝트: 프로젝트 점검이 만든 plan 만 쓴다 (다른 기록과 섞지 않음)
        pj = Path(case["plan_json"])
        when = str((case.get("scan") or {}).get("at") or "").replace("T", " ")[:16]
        if pj.exists():
            return pj, f"원본 plan (프로젝트 점검 {when})".replace(" )", ")")
        # 점검을 했는데 plan 이 없으면 '먼저 점검하라' 가 아니라 '점검에서 만들지 못함' (이유는 점검 기록의 why — 화면에 따로 나옴)
        return None, (f"원본 plan 없음 — {when} 점검에서 plan 을 만들지 못함 (아래 이유)" if when else "원본 plan 없음 — 프로젝트 점검(Trivy · plan)을 먼저")
    # 1) 원본 캐시 (같은 원본·도구로 만든 plan)
    cache_root = root / "data" / "cache" / "baseline"
    if cache_root.is_dir():
        hits = []
        for d in cache_root.iterdir():
            meta = _read_json(d / "meta.json") or {}
            pj = d / "plan_baseline.json"
            if pj.exists() and str(meta.get("tf_dir", "")).replace("\\", "/").endswith(tf_dir):
                hits.append((pj.stat().st_mtime, pj, meta.get("created_at", "")))
        if hits:
            hits.sort(reverse=True)
            when = str(hits[0][2] or "").replace("T", " ")[:16]
            return hits[0][1], (f"원본 plan ({when} 생성)" if when else "원본 plan")
    # 2) 이 사례의 기록 중 가장 최근 것
    for rid, st, d in _records_for(tf_dir):
        pj = d / "local_verify" / "plan_baseline.json"
        if pj.exists():
            return pj, "가장 최근 검토 기록의 원본 plan"
    return None, "원본 plan 없음"


def _records_for(tf_dir: str) -> List[Tuple[str, Dict[str, Any], Path]]:
    from .server import reviews_root
    out = []
    rr = reviews_root()
    if not rr.is_dir():
        return out
    for d in sorted(rr.iterdir(), reverse=True):
        st = _read_json(d / "state.json")
        if st and str(st.get("tf_dir", "")).replace("\\", "/").rstrip("/").endswith(tf_dir):
            out.append((d.name, st, d))
    return out


def architecture(plan: Optional[Dict[str, Any]], sources: Dict[str, str]) -> Dict[str, Any]:
    """plan 에서 그림에 필요한 것만: 서브넷(공개/비공개), 서버(어느 서브넷·어느 보안 그룹·역할), 버킷, 역할."""
    arch: Dict[str, Any] = {"subnets": [], "instances": [], "buckets": [], "roles": [], "security_groups": [], "source": "plan" if plan else "none"}
    if not plan:
        return arch
    pv = (plan.get("planned_values") or {}).get("root_module") or {}
    cfg = {r.get("address"): r for r in ((plan.get("configuration") or {}).get("root_module") or {}).get("resources") or []}

    def refs(addr: str, key: str) -> List[str]:
        ex = (cfg.get(addr) or {}).get("expressions") or {}
        v = ex.get(key)
        out: List[str] = []
        if isinstance(v, dict):
            out = [r for r in v.get("references") or [] if r.count(".") == 1]
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    out += [r for r in item.get("references") or [] if r.count(".") == 1]
        return out

    for r in pv.get("resources") or []:
        a, t, v = r.get("address"), r.get("type"), r.get("values") or {}
        if t == "aws_subnet":
            arch["subnets"].append({"address": a, "name": a.split(".")[-1], "cidr": v.get("cidr_block"), "public": bool(v.get("map_public_ip_on_launch"))})
        elif t == "aws_instance":
            arch["instances"].append({"address": a, "name": a.split(".")[-1], "subnet": (refs(a, "subnet_id") or [None])[0],
                                      "security_groups": refs(a, "vpc_security_group_ids"), "role_profile": (refs(a, "iam_instance_profile") or [None])[0]})
        elif t == "aws_s3_bucket":
            arch["buckets"].append({"address": a, "name": v.get("bucket") or a.split(".")[-1]})
        elif t == "aws_iam_role":
            arch["roles"].append({"address": a, "name": v.get("name") or a.split(".")[-1]})
        elif t == "aws_security_group":
            arch["security_groups"].append({"address": a, "name": v.get("name") or a.split(".")[-1]})
    return arch


# ----------------------------------------------------------------------------- 1. 사례 요약
def case_summary(case_id: str) -> Dict[str, Any]:
    case = get_case(case_id)
    if case is None:
        return {"error": f"사례 없음: {case_id}"}
    sets = _sets(case)
    plan_path, plan_src = _baseline_plan_path(case)
    plan = None
    if plan_path:
        try:
            plan = load_plan(plan_path)
        except PlanParseError:
            plan = None
    sources = {}
    try:
        sources = read_tf_files(_root() / case["tf_dir"])
    except Exception:
        sources = {}
    reqs = []
    for s in sets:
        for r in s["requirements"]:
            reqs.append({**r, "set_id": s["set_id"], "set_label": s["label"], "role": s["role"]})
    blocking = [s for s in sets if s["role"] == "primary" and (s["intent"] is None or s.get("intent_status") == "draft")]
    return {
        "id": case["id"], "name": case["name"], "summary": case["summary"], "tf_dir": case["tf_dir"],
        "sets": [{k: v for k, v in s.items() if k not in ("intent", "manifest")} for s in sets],
        "requirements": reqs,
        "requirements_ok": not blocking,
        "requirements_problem": "; ".join(f"{s['label']}: {s.get('intent_error') or '요구사항 draft 상태'}" for s in blocking) if blocking else "",
        "findings": findings_classified(case, sets),
        "architecture": architecture(plan, sources),
        "baseline_plan": {"available": plan is not None, "source": plan_src},
        "files": sorted(sources.keys()),
    }


# ----------------------------------------------------------------------------- 2. 현재 설정의 문제 (원본 plan + 요구사항)
def current_state(case_id: str) -> Dict[str, Any]:
    case = get_case(case_id)
    if case is None:
        return {"error": f"사례 없음: {case_id}"}
    sets = _sets(case)
    plan_path, plan_src = _baseline_plan_path(case)
    if plan_path is None:
        return {"ok": False, "reason": "원본 실행 계획(plan) 없음 — '원본 점검 실행' 시 이 PC 의 Terraform 으로 생성",
                "plan_source": plan_src, "sets": []}
    try:
        plan = load_plan(plan_path)
    except PlanParseError as e:
        return {"ok": False, "reason": f"원본 plan 조회 실패: {e}", "plan_source": plan_src, "sets": []}
    sources = read_tf_files(_root() / case["tf_dir"])
    out_sets = []
    for s in sets:
        if s["intent"] is None:
            out_sets.append({"set_id": s["set_id"], "label": s["label"], "role": s["role"], "ok": False, "reason": s.get("intent_error") or "요구사항 없음", "rows": []})
            continue
        lr = v6_intent_oracle(plan, sources, s["intent"], s.get("intent_error"))
        details = lr.details if isinstance(lr.details, dict) else {}
        rows = explain.oracle_rows(s["intent_kind"], details, s["requirements"])
        violated = [r for r in rows if r["verdict"] == "FAIL"]
        unknown = [r for r in rows if r["verdict"] == "UNKNOWN"]
        topo = {k: details.get(k) for k in ("flows", "excess", "tiers", "notes", "undesigned")} if s["intent_kind"] == "topology" else None
        out_sets.append({"set_id": s["set_id"], "label": s["label"], "role": s["role"], "ok": True, "verdict": lr.verdict.value, "topology": topo,
                         "design_version": s.get("design_version", 1),
                         "summary": lr.summary, "rows": rows, "n_violated": len(violated), "n_unknown": len(unknown),
                         "disclaimer": explain.disclaimer_ko(details.get("disclaimer", ""))})
    return {"ok": True, "plan_source": plan_src, "sets": out_sets, "computed": "이 PC 에서 원본 plan 에 요구사항을 대입해 계산 (AWS 접속 없음)"}


# ----------------------------------------------------------------------------- 표시 이름 (교수 피드백 7, 2026-10-31)
# 후보 id(correct-design, breaks-required-… 같은 이름)는 기대 결과를 드러낸다. id 는 내부 식별자(기록 폴더 · 작업 요청)로만 쓰고,
# 화면 · 작업 로그 · 새 보고서에는 '수정안 NN' 을 쓴다 (검토 문서 11-02: 사용자 화면에서 '후보 · 정답' 낱말 제거). 번호 순서 = sha256(세트/id) 순서라 작성 순서 · 기대 결과와 상관없다.
# 기대 결과(expected · expected_reason · note)는 manifest 에 그대로 남는다 (평가용) — 화면으로 보내는 자료에서만 뺀다.
DIRECT_PREFIXES = ("paste", "upload")
AI_PREFIX = "ai-"            # AI 수정 기록 (llmfix) — 후보 목록이 아니라 AI 수정 실행(data/llm_runs)으로 묶어 보여 준다
_AI_RUN_RE = re.compile(r"^ai-\d{8}-\d{6}-[0-9a-f]{6}-a\d+$")


def is_ai_run(cid: str) -> bool:
    """llmfix 가 만든 기록의 후보 id (ai-<실행 id>-a<시도>) 인가. manifest 후보 'ai-claude-r1' 같은 이름은 아니다."""
    return bool(_AI_RUN_RE.match(str(cid or "")))


def display_labels(set_id: str, man: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    if man is None:
        man, _ = _manifest(set_id)
    ids = [str(c.get("id")) for c in (man or {}).get("candidates") or [] if c.get("id")]
    order = sorted(ids, key=lambda i: hashlib.sha256(f"{set_id}/{i}".encode("utf-8")).hexdigest())
    return {cid: f"수정안 {n:02d}" for n, cid in enumerate(order, 1)}


def _short_time(iso: str) -> str:
    t = str(iso or "")
    return f"{int(t[5:7])}/{int(t[8:10])} {t[11:16]}" if len(t) >= 16 and t[4] == "-" else t


def label_for(set_id: str, cid: str, started_at: str = "", labels: Optional[Dict[str, str]] = None) -> str:
    """기록·후보 id → 화면 이름. 직접 제출(paste-…/upload-…)은 '직접 제출 · 10/31 14:02'."""
    cid = str(cid or "")
    if cid.startswith(DIRECT_PREFIXES):
        return "직접 제출" + (f" · {_short_time(started_at)}" if started_at else "")
    if is_ai_run(cid):                                 # AI 수정 (llmfix, D-27): ai-<실행 id>-a<시도>
        n = cid.rsplit("-a", 1)[-1] if "-a" in cid else "?"
        return f"AI 수정 · 시도 {n}" + (f" · {_short_time(started_at)}" if started_at else "")
    labs = labels if labels is not None else display_labels(set_id)
    if cid.endswith("-rb") and cid[:-3] in labs:
        return f"{labs[cid[:-3]]} (규칙 기반 생성)"
    if cid.endswith("-rb") or cid == "rule-based":
        return labs.get(cid, "규칙 기반 생성")
    return labs.get(cid) or "목록 밖 수정안"


def scenario_parts(scenario: str) -> Tuple[str, str]:
    """기록 scenario 'ui/<세트>/<후보>' 또는 '<세트>/<후보>' → (세트, 후보)."""
    parts = str(scenario or "").split("/")
    if parts and parts[0] == "ui":
        parts = parts[1:]
    if len(parts) < 2:
        return "", str(scenario or "")
    return parts[0], "/".join(parts[1:])


def label_for_scenario(scenario: str, started_at: str = "") -> str:
    set_id, cid = scenario_parts(scenario)
    return label_for(set_id, cid, started_at) if set_id else (cid or "")


def record_label(st: Dict[str, Any]) -> str:
    """기록(state.json) → 화면 이름. 2026-10-31 이후 기록은 candidate_label 을 저장한다. 그 전 기록은 scenario 로 계산."""
    return str(st.get("candidate_label") or label_for_scenario(str(st.get("scenario") or ""), str(st.get("started_at") or "")))


def _target_file(fc: Dict[str, Any], set_id: str) -> Optional[str]:
    t = next((f for f in fc.get("in_scope", []) if f.get("set_id") == set_id), None)
    return Path(str(t["file"])).name if t and t.get("file") else None


def manifest_candidate_files(set_dir: Path, ref: str, target_name: Optional[str]) -> Optional[Dict[str, str]]:
    """manifest 후보 지정(manual:…) → {파일 이름: 내용}. 규칙 기반 · 세트 폴더 밖 · 읽기 실패는 None."""
    if not str(ref).startswith("manual:"):
        return None
    p = _resolve(ref[7:], set_dir)
    try:
        if p is None or not p.exists():
            return None
        p.resolve().relative_to(set_dir.resolve())
        if p.is_dir():
            return {q.name: q.read_text(encoding="utf-8") for q in sorted(p.glob("*.tf"))}
        if p.suffix.lower() == ".tf" and target_name:
            return {target_name: p.read_text(encoding="utf-8")}
    except (OSError, ValueError):
        return None
    return None


# ----------------------------------------------------------------------------- 3. 후보 목록 + 최신 기록
def candidates(case_id: str) -> Dict[str, Any]:
    from ..review.change_summary import summarize
    case = get_case(case_id)
    if case is None:
        return {"error": f"사례 없음: {case_id}"}
    recs = _records_for(case["tf_dir"])
    out_sets = []
    sets = _sets(case)
    fc = findings_classified(case, sets)
    for s in sets:
        man = s.get("manifest") or {}
        _m, set_dir = _manifest(s["set_id"])
        labels = display_labels(s["set_id"], man)
        tname = _target_file(fc, s["set_id"])
        tf_dir = _root() / str(man.get("tf_dir") or case["tf_dir"])
        original: Dict[str, str] = {}
        if tname and (tf_dir / tname).exists():
            original = {tname: (tf_dir / tname).read_text(encoding="utf-8")}
        items = []
        for c in man.get("candidates") or []:
            cid = c.get("id")
            latest = None
            post = None
            lsha = None
            for rid, st, d in recs:
                sc = str(st.get("scenario", ""))
                if sc.endswith(f"/{s['set_id']}/{cid}") or sc == f"{s['set_id']}/{cid}" or sc.endswith(f"/{s['set_id']}/{cid}-rb"):
                    if latest is None:
                        latest = _record_brief(rid, st, d)
                        lsha = st.get("candidate_sha256")
                    # 실제 AWS 검사 결과: 같은 후보 파일(sha256 같음)을 잰 가장 최근 기록
                    pst = (st.get("post_deploy") or {}).get("status")
                    if pst and lsha and st.get("candidate_sha256") == lsha:
                        post = {"id": rid, "status": pst, "at": st.get("started_at")}
                        break
            src = c.get("source") or ("rule_based" if c.get("candidate") == "rule_based" else "seeded")
            ol = explain.origin_label(src, None, c.get("note", ""))
            files = manifest_candidate_files(set_dir, str(c.get("candidate") or ""), tname)
            changes = summarize(original, files) if files is not None and original else None
            if c.get("candidate") == "rule_based":
                auto = "검사 시작 시 규칙으로 생성 — 변경 내용은 검사 후 기록에 표시"
            else:
                auto = changes["text"] if changes else "변경 내용 계산 불가 (수정안 파일 형식)"
            # 화면에 보내는 것: 표시 이름 · 출처 · 코드에서 자동으로 센 '바뀐 블록' 만. 기대 결과(expected*) · 작성 메모(note) · 파일 이름 ·
            # 사람이 적은 설명(change_summary)은 보내지 않는다 (교수 피드백 10-31 '후보 밑 정답 내용 삭제' — manifest 에는 그대로, 평가용)
            items.append({"id": cid, "label": labels.get(cid, cid), "origin": ol,
                          "summary": auto, "changes": changes,
                          "latest": latest, "post": post})
        # 붙여넣기 등 manifest 에 없는 후보의 기록도 보여 준다
        known = {f"{s['set_id']}/{i['id']}" for i in items}
        for rid, st, d in recs:
            sc = str(st.get("scenario", ""))
            if f"/{s['set_id']}/" not in sc and not sc.startswith(f"{s['set_id']}/"):
                continue
            tail = sc.split(f"{s['set_id']}/", 1)[1]
            if tail.endswith("-rb"):
                tail = tail[:-3]
            if f"{s['set_id']}/{tail}" in known:
                continue
            known.add(f"{s['set_id']}/{tail}")
            direct = tail.startswith(DIRECT_PREFIXES)
            if is_ai_run(tail):
                continue
            items.append({"id": tail, "label": label_for(s["set_id"], tail, str(st.get("started_at") or ""), labels),
                          "origin": explain.origin_label(st.get("candidate_origin"), st.get("candidate_generator"), "직접 제출" if direct else ""),
                          "summary": str(st.get("candidate_summary") or ("직접 제출한 수정 코드 — 바뀐 내용은 기록의 변경 코드 참고" if direct else "목록 밖 후보")),
                          "changes": None, "latest": _record_brief(rid, st, d)})
        # 지금 기준 파일의 버전 · 지문 · 확정 상태 (D-40) — 요구사항(IAM 등) 세트도 화면이 '이전 기준 결과' 와 '초안 기준' 을 가려낼 수 있게
        try:
            from . import designs
            dv, dconf = designs.active_version(s["set_id"]), designs.confirmation(s["set_id"])
            dsha = next((v.get("sha256") for v in designs.versions(s["set_id"]) if v.get("active")), None)
        except (ValueError, OSError):
            dv, dconf, dsha = 1, None, None
        out_sets.append({"set_id": s["set_id"], "label": s["label"], "role": s["role"], "rule": s.get("rule"), "resource": s.get("resource"),
                         "intent_kind": s.get("intent_kind"), "candidates": items,
                         "design_version": dv, "design_sha256": dsha, "design_confirmation": dconf})
    return {"sets": out_sets, "n_records": len(recs)}


def _record_brief(rid: str, st: Dict[str, Any], d: Path) -> Dict[str, Any]:
    ver = _read_json(d / "verification.json")
    pol = _read_json(d / "policy.json")
    risk = _read_json(d / "risk.json")
    cls = explain.classify_candidate(st, ver, pol)
    dec = _read_json(d / "decision.json")
    layers = ((ver or {}).get("report") or {}).get("layers") or []
    des = st.get("design") if isinstance(st.get("design"), dict) else {}
    return {"id": rid, "state": st.get("state"), "state_ko": explain.STATE_KO.get(str(st.get("state")), st.get("state")),
            "design": {"intent_version": des.get("intent_version"), "sha256": des.get("sha256")} if des else None,
            "level": st.get("review_level"), "level_ko": explain.LEVEL_KO.get(str(st.get("review_level")), st.get("review_level")),
            "verification_status": st.get("verification_status"), "started_at": st.get("started_at"), "finished_at": st.get("finished_at"),
            "classification": cls, "risk": ((risk or {}).get("decision") or {}).get("risk_level"),
            "layers": {l.get("layer"): l.get("verdict") for l in layers},
            "decision": (dec or {}).get("decision"), "decision_ko": explain.DECISION_KO.get(str((dec or {}).get("decision")), None),
            "post_deploy": (st.get("post_deploy") or {}).get("status"), "tools": _tools_brief(st)}


def _tools_brief(st: Dict[str, Any]) -> Dict[str, str]:
    lt = st.get("local_tools") or {}
    out = {}
    for k in ("trivy", "terraform"):
        v = lt.get(k) or {}
        out[k] = (f"{v.get('kind') or k} {v.get('version')}" if v.get("version") else "없음")
    return out
