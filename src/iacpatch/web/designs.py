"""고객 설계도 버전 (D-30, 2026-11-01) — 화면에서 설계도를 고치면 새 버전으로 저장하고, 그 버전이 '지금 기준' 이 된다.

  v1   = 실험 세트 manifest 가 가리키는 설계도 파일 (평가 기준 — 이 모듈은 고치지 않는다, 읽기 전용)
  v2~  = data/designs/<세트>/v<N>.json  (화면에서 저장, 저장하면 바로 지금 기준)
  지금 기준 = data/designs/<세트>/active.json 의 버전 (없으면 v1). 화면에서 예전 버전으로 되돌릴 수 있다.

검사(server.job_candidate) · 지금 코드 계산(cases.current_state) · AI 수정(llmfix) 이 모두 '지금 기준' 을 쓴다.
과거 기록은 기록에 저장한 설계도 사본(input/design.json)으로 해석된다 — 설계도가 바뀌어도 과거 결과를 다시 판정하지 않는다.
설계도 내용은 사람이 정한다: 이 모듈은 형식만 검사하고(topology_intent.parse_topology_intent + 이름 규칙) 값을 추측해 채우지 않는다.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .topomodel import KIND_KO

SET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
SG_RE = re.compile(r"^(module\.[A-Za-z0-9_-]+\.)*aws_security_group\.[A-Za-z_][A-Za-z0-9_-]{0,80}$")
TYPES = dict(KIND_KO)        # 구성요소 종류 = 그림 아이콘 종류 (topomodel 한 곳에서 정함)
MAX_TIERS, MAX_EXT, MAX_FLOWS = 30, 12, 80


def _root() -> Path:
    from .. import app as _app
    return _app.ROOT


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def store_root() -> Path:
    """data/designs (시험은 IACPATCH_DESIGNS_DIR 로 바꾼다 — 저장소 data 를 건드리지 않게)."""
    env = os.environ.get("IACPATCH_DESIGNS_DIR")
    return Path(env) if env else _root() / "data" / "designs"


def store_dir(set_id: str) -> Path:
    if not SET_RE.match(str(set_id or "")):
        raise ValueError(f"세트 이름이 올바르지 않음: {set_id!r}")
    return store_root() / set_id


def _manifest_intent(set_id: str) -> Optional[Path]:
    from . import cases as cs
    man, set_dir = cs._manifest(set_id)
    if not man or not man.get("intent"):
        return None
    p = cs._resolve(man.get("intent"), set_dir)
    return p if p and p.exists() else None


def _proposal_path(set_id: str) -> Optional[Path]:
    """세트 manifest 의 proposal(고객 제안서 파일). 없으면 None."""
    from . import cases as cs
    man, set_dir = cs._manifest(set_id)
    if not man or not man.get("proposal"):
        return None
    p = cs._resolve(man.get("proposal"), set_dir)
    return p if p and p.is_file() else None


def proposal_label(set_id: str) -> str:
    """설계도 v1 의 원문 이름 — manifest 의 proposal_label (팀 3계층 = '팀 설계 문서', D-49). 없으면 '고객 제안서' (D-46)."""
    from . import cases as cs
    man, _ = cs._manifest(set_id)
    lab = str((man or {}).get("proposal_label") or "").strip()
    return lab or "고객 제안서"


def proposal_text(set_id: str) -> Optional[Dict[str, Any]]:
    """고객 제안서 · 팀 설계 문서 (D-46 · D-49) — 화면 ③ 에 그대로 보여 준다 (해석하지 않음). {path, text, label} 또는 None."""
    p = _proposal_path(set_id)
    if p is None:
        return None
    try:
        return {"path": _rel(p), "text": p.read_text(encoding="utf-8")[:20000], "label": proposal_label(set_id)}
    except OSError:
        return None


def _kind(p: Optional[Path]) -> Optional[str]:
    try:
        k = json.loads(p.read_text(encoding="utf-8")).get("kind") if p else None
    except (OSError, ValueError):
        return None
    return "security_group" if k in (None, "", "sg") else str(k)


def _case_of(set_id: str) -> Optional[str]:
    from . import cases as cs
    c = cs.case_of_set(set_id)
    return c["id"] if c else None


def _ref(x: str) -> Tuple[str, Optional[Path], str]:
    """세트 또는 프로젝트 id → (저장 키, v1 파일, 종류).
    종류: manifest   = 실험 세트의 토폴로지 설계도가 v1 (평가 기준, 읽기 전용)
          project    = 프로젝트 설계도 (화면에서 처음 확정한 것이 v1, data/designs/<프로젝트>/v1.json)
                       — 보안 그룹 요구사항(구버전 형식) 세트도 프로젝트 설계도가 생기면 그것을 지금 기준으로 쓴다
          requirement = 토폴로지가 아닌 요구사항(IAM · 보안 그룹 형식) — v1 = manifest 파일(팀 작성 평가 기준), v2~ = 화면에서 JSON 으로 올린 판
                       (D-40, 2026-11-02 — 검토 문서 "IAM 요구사항도 버전 · 지문 · 확정이 있어야"). 편집기는 없고 파일 올리기만
          proposal   = 고객 제안서 예제(manifest 에 proposal 파일이 있는 세트, D-46) — v1 = 제안서 조건을 옮긴 **초안**(확정 전), 프로젝트처럼
                       화면에서 고치고(v2~) 담당자가 확정한다. '팀 작성 평가 기준' 으로 자동 확정하지 않는다
          req_proposal = 요구사항 파일(IAM)인데 manifest 에 원문(proposal)이 있는 세트 (15차, D-51 — 팀 3계층 요청 3) — v1 = 팀 설계 문서의
                       권한 문장을 옮긴 **초안**: 담당자가 원문과 맞는지 보고 확정한다. 새 판은 requirement 처럼 JSON 올리기"""
    from . import cases as cs
    pid = cs.project_of_set(x)
    if pid:                                   # 연결한 프로젝트의 세트 → 프로젝트 설계도 하나를 같이 쓴다 (D-32)
        p = store_dir(pid) / "v1.json"
        return pid, (p if p.is_file() else None), "project"
    base = _manifest_intent(x)
    if base is not None:
        k = _kind(base)
        if k == "topology" and _proposal_path(x) is not None:
            return x, base, "proposal"            # 고객 제안서 예제 (D-46): v1 = 제안서를 옮긴 초안, 사람이 확정 · 고칠 수 있다
        if k == "topology":
            return x, base, "manifest"
        if k == "iam" and _proposal_path(x) is not None:
            return x, base, "req_proposal"        # 15차 (D-51): 팀 설계 문서에서 옮긴 IAM 요구사항 초안 — 사람이 확정
        case = _case_of(x)
        if k == "security_group" and case and (store_dir(case) / "v1.json").is_file():
            return case, store_dir(case) / "v1.json", "project"
        return x, base, "requirement"
    p = store_dir(x) / "v1.json"
    return x, (p if p.is_file() else None), "project"


def base_path(set_id: str) -> Optional[Path]:
    """v1 파일 (실험 세트 manifest 의 설계도 또는 프로젝트에서 처음 확정한 설계도)."""
    return _ref(set_id)[1]


def _is_topology(p: Optional[Path]) -> bool:
    return _kind(p) == "topology"


def _stored(set_id: str) -> Dict[int, Path]:
    key = _ref(set_id)[0]
    d = store_dir(key)
    out: Dict[int, Path] = {}
    if d.is_dir():
        for p in d.glob("v*.json"):
            m = re.match(r"^v(\d+)\.json$", p.name)
            if m and int(m.group(1)) >= 2:
                out[int(m.group(1))] = p
    return out


def path_for(set_id: str, version: Optional[int] = None) -> Optional[Path]:
    v = active_version(set_id) if version is None else int(version)
    return base_path(set_id) if v == 1 else _stored(set_id).get(v)


def active_version(set_id: str) -> int:
    key = _ref(set_id)[0]
    try:
        a = json.loads((store_dir(key) / "active.json").read_text(encoding="utf-8"))
        v = int(a.get("version"))
    except (OSError, ValueError, TypeError):
        return 1
    return v if v == 1 or v in _stored(set_id) else 1


def active_path(set_id: str) -> Optional[Path]:
    """지금 기준 파일 — 설계도(토폴로지)든 요구사항(IAM · 보안 그룹 형식)이든 활성 버전 (없으면 v1 = manifest)."""
    _key, base, _kind = _ref(set_id)
    return path_for(set_id) or base


def load(set_id: str, version: Optional[int] = None) -> Optional[Dict[str, Any]]:
    p = path_for(set_id, version)
    if not p:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _rel(p: Path) -> str:
    try:
        return p.resolve().relative_to(_root().resolve()).as_posix()
    except ValueError:
        return str(p)


def versions(set_id: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    _key, base, kind = _ref(set_id)
    act = active_version(set_id)
    items = ([(1, base)] if base else []) + sorted(_stored(set_id).items())
    for v, p in items:
        try:
            raw = p.read_bytes()
            d = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            continue
        ed = d.get("edited") or {}
        first = ("실험 세트의 설계도 (평가 기준 — 고치지 않음)" if kind == "manifest" else "실험 세트의 요구사항 파일 (팀 작성 평가 기준)" if kind == "requirement"
                 else f"{proposal_label(set_id)}에서 옮긴 설계도 초안 (담당자 확인 · 확정 필요)" if kind == "proposal"
                 else f"{proposal_label(set_id)}에서 옮긴 요구사항 초안 (담당자 확인 · 확정 필요)" if kind == "req_proposal"
                 else ("자동 기준 (지금 코드 − 위험한 통신)" if d.get("auto") else "처음 확정한 설계도"))
        out.append({"version": v, "path": _rel(p), "source": ("manifest" if kind in ("manifest", "requirement") else "proposal" if kind in ("proposal", "req_proposal") else "project") if v == 1 else ("imported" if kind in ("requirement", "req_proposal") else "edited"), "active": v == act,
                    "kind": d.get("kind") or "security_group", "n_rules": _n_rules(d),
                    "sha256": _sha(raw), "intent_id": d.get("intent_id"), "intent_version": d.get("intent_version"),
                    "created_at": ed.get("at") or "", "note": ed.get("note") or (first if v == 1 else ""),
                    "from_version": ed.get("from_version"), "changes": (ed.get("changes") or {}).get("text", ""),
                    "n_tiers": len(d.get("tiers") or []), "n_flows": len(d.get("flows") or []), "auto": bool(d.get("auto")), "by": ed.get("by") or "",
                    "done": ((d.get("edits") or {}).get("done") or [])[:20],
                    "confirmation": confirmation(set_id, v)})
    return out


def _n_rules(d: Dict[str, Any]) -> int:
    """요구사항 파일의 규칙 수 (IAM: 허용 권한 묶음 + 필수 권한, 보안 그룹 형식: 허용 · 필수 접근 규칙) — 화면 표시용."""
    n = 0
    for k in ("approved_permissions", "required_permissions", "approved_managed_policy_arns", "allowed_ingress", "required_access", "approved_sources", "required_flows"):
        v = d.get(k)
        if isinstance(v, list):
            n += len(v)
    return n


# ----------------------------------------------------------------------------- 형식 검사 · 정리
def _port_key(f: Dict[str, Any]) -> Tuple[str, int, int]:
    proto = str(f.get("protocol") or "tcp").lower()
    if proto == "-1":
        return proto, 0, 65535
    lo = f.get("from_port", f.get("port"))
    hi = f.get("to_port", f.get("port"))
    return proto, int(lo), int(hi)


def normalize(raw: Dict[str, Any], base: Dict[str, Any]) -> Dict[str, Any]:
    """화면이 보낸 설계도 → 저장 형식. 아는 칸만 옮긴다 (모르는 칸은 버림). id 가 없으면 만든다 (from-to-포트)."""
    if not isinstance(raw, dict):
        raise ValueError("설계도는 JSON 객체여야 함")
    tiers = []
    for t in raw.get("tiers") or []:
        row = {"id": str(t.get("id") or "").strip(), "label": str(t.get("label") or "").strip(), "security_group": str(t.get("security_group") or "").strip()}
        if t.get("type"):
            row["type"] = str(t.get("type"))
        tiers.append(row)
    ext = [{"id": str(e.get("id") or "").strip(), "label": str(e.get("label") or "").strip(),
            "cidrs_v4": [str(c).strip() for c in (e.get("cidrs_v4") or []) if str(c).strip()]} for e in raw.get("external") or []]
    flows = []
    for f in raw.get("flows") or []:
        proto = str(f.get("protocol") or "tcp").lower()
        row: Dict[str, Any] = {"id": str(f.get("id") or "").strip(), "from": str(f.get("from") or ""), "to": str(f.get("to") or ""), "protocol": proto}
        if proto != "-1":
            try:
                lo, hi = int(f.get("from_port", f.get("port"))), int(f.get("to_port", f.get("port")))
            except (TypeError, ValueError):
                raise ValueError(f"통신 {row['from']} → {row['to']}: 포트가 숫자가 아님")
            if lo == hi:
                row["port"] = lo
            else:
                row["from_port"], row["to_port"] = lo, hi
        if not row["id"]:
            row["id"] = f"{row['from']}-{row['to']}-{row.get('port', row.get('from_port', 'all'))}"
        if f.get("label"):
            row["label"] = str(f.get("label")).strip()
        flows.append(row)
    out = {"kind": "topology", "intent_version": "", "intent_id": str(base.get("intent_id") or raw.get("intent_id") or ""), "status": "active",
           "description": str(base.get("description") or ""), "target_dir": str(base.get("target_dir") or raw.get("target_dir") or ""),
           "vpc_cidr": str(raw.get("vpc_cidr") or base.get("vpc_cidr") or ""), "tiers": tiers, "external": ext, "flows": flows}
    return out


def validate(d: Dict[str, Any]) -> List[str]:
    """형식 오류 목록 (빈 목록 = 저장 가능). 판정 규칙 자체는 topology_intent 와 같다."""
    from ..intent import IntentError
    from ..topology_intent import parse_topology_intent
    errs: List[str] = []
    tiers, ext, flows = d.get("tiers") or [], d.get("external") or [], d.get("flows") or []
    if len(tiers) > MAX_TIERS or len(ext) > MAX_EXT or len(flows) > MAX_FLOWS:
        errs.append(f"너무 큼 (구성요소 {MAX_TIERS} · 외부 출처 {MAX_EXT} · 통신 {MAX_FLOWS} 개까지)")
    for t in tiers:
        if not ID_RE.match(t.get("id") or ""):
            errs.append(f"구성요소 id '{t.get('id')}': 영문 소문자 · 숫자 · - _ 만 (40자까지)")
        if not t.get("label"):
            errs.append(f"구성요소 '{t.get('id')}': 이름이 비어 있음")
        if not SG_RE.match(t.get("security_group") or ""):
            errs.append(f"구성요소 '{t.get('label') or t.get('id')}': 보안 그룹은 Terraform 주소 형식 (예: aws_security_group.web)")
        if t.get("type") and t["type"] not in TYPES:
            errs.append(f"구성요소 '{t.get('label')}': 종류는 {', '.join(TYPES)} 중 하나")
    sgs = [t.get("security_group") for t in tiers]
    dup = sorted({s for s in sgs if sgs.count(s) > 1})
    if dup:
        errs.append(f"보안 그룹 하나에 구성요소 여러 개: {', '.join(dup)} — 구성요소마다 보안 그룹이 달라야 통신을 구분할 수 있음")
    for e in ext:
        if not ID_RE.match(e.get("id") or ""):
            errs.append(f"외부 출처 id '{e.get('id')}': 영문 소문자 · 숫자 · - _ 만")
        if not e.get("cidrs_v4"):
            errs.append(f"외부 출처 '{e.get('label') or e.get('id')}': IP 대역(CIDR)이 하나 이상 필요")
    keys = {}
    for f in flows:
        try:
            k = (f.get("from"), f.get("to")) + _port_key(f)
        except (TypeError, ValueError):
            continue
        if k in keys:
            errs.append(f"같은 통신이 두 번: {f.get('from')} → {f.get('to')} {k[2]}-{k[3]}")
        keys[k] = 1
    if not errs:
        try:
            parse_topology_intent(d)
        except IntentError as e:
            errs.append(_ko(str(e)))
    return errs


def _ko(msg: str) -> str:
    rep = [("tiers must not be empty", "구성요소가 하나 이상 필요"), ("flows must not be empty", "통신이 하나 이상 필요"),
           ("vpc_cidr missing", "VPC 대역(vpc_cidr)이 필요"), ("flows id 가 겹친다", "통신 id 가 겹침"),
           ("는 tiers 의 id 여야 한다 (들어오는 통신만 다룬다)", "는 구성요소여야 함 (외부로 나가는 통신은 다루지 않음)"),
           ("가 tiers/external 에 없음", "가 구성요소 · 외부 출처에 없음"), ("placeholders present", "자리표시자(TODO 등)가 남아 있음")]
    for a, b in rep:
        msg = msg.replace(a, b)
    return msg


# ----------------------------------------------------------------------------- 차이
def _flow_text(f: Dict[str, Any], names: Dict[str, str]) -> str:
    proto, lo, hi = _port_key(f)
    port = "전체" if proto == "-1" else (str(lo) if lo == hi else f"{lo}-{hi}")
    return f"{names.get(f.get('from'), f.get('from'))} → {names.get(f.get('to'), f.get('to'))} {port}"


def diff(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """a(이전) → b(새) 바뀐 것. 사람이 읽는 문장(text)도 같이."""
    na = {x["id"]: x.get("label") or x["id"] for x in (a.get("tiers") or []) + (a.get("external") or [])}
    nb = {x["id"]: x.get("label") or x["id"] for x in (b.get("tiers") or []) + (b.get("external") or [])}
    names = {**na, **nb}
    ta, tb = {t["id"]: t for t in a.get("tiers") or []}, {t["id"]: t for t in b.get("tiers") or []}
    ea, eb = {e["id"]: e for e in a.get("external") or []}, {e["id"]: e for e in b.get("external") or []}
    fk = lambda f: (f.get("from"), f.get("to")) + _port_key(f)  # noqa: E731
    fa, fb = {fk(f): f for f in a.get("flows") or []}, {fk(f): f for f in b.get("flows") or []}
    out = {
        "tiers_added": [tb[i]["label"] for i in tb if i not in ta], "tiers_removed": [ta[i]["label"] for i in ta if i not in tb],
        "tiers_changed": [tb[i]["label"] for i in tb if i in ta and any(tb[i].get(k) != ta[i].get(k) for k in ("label", "security_group", "type"))],
        "external_added": [eb[i]["label"] for i in eb if i not in ea], "external_removed": [ea[i]["label"] for i in ea if i not in eb],
        "external_changed": [eb[i]["label"] for i in eb if i in ea and (eb[i].get("cidrs_v4") != ea[i].get("cidrs_v4") or eb[i].get("label") != ea[i].get("label"))],
        "flows_added": [_flow_text(fb[k], names) for k in fb if k not in fa], "flows_removed": [_flow_text(fa[k], names) for k in fa if k not in fb],
        "vpc_changed": a.get("vpc_cidr") != b.get("vpc_cidr"),
    }
    parts = []
    for key, word in (("tiers_added", "구성요소 추가"), ("tiers_removed", "구성요소 삭제"), ("tiers_changed", "구성요소 수정"),
                      ("external_added", "외부 출처 추가"), ("external_removed", "외부 출처 삭제"), ("external_changed", "외부 출처 대역 수정"),
                      ("flows_added", "통신 추가"), ("flows_removed", "통신 삭제")):
        if out[key]:
            parts.append(f"{word}: {', '.join(out[key][:6])}" + (f" 외 {len(out[key]) - 6}개" if len(out[key]) > 6 else ""))
    if out["vpc_changed"]:
        parts.append(f"VPC 대역 {a.get('vpc_cidr')} → {b.get('vpc_cidr')}")
    out["text"] = " · ".join(parts) or "바뀐 것 없음"
    out["empty"] = not parts
    return out


# ----------------------------------------------------------------------------- 저장 · 기준 바꾸기
def save(set_id: str, raw: Dict[str, Any], note: str = "", base_version: Optional[int] = None, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    base_v = active_version(set_id) if base_version is None else int(base_version)
    base = load(set_id, base_v)
    if base is None or base.get("kind") != "topology":
        return {"ok": False, "errors": ["토폴로지 형식 설계도가 있는 세트만 편집할 수 있음"]}
    try:
        d = normalize(raw, base)
    except ValueError as e:
        return {"ok": False, "errors": [str(e)]}
    errs = validate(d)
    if errs:
        return {"ok": False, "errors": errs}
    ch = diff(base, d)
    if ch["empty"]:
        return {"ok": False, "errors": [f"v{base_v} 와 바뀐 것이 없음 — 저장하지 않음"]}
    v = max([1] + list(_stored(set_id))) + 1
    d["intent_version"] = str(v)
    note = str(note or "").strip()[:200]
    d["description"] = f"v{v}: {note or ch['text']} (v{base_v} 를 화면에서 고침). " + str(base.get("description") or "")[:600]
    d["edited"] = {"from_version": base_v, "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "note": note, "by": "화면 편집 (사람)", "changes": ch}
    for mk, mv in (meta or {}).items():        # 그림에서 바꾼 것 목록 등 (판정에 쓰지 않는 기록)
        if mk in ("edits",):
            d[mk] = mv
    sd = store_dir(_ref(set_id)[0])
    sd.mkdir(parents=True, exist_ok=True)
    p = sd / f"v{v}.json"
    p.write_bytes((json.dumps(d, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    activate(set_id, v)
    return {"ok": True, "version": v, "path": _rel(p), "changes": ch}


def create_first(project: str, raw: Dict[str, Any], note: str = "", target_dir: str = "", meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """설계도가 없는 프로젝트에서 처음 확정 (v1). 이미 있으면 거절.
    meta.auto 가 있으면 자동 기준(지금 코드 − 위험한 통신, 사람이 바꾼 것 없음 — web/structure.py) — 그렇게 기록한다."""
    key, base, kind = _ref(project)
    if base is not None or kind != "project":
        return {"ok": False, "errors": ["이미 설계도가 있음 — 고치려면 새 버전으로 저장"]}
    stub = {"intent_id": f"{project}-design", "target_dir": target_dir, "description": "", "vpc_cidr": str(raw.get("vpc_cidr") or "")}
    try:
        d = normalize(raw, stub)
    except ValueError as e:
        return {"ok": False, "errors": [str(e)]}
    errs = validate(d)
    if errs:
        return {"ok": False, "errors": errs}
    note = str(note or "").strip()[:200]
    auto = (meta or {}).get("auto")
    d["intent_version"] = "1"
    d["description"] = (f"v1: {note} — 프로그램이 지금 코드에서 위험한 통신을 빼고 만든 것 (사람이 확인한 고객 설계 아님)" if auto
                        else f"v1: {note or '처음 확정'} (화면에서 정해 확정)")
    d["edited"] = {"from_version": None, "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "note": note, "by": "자동 (프로그램)" if auto else "화면 편집 (사람)",
                   "changes": {"text": "자동 기준" if auto else "처음 확정", "empty": False}}
    for mk, mv in (meta or {}).items():
        if mk in ("auto", "edits"):
            d[mk] = mv
    sd = store_dir(key)
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "v1.json").write_bytes((json.dumps(d, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    activate(key, 1)
    return {"ok": True, "version": 1, "path": _rel(sd / "v1.json")}


def import_version(set_id: str, raw: Any, note: str = "", by: str = "") -> Dict[str, Any]:
    """요구사항 파일(IAM · 보안 그룹 형식)의 새 버전을 JSON 으로 올린다 (D-40). 편집기는 없다 — 사람이 고친 파일을 그대로 받아
    형식(iam_intent · intent 파서)과 대상(같은 kind · 같은 intent_id)만 검사하고, 바뀐 것이 없으면 거절한다. 올린 판은 초안(확정 전)이다."""
    from ..iam_intent import IntentError as IamErr, parse_iam_intent
    from ..intent import IntentError as SgErr, parse_intent
    _key, base, kind = _ref(set_id)
    if kind not in ("requirement", "req_proposal") or base is None:
        return {"ok": False, "errors": ["요구사항 파일(IAM · 보안 그룹 형식) 세트만 JSON 으로 올릴 수 있음 — 설계도(토폴로지)는 ③ 목록에서 고쳐 저장"]}
    if isinstance(raw, (str, bytes)):
        try:
            raw = json.loads(raw)
        except ValueError as e:
            return {"ok": False, "errors": [f"JSON 형식이 아님: {e}"]}
    if not isinstance(raw, dict):
        return {"ok": False, "errors": ["JSON 객체(중괄호)가 아님"]}
    cur_v = active_version(set_id)
    cur = load(set_id, cur_v) or {}
    base_kind = str(cur.get("kind") or "sg").lower() or "sg"
    new_kind = str(raw.get("kind") or "sg").lower() or "sg"
    if new_kind != base_kind:
        return {"ok": False, "errors": [f"종류가 다름: 지금 기준은 {base_kind}, 올린 파일은 {new_kind}"]}
    if str(raw.get("intent_id") or "") != str(cur.get("intent_id") or ""):
        return {"ok": False, "errors": [f"다른 요구사항 파일: intent_id 가 다름 (지금 기준 {cur.get('intent_id')!r}, 올린 파일 {raw.get('intent_id')!r})"]}
    try:
        if new_kind == "iam":
            parse_iam_intent(dict(raw), path=f"upload:{set_id}")
        else:
            parse_intent(dict(raw), path=f"upload:{set_id}")
    except (IamErr, SgErr, ValueError, TypeError, KeyError) as e:
        return {"ok": False, "errors": [f"형식 검사 실패: {e}"]}
    d = dict(raw)
    for k in ("edited",):
        d.pop(k, None)
    cmp_old = {k: v for k, v in cur.items() if k not in ("edited", "intent_version", "description")}
    cmp_new = {k: v for k, v in d.items() if k not in ("edited", "intent_version", "description")}
    if cmp_old == cmp_new:
        return {"ok": False, "errors": [f"v{cur_v} 와 바뀐 것이 없음 — 올리지 않음"]}
    v = max([1] + list(_stored(set_id))) + 1
    note = str(note or "").strip()[:200]
    d["intent_version"] = str(v)
    changed = sorted(k for k in set(cmp_old) | set(cmp_new) if cmp_old.get(k) != cmp_new.get(k))
    d["edited"] = {"from_version": cur_v, "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "note": note, "by": (str(by or "").strip()[:80] or "화면에서 파일 올림 (사람)"),
                   "changes": {"text": "바뀐 항목: " + ", ".join(changed), "keys": changed, "empty": False}}
    sd = store_dir(_ref(set_id)[0])
    sd.mkdir(parents=True, exist_ok=True)
    p = sd / f"v{v}.json"
    p.write_bytes((json.dumps(d, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    activate(set_id, v)
    return {"ok": True, "version": v, "path": _rel(p), "changes": d["edited"]["changes"], "confirmation": confirmation(set_id, v)}


def activate(set_id: str, version: int) -> Dict[str, Any]:
    v = int(version)
    if v != 1 and v not in _stored(set_id):
        return {"ok": False, "errors": [f"버전 없음: v{v}"]}
    sd = store_dir(_ref(set_id)[0])
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "active.json").write_text(json.dumps({"version": v, "at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"ok": True, "version": v}


# ----------------------------------------------------------------------------- 확정 (D-38, 2026-11-02 — 검토 문서 "고객이 확정하지 않은 설계도로 '고객 요구 충족' 을 판정하지 않는다")
# 초안 = 프로그램이 만든 자동 기준(v1 자동) · 화면에서 고쳐 저장만 한 버전. 확정 = 담당자가 이름을 적고 '이 설계도가 고객 요구다' 라고 한 것.
# 확정은 버전 파일 내용과 따로 둔다 (data/designs/<키>/confirmed.json) — 파일 sha256 이 바뀌지 않으므로 이미 돌린 검사가 '이전 설계도 기준' 으로 밀리지 않는다.
# 확정 기록에 그때의 파일 sha256 을 같이 적어, 파일이 바뀌면(사람이 손으로 고치면) 확정이 자동으로 풀린다.
# 실험 세트(manifest) 설계도와 IAM 등 요구사항 파일은 팀이 평가 기준으로 작성한 것 → '팀 작성 평가 기준' 으로 표시한다 (사람이 확정한 고객 설계도와 구분).
MANIFEST_BASIS = "팀 작성 평가 기준 (실험 세트 — 고객이 확정한 설계도 아님)"


def _conf_path(set_id: str) -> Path:
    return store_dir(_ref(set_id)[0]) / "confirmed.json"


def _conf_all(set_id: str) -> Dict[str, Any]:
    try:
        d = json.loads(_conf_path(set_id).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def confirmation(set_id: str, version: Optional[int] = None) -> Dict[str, Any]:
    """{confirmed, basis: manifest|human|draft, by, at, note, version, sha256_ok}. 판정에 쓰는 값 — 기록(state.design.confirmation)에도 같은 것이 들어간다."""
    _key, base, kind = _ref(set_id)
    v = active_version(set_id) if version is None else int(version)
    fk = _kind(path_for(set_id, v)) or "security_group"
    if kind == "manifest" or (kind == "requirement" and v == 1):
        return {"confirmed": True, "basis": "manifest", "by": MANIFEST_BASIS, "at": None, "note": "", "version": v, "kind": fk}
    p = path_for(set_id, v)
    raw = p.read_bytes() if p and p.is_file() else None
    cur_sha = _sha(raw) if raw is not None else None
    try:
        auto = bool(json.loads(raw.decode("utf-8")).get("auto")) if raw is not None else False    # 프로그램이 코드에서 만든 자동 기준인가 (사람이 저장한 수정본과 구분)
    except (ValueError, UnicodeDecodeError, AttributeError):
        auto = False
    src = {"source": "proposal", "source_label": proposal_label(set_id)} if kind in ("proposal", "req_proposal") and v == 1 else {}     # 제안서 · 설계 문서를 옮긴 초안 (D-46 · D-49 · D-51) — 화면 문구용, 판정은 confirmed 로만
    c = _conf_all(set_id).get(str(v))
    if not isinstance(c, dict) or not c.get("by"):
        return {"confirmed": False, "basis": "draft", "by": "", "at": None, "note": "", "version": v, "auto": auto, "kind": fk, **src}
    if c.get("sha256") and cur_sha and c["sha256"] != cur_sha:
        return {"confirmed": False, "basis": "draft", "by": c.get("by"), "at": c.get("at"), "note": "확정한 뒤 파일이 바뀌어 확정이 풀림 — 다시 확정 필요", "version": v, "auto": auto, "kind": fk, **src}
    return {"confirmed": True, "basis": "human", "by": str(c.get("by")), "at": c.get("at"), "note": str(c.get("note") or ""), "version": v, "auto": auto, "kind": fk, **src}


def confirm(set_id: str, version: Optional[int], by: str, note: str = "") -> Dict[str, Any]:
    """담당자 확정. 이름이 없으면 거절. 실험 세트 설계도는 확정 대상이 아니다 (평가 기준 — 고치지 않음)."""
    _key, base, kind = _ref(set_id)
    v = active_version(set_id) if version is None else int(version)
    if kind == "manifest" or (kind == "requirement" and v == 1):
        return {"ok": False, "errors": ["실험 세트의 설계도 · 요구사항 파일(팀 작성 평가 기준)은 화면에서 확정 · 수정하지 않음 — 새 판을 올린 뒤 그 판을 확정"]}
    by = str(by or "").strip()[:80]
    if not by:
        return {"ok": False, "errors": ["확정한 사람 이름이 필요함 (기록에 남음)"]}
    p = path_for(set_id, v)
    if not p or not p.is_file():
        return {"ok": False, "errors": [f"버전 없음: v{v}"]}
    allc = _conf_all(set_id)
    allc[str(v)] = {"by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "note": str(note or "").strip()[:200], "sha256": _sha(p.read_bytes())}
    cp = _conf_path(set_id)
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(json.dumps(allc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "version": v, "confirmation": confirmation(set_id, v)}


# ----------------------------------------------------------------------------- 미리보기: 이 설계도로 지금 코드를 보면
def code_security_groups(set_id: str) -> List[Dict[str, Any]]:
    """원본 코드(plan)의 보안 그룹과 붙은 리소스 — 편집 화면의 '보안 그룹 고르기' 목록. plan 이 없으면 빈 목록."""
    plan, sources, _src = _original_plan(set_id)
    if plan is None:
        return []
    from ..verify.plan_model import PlanParseError, build_world
    try:
        w = build_world(plan, sources)
    except PlanParseError:
        return []
    out = []
    for addr in sorted(w.security_groups):
        if addr.startswith("sg-"):
            continue
        out.append({"address": addr, "resources": [a.address for a in w.attachments if addr in a.sg_refs],
                    "inbound": sum(1 for r in w.security_groups[addr].rules if r.direction == "ingress")})
    return out


def _original_plan(set_id: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, str], str]:
    from ..evidence import read_tf_files
    from ..verify.plan_model import PlanParseError, load_plan
    from . import cases as cs
    case = cs.get_case(set_id) or cs.case_of_set(set_id)
    if case is None:
        return None, {}, "사례 없음"
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


def preview(set_id: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """저장 전 미리보기: 이 설계도(초안)를 기준으로 원본 코드를 V6 와 같은 방법으로 비교한 결과 + 그림 모델."""
    from ..topology_intent import parse_topology_intent
    from ..verify.v6 import v6_intent_oracle
    from .topomodel import model
    base = load(set_id) or {}
    try:
        d = normalize(raw, base)
    except ValueError as e:
        return {"ok": False, "errors": [str(e)]}
    errs = validate(d)
    if errs:
        return {"ok": False, "errors": errs}
    spec = parse_topology_intent(d)
    plan, sources, src = _original_plan(set_id)
    ch = diff(base, d)
    if plan is None:
        return {"ok": True, "computed": False, "reason": src, "model": model(d, None, "design"), "changes": ch}
    lr = v6_intent_oracle(plan, sources, spec)
    det = lr.details if isinstance(lr.details, dict) else {}
    return {"ok": True, "computed": True, "plan_source": src, "verdict": lr.verdict.value, "summary": lr.summary, "changes": ch,
            "topology": {k: det.get(k) for k in ("flows", "excess", "tiers", "notes", "undesigned")},
            "model": model(d, det.get("tiers"), "current", undesigned=det.get("undesigned"))}


def payload(set_id: str, version: Optional[int] = None) -> Dict[str, Any]:
    """화면용: 버전 목록 · 지금 기준 · 고를 수 있는 보안 그룹(원본 코드)."""
    vs = versions(set_id)
    if not vs:
        return {"ok": False, "reason": "이 세트에는 설계도(요구사항) 파일이 없음", "versions": []}
    act = active_version(set_id)
    v = act if version is None else int(version)
    d = load(set_id, v)
    if d is None:
        return {"ok": False, "reason": f"버전 없음: v{v}", "versions": vs}
    editable = d.get("kind") == "topology"
    return {"ok": True, "set_id": set_id, "active_version": act, "version": v, "versions": vs, "design": d, "editable": editable,
            "confirmation": confirmation(set_id, v), "confirmable": _ref(set_id)[2] in ("project", "proposal", "req_proposal") or (_ref(set_id)[2] == "requirement" and v >= 2),
            "importable": _ref(set_id)[2] in ("requirement", "req_proposal"),
            "types": TYPES, "code_security_groups": code_security_groups(set_id) if editable else []}
