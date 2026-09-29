"""Intent Spec — 사람이 정의한 '이 인프라가 허용해야 하는 접근' (V6/V7/V8 의 기준).

Intent 는 Trivy 와 무관하게 사람이 작성한다. 형식은 JSON (policy/intent/<scenario>.json).

    {
      "intent_version": "1",
      "intent_id": "sg-baseline",
      "status": "active",                       # "draft" 면 사용 불가 (INSUFFICIENT_INFO)
      "target_dir": "infrastructure/sg-baseline",
      "targets": {
        "security_groups": ["aws_security_group.vulnerable_ssh"],
        "attachment_points": []                # 비우면 plan 에서 자동 탐색, 없으면 SG 단독 평가
      },
      "guarded_services": [
        {"label": "ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
         "approved_sources": {"cidrs_v4": ["203.0.113.0/24"], "cidrs_v6": [],
                              "security_group_refs": [], "prefix_list_refs": []}}
      ],
      "required_access": [
        {"label": "admin-ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
         "source_cidr": "203.0.113.0/24"}
      ]
    }

원칙:
  - 승인 CIDR 은 추측해서 채우지 않는다. 플레이스홀더("__FILL_ME__", "<...>", "TODO", "REPLACE")가 남아 있으면
    INSUFFICIENT_INFO 로 처리하고 파이프라인은 패치 생성으로 진행하지 않는다.
  - 보호 서비스의 승인 출처가 인터넷 전체(0.0.0.0/0, ::/0)를 덮으면 intent 자체가 무효다.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ApprovedSources, RequiredAccess, ServiceSpec
from .verify.netset import CidrParseError, NetSet, parse_cidr

PLACEHOLDER_RE = re.compile(r"__FILL_ME__|<[^>]*>|TODO|REPLACE|CHANGE_ME", re.IGNORECASE)
VALID_DIRECTIONS = {"ingress", "egress"}
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "icmpv6", "-1"}


class IntentError(ValueError):
    pass


@dataclass
class GuardedService:
    service: ServiceSpec
    approved: ApprovedSources


@dataclass
class IntentSpec:
    intent_id: str
    intent_version: str
    status: str
    target_dir: str
    target_security_groups: List[str]
    attachment_points: List[str]
    guarded_services: List[GuardedService]
    required_access: List[RequiredAccess]
    description: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.raw)


def _svc(d: Dict[str, Any], where: str) -> ServiceSpec:
    for k in ("direction", "protocol", "from_port", "to_port"):
        if k not in d:
            raise IntentError(f"{where}: missing '{k}'")
    direction = str(d["direction"]).lower()
    if direction not in VALID_DIRECTIONS:
        raise IntentError(f"{where}: direction must be ingress|egress")
    protocol = str(d["protocol"]).lower()
    if protocol not in VALID_PROTOCOLS:
        raise IntentError(f"{where}: protocol must be one of {sorted(VALID_PROTOCOLS)}")
    try:
        fp, tp = int(d["from_port"]), int(d["to_port"])
    except (TypeError, ValueError):
        raise IntentError(f"{where}: from_port/to_port must be integers")
    if protocol in ("tcp", "udp") and not (0 <= fp <= tp <= 65535):
        raise IntentError(f"{where}: bad port range {fp}-{tp}")
    return ServiceSpec(direction, protocol, fp, tp, str(d.get("label", "")))


def _check_placeholders(obj: Any, path: str, problems: List[str]) -> None:
    if isinstance(obj, str):
        if PLACEHOLDER_RE.search(obj):
            problems.append(f"{path}: placeholder value {obj!r}")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("description", "_comment", "label"):
                continue  # 자유 텍스트는 검사하지 않는다
            _check_placeholders(v, f"{path}.{k}", problems)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _check_placeholders(v, f"{path}[{i}]", problems)


def _cidr_list(lst: Any, version: int, where: str) -> List[str]:
    if lst is None:
        return []
    if not isinstance(lst, list):
        raise IntentError(f"{where}: must be a list")
    out: List[str] = []
    for c in lst:
        try:
            n = parse_cidr(str(c))
        except CidrParseError as e:
            raise IntentError(f"{where}: {e}")
        if n.version != version:
            raise IntentError(f"{where}: {c} is not IPv{version}")
        out.append(str(n))
    return out


def parse_intent(data: Dict[str, Any], path: str = "") -> IntentSpec:
    """dict → IntentSpec. 문제가 있으면 IntentError (메시지에 이유)."""
    if not isinstance(data, dict):
        raise IntentError("intent must be a JSON object")
    problems: List[str] = []
    _check_placeholders(data, "intent", problems)
    if problems:
        raise IntentError("placeholders present — fill in real values before running: " + "; ".join(problems[:5]))
    status = str(data.get("status", "active")).lower()
    if status != "active":
        raise IntentError(f"intent status is {status!r} (must be 'active')")
    intent_id = str(data.get("intent_id") or "").strip()
    if not intent_id:
        raise IntentError("intent_id missing")
    targets = data.get("targets") or {}
    sgs = targets.get("security_groups") or []
    if not isinstance(sgs, list) or not sgs:
        raise IntentError("targets.security_groups must be a non-empty list of resource addresses")
    aps = targets.get("attachment_points") or []
    services: List[GuardedService] = []
    for i, g in enumerate(data.get("guarded_services") or []):
        where = f"guarded_services[{i}]"
        svc = _svc(g, where)
        ap = g.get("approved_sources") or {}
        approved = ApprovedSources(
            cidrs_v4=_cidr_list(ap.get("cidrs_v4"), 4, where + ".cidrs_v4"),
            cidrs_v6=_cidr_list(ap.get("cidrs_v6"), 6, where + ".cidrs_v6"),
            security_group_refs=[str(x) for x in (ap.get("security_group_refs") or [])],
            prefix_list_refs=[str(x) for x in (ap.get("prefix_list_refs") or [])],
        )
        if approved.cidrs_v4 and NetSet.from_cidrs(4, approved.cidrs_v4).covers_everything():
            raise IntentError(f"{where}: approved IPv4 sources cover the entire internet — not acceptable for a guarded service")
        if approved.cidrs_v6 and NetSet.from_cidrs(6, approved.cidrs_v6).covers_everything():
            raise IntentError(f"{where}: approved IPv6 sources cover the entire internet — not acceptable for a guarded service")
        services.append(GuardedService(svc, approved))
    if not services:
        raise IntentError("guarded_services must contain at least one service")
    required: List[RequiredAccess] = []
    for i, r in enumerate(data.get("required_access") or []):
        where = f"required_access[{i}]"
        svc = _svc(r, where)
        src = r.get("source_cidr")
        try:
            n = parse_cidr(str(src))
        except CidrParseError as e:
            raise IntentError(f"{where}: {e}")
        required.append(RequiredAccess(svc, str(n), str(r.get("label", ""))))
    return IntentSpec(
        intent_id=intent_id,
        intent_version=str(data.get("intent_version", "1")),
        status=status,
        target_dir=str(data.get("target_dir", "")),
        target_security_groups=[str(s) for s in sgs],
        attachment_points=[str(a) for a in aps],
        guarded_services=services,
        required_access=required,
        description=str(data.get("description", "")),
        raw=data,
        path=path,
    )


def load_intent(path: str | Path) -> IntentSpec:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise IntentError(f"intent file not found: {p}")
    except json.JSONDecodeError as e:
        raise IntentError(f"intent file is not valid JSON ({p}): {e}")
    return parse_intent(data, str(p))


def try_load_intent(path: str | Path) -> "tuple[Optional[IntentSpec], Optional[str]]":
    """(spec, None) 또는 (None, 오류 메시지). 파이프라인이 INSUFFICIENT_INFO 로 분기하는 데 쓴다."""
    try:
        return load_intent(path), None
    except IntentError as e:
        return None, str(e)
