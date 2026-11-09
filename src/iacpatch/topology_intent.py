"""설계도(토폴로지) 기준 의도 — "설계도에 그린 통신만 허용한다" (V6 의 세 번째 종류, 2026-10-20).

SG 의도(intent.py)는 포트 하나씩 "승인 출처"를 적는다. 계층이 많은 구조(ALB → 웹 → NLB → API → Redis/MySQL, Bastion)에서는
그 방식으로는 "웹 서버가 DB 에 바로 붙는다" 같은 계층 간 통신 오류를 적을 수가 없다. 그래서 설계도의 화살표를 그대로 적는다.

    {
      "kind": "topology",
      "intent_version": "1",
      "intent_id": "arch-3tier-flows",
      "status": "active",
      "target_dir": "scenarios/arch/webapp-3tier",
      "vpc_cidr": "10.0.0.0/16",
      "tiers":    [{"id": "web", "label": "웹 서버", "security_group": "aws_security_group.web"}, ...],
      "external": [{"id": "internet", "label": "인터넷 사용자", "cidrs_v4": ["0.0.0.0/0"]},
                   {"id": "admin", "label": "관리자 접속 허용 목록", "cidrs_v4": ["203.0.113.0/24"]}],
      "flows":    [{"id": "alb-web", "from": "alb", "to": "web", "protocol": "tcp", "port": 80, "label": "ALB → 웹 서버"}, ...]
    }

판정 기준 (verify/topology_oracle.py):
  - flows 에 있는 통신은 전부 열려 있어야 한다 (막히면 서비스나 관리 경로가 끊긴 것).
  - flows 에 없는 통신(들어오는 방향)은 전부 막혀 있어야 한다 (열려 있으면 설계 위반).
값을 추측해서 채우지 않는다. 자리표시자가 남아 있으면 사용하지 않는다 (intent.py 와 같은 규칙).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .intent import IntentError, _check_placeholders, _cidr_list

VALID_PROTOCOLS = {"tcp", "udp", "icmp", "-1"}


@dataclass
class Tier:
    id: str
    label: str
    security_group: str


@dataclass
class External:
    id: str
    label: str
    cidrs_v4: List[str]


@dataclass
class Flow:
    id: str
    src: str
    dst: str
    protocol: str
    from_port: int
    to_port: int
    label: str = ""

    @property
    def ports(self) -> str:
        if self.protocol == "-1":
            return "전체"
        return str(self.from_port) if self.from_port == self.to_port else f"{self.from_port}-{self.to_port}"


@dataclass
class TopologyIntentSpec:
    intent_id: str
    intent_version: str
    status: str
    target_dir: str
    vpc_cidr: str
    tiers: List[Tier]
    external: List[External]
    flows: List[Flow]
    description: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    path: str = ""

    @property
    def target_security_groups(self) -> List[str]:
        return [t.security_group for t in self.tiers]

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.raw)

    def label_of(self, entity_id: str) -> str:
        for t in self.tiers:
            if t.id == entity_id:
                return t.label
        for e in self.external:
            if e.id == entity_id:
                return e.label
        return {"vpc": "VPC 안 모든 서버", "unknown": "확인할 수 없는 출처"}.get(entity_id, entity_id)


def parse_topology_intent(data: Dict[str, Any], path: str = "") -> TopologyIntentSpec:
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
    vpc = _cidr_list([data.get("vpc_cidr")], 4, "vpc_cidr")[0] if data.get("vpc_cidr") else None
    if not vpc:
        raise IntentError("vpc_cidr missing")
    tiers: List[Tier] = []
    for i, t in enumerate(data.get("tiers") or []):
        if not t.get("id") or not t.get("security_group"):
            raise IntentError(f"tiers[{i}]: id 와 security_group 이 필요하다")
        tiers.append(Tier(str(t["id"]), str(t.get("label") or t["id"]), str(t["security_group"])))
    if not tiers:
        raise IntentError("tiers must not be empty")
    ext: List[External] = []
    for i, e in enumerate(data.get("external") or []):
        if not e.get("id"):
            raise IntentError(f"external[{i}]: id 가 필요하다")
        ext.append(External(str(e["id"]), str(e.get("label") or e["id"]), _cidr_list(e.get("cidrs_v4"), 4, f"external[{i}].cidrs_v4")))
    ids = [t.id for t in tiers] + [e.id for e in ext]
    if len(ids) != len(set(ids)):
        raise IntentError("tiers/external id 가 겹친다")
    if "vpc" in ids or "unknown" in ids:
        raise IntentError("'vpc', 'unknown' 은 예약된 id 다")
    tier_ids = {t.id for t in tiers}
    flows: List[Flow] = []
    for i, f in enumerate(data.get("flows") or []):
        where = f"flows[{i}]"
        src, dst = str(f.get("from") or ""), str(f.get("to") or "")
        if src not in ids:
            raise IntentError(f"{where}: from {src!r} 가 tiers/external 에 없음")
        if dst not in tier_ids:
            raise IntentError(f"{where}: to {dst!r} 는 tiers 의 id 여야 한다 (들어오는 통신만 다룬다)")
        proto = str(f.get("protocol", "tcp")).lower()
        if proto not in VALID_PROTOCOLS:
            raise IntentError(f"{where}: protocol 은 {sorted(VALID_PROTOCOLS)} 중 하나")
        if proto == "-1":
            lo, hi = 0, 65535
        else:
            try:
                lo = int(f.get("from_port", f.get("port")))
                hi = int(f.get("to_port", f.get("port")))
            except (TypeError, ValueError):
                raise IntentError(f"{where}: port(또는 from_port/to_port)가 필요하다")
            if not (0 <= lo <= hi <= 65535):
                raise IntentError(f"{where}: bad port range {lo}-{hi}")
        flows.append(Flow(str(f.get("id") or f"{src}-{dst}-{lo}"), src, dst, proto, lo, hi, str(f.get("label") or "")))
    if not flows:
        raise IntentError("flows must not be empty")
    if len({f.id for f in flows}) != len(flows):
        raise IntentError("flows id 가 겹친다")
    return TopologyIntentSpec(intent_id=intent_id, intent_version=str(data.get("intent_version", "1")), status=status,
                              target_dir=str(data.get("target_dir", "")), vpc_cidr=vpc, tiers=tiers, external=ext, flows=flows,
                              description=str(data.get("description", "")), raw=data, path=path)


def load_topology_intent(path: str | Path) -> TopologyIntentSpec:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise IntentError(f"intent file not found: {p}")
    except json.JSONDecodeError as e:
        raise IntentError(f"intent file is not valid JSON ({p}): {e}")
    return parse_topology_intent(data, str(p))


def try_load_topology_intent(path: str | Path) -> "tuple[Optional[TopologyIntentSpec], Optional[str]]":
    try:
        return load_topology_intent(path), None
    except IntentError as e:
        return None, str(e)
