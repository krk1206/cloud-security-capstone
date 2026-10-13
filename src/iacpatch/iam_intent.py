"""IAM Intent — "이 역할/정책은 어떤 권한만 가져야 하는가" 를 사람이 미리 적어 둔 파일 (Tier 1, docs/IAM_SCOPE.md).

SG intent(intent.py) 와 같은 역할이지만 대상이 IAM 이다. `"kind": "iam"` 으로 구분한다.

{
  "kind": "iam", "intent_id": "iam-app-role", "status": "active",
  "targets": {"policies": ["aws_iam_policy.app"], "roles": ["aws_iam_role.app"]},
  "approved_permissions": [                       # 허용해도 되는 (action 패턴 × resource 패턴) 집합의 합
    {"actions": ["s3:GetObject", "s3:ListBucket"], "resources": ["arn:aws:s3:::app-data", "arn:aws:s3:::app-data/*"]}
  ],
  "required_permissions": [                       # 반드시 남아 있어야 하는 (action, resource) — 없어지면 MISSING
    {"label": "read-objects", "action": "s3:GetObject", "resource": "arn:aws:s3:::app-data/*"}
  ],
  "approved_managed_policy_arns": []              # 역할에 붙어도 되는 AWS 관리형 정책 ARN (내용을 못 읽으므로 목록으로만)
}

- action/resource 의 와일드카드는 `*` 만 지원한다. `?` 나 정책 변수(${aws:...}) 가 나오면 오라클은 UNKNOWN 을 낸다.
- 값은 실행 전에 고정한다 (D-2 와 같은 원칙). 자리표시자(<...>) 가 남아 있으면 로드하지 않는다.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .intent import IntentError, _check_placeholders


@dataclass
class ApprovedPermission:
    actions: List[str]
    resources: List[str]


@dataclass
class RequiredPermission:
    label: str
    action: str
    resource: str


@dataclass
class IamIntentSpec:
    intent_id: str
    intent_version: str
    status: str
    target_policies: List[str]
    target_roles: List[str]
    approved: List[ApprovedPermission]
    required: List[RequiredPermission]
    approved_managed_policy_arns: List[str] = field(default_factory=list)
    description: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    path: str = ""
    kind: str = "iam"

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.raw)


def _str_list(v: Any, where: str) -> List[str]:
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list) or not all(isinstance(x, str) and x.strip() for x in v):
        raise IntentError(f"{where} must be a non-empty string or list of strings")
    return [x.strip() for x in v]


def parse_iam_intent(data: Dict[str, Any], path: str = "") -> IamIntentSpec:
    if not isinstance(data, dict):
        raise IntentError("intent must be a JSON object")
    if str(data.get("kind", "")).lower() != "iam":
        raise IntentError("not an IAM intent (kind != 'iam')")
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
    pols = targets.get("policies") or []
    roles = targets.get("roles") or []
    if not isinstance(pols, list) or not isinstance(roles, list) or not (pols or roles):
        raise IntentError("targets.policies or targets.roles must list at least one Terraform address")
    approved: List[ApprovedPermission] = []
    for i, a in enumerate(data.get("approved_permissions") or []):
        if not isinstance(a, dict):
            raise IntentError(f"approved_permissions[{i}] must be an object")
        approved.append(ApprovedPermission(_str_list(a.get("actions"), f"approved_permissions[{i}].actions"),
                                           _str_list(a.get("resources"), f"approved_permissions[{i}].resources")))
    if not approved:
        raise IntentError("approved_permissions must not be empty (an empty allow set makes every statement EXCESS)")
    required: List[RequiredPermission] = []
    for i, r in enumerate(data.get("required_permissions") or []):
        if not isinstance(r, dict) or not r.get("action") or not r.get("resource"):
            raise IntentError(f"required_permissions[{i}] needs action and resource")
        required.append(RequiredPermission(str(r.get("label") or f"required-{i}"), str(r["action"]).strip(), str(r["resource"]).strip()))
    managed = data.get("approved_managed_policy_arns") or []
    if not isinstance(managed, list):
        raise IntentError("approved_managed_policy_arns must be a list")
    return IamIntentSpec(intent_id=intent_id, intent_version=str(data.get("intent_version") or "1"), status=status,
                         target_policies=[str(p) for p in pols], target_roles=[str(r) for r in roles], approved=approved,
                         required=required, approved_managed_policy_arns=[str(m) for m in managed],
                         description=str(data.get("description") or ""), raw=data, path=path)


def load_iam_intent(path: str | Path) -> IamIntentSpec:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise IntentError(f"intent file not found: {p}")
    except json.JSONDecodeError as e:
        raise IntentError(f"intent file is not valid JSON ({p}): {e}")
    return parse_iam_intent(data, str(p))


def intent_kind(path: str | Path) -> str:
    """파일의 kind 필드만 읽는다: 'iam' | 'sg' (기본) | 'unreadable'."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "unreadable"
    return "iam" if isinstance(data, dict) and str(data.get("kind", "")).lower() == "iam" else "sg"


def try_load_any_intent(path: str | Path) -> Tuple[Optional[Any], str, Optional[str]]:
    """(spec, kind, error). kind 는 'sg' | 'iam'. SG intent 는 intent.try_load_intent 로 위임."""
    kind = intent_kind(path)
    if kind == "iam":
        try:
            return load_iam_intent(path), "iam", None
        except IntentError as e:
            return None, "iam", str(e)
    from .intent import try_load_intent
    spec, err = try_load_intent(path)
    return spec, "sg", err
