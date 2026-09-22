"""V6 Intent Oracle — IAM (Tier 1, docs/IAM_SCOPE.md).

무엇을 증명하나: 후보 plan 에서 대상 정책(그리고 대상 역할에 붙는 모든 정책)의 **Allow 문이 허용하는 (Action × Resource)
집합** 이 intent 의 승인 집합 안에 있는지(EXCESS), intent 가 요구하는 권한이 남아 있는지(MISSING).
스캐너 룰과 무관하다: Trivy 0.74.0 내장 체크는 `s3:*` (AVD-AWS-0345) 와 `iam:PassRole` (AVD-AWS-0342) 만 잡고,
`"Action": "*"` 는 잡지 않는다(AVD-AWS-0057 deprecated) — 그래서 "s3:* → *" 같은 후보가 스캐너를 통과한다.

Tier 1 에서 판단하지 않는 것 (→ UNKNOWN, 자동 승인 금지):
  Deny 문, NotAction / NotResource, Condition, Principal(리소스 정책), 정책 변수(${...}), `?` 와일드카드,
  plan 시점에 값이 미확정인 policy, AWS 관리형 정책(내용을 읽지 않음; intent 의 approved_managed_policy_arns 에 있으면 허용),
  같은 역할에 다른 방식(aws_iam_policy_attachment 의 roles 목록 등)으로 붙는 정책.

패턴 포함 판정: 후보 패턴 P 가 승인 패턴 Q 에 포함되는가(P ⊆ Q) — `*` 만 지원. P 의 `*` 를 어떤 리터럴과도 일치하지 않는
문자로 바꿔 Q 에 매칭한다 (예: "s3:*" ⊄ "s3:Get*", "s3:GetObject" ⊆ "s3:Get*", "*" ⊆ "*" 만).
Action 은 대소문자 무시, Resource(ARN) 는 대소문자 구분.

우선순위: EXCESS/MISSING 이 하나라도 있으면 FAIL. FAIL 이 없고 UNKNOWN 이 있으면 UNKNOWN. 둘 다 없으면 PASS.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..iam_intent import IamIntentSpec
from ..models import Verdict
from .plan_model import PlanParseError

POLICY_TYPES = ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy")
UNSUPPORTED_ATTACH_TYPES = ("aws_iam_policy_attachment", "aws_iam_role_policies_exclusive")
_SENTINEL = "\x00"


# ---------------------------------------------------------------------------
# 모델
# ---------------------------------------------------------------------------
@dataclass
class IamStatement:
    origin: str                      # "aws_iam_policy.app#0"
    effect: str
    actions: List[str]
    resources: List[str]
    not_actions: List[str] = field(default_factory=list)
    not_resources: List[str] = field(default_factory=list)
    has_condition: bool = False
    has_principal: bool = False
    sid: str = ""

    def unsupported_reasons(self) -> List[str]:
        r = []
        if self.effect != "allow":
            r.append(f"{self.origin}: Effect={self.effect!r} (Deny/other not evaluated in Tier 1)")
        if self.not_actions:
            r.append(f"{self.origin}: NotAction not supported")
        if self.not_resources:
            r.append(f"{self.origin}: NotResource not supported")
        if self.has_condition:
            r.append(f"{self.origin}: Condition not evaluated")
        if self.has_principal:
            r.append(f"{self.origin}: Principal present (resource policy?) — not evaluated")
        for v in self.actions + self.resources:
            if "${" in v or "?" in v:
                r.append(f"{self.origin}: pattern {v!r} uses a variable or '?' — not supported")
        return r


@dataclass
class IamPolicyDoc:
    address: str
    statements: List[IamStatement] = field(default_factory=list)
    unknown_reason: str = ""         # 값 미확정 / 파싱 실패


@dataclass
class IamRole:
    address: str
    name: str = ""
    attached_policies: List[str] = field(default_factory=list)      # 정책 주소 (plan 안)
    managed_policy_arns: List[str] = field(default_factory=list)    # 리터럴 ARN
    inline_docs: List[IamPolicyDoc] = field(default_factory=list)
    trust_policy: str = ""
    unknown_reasons: List[str] = field(default_factory=list)


@dataclass
class IamWorld:
    policies: Dict[str, IamPolicyDoc] = field(default_factory=dict)
    roles: Dict[str, IamRole] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    source: str = "plan"


# ---------------------------------------------------------------------------
# 정책 문서 파싱
# ---------------------------------------------------------------------------
def _as_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v]
    return [json.dumps(v)]


def parse_policy_document(address: str, text: Any) -> IamPolicyDoc:
    doc = IamPolicyDoc(address)
    if text is None:
        doc.unknown_reason = "policy value unknown at plan time"
        return doc
    try:
        data = json.loads(text) if isinstance(text, str) else text
    except (TypeError, ValueError) as e:
        doc.unknown_reason = f"policy is not valid JSON: {e}"
        return doc
    if not isinstance(data, dict):
        doc.unknown_reason = "policy document is not an object"
        return doc
    stmts = data.get("Statement")
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        doc.unknown_reason = "policy has no Statement list"
        return doc
    for i, s in enumerate(stmts):
        if not isinstance(s, dict):
            doc.unknown_reason = f"Statement[{i}] is not an object"
            return doc
        doc.statements.append(IamStatement(
            origin=f"{address}#{i}", effect=str(s.get("Effect", "")).lower(), actions=_as_list(s.get("Action")),
            resources=_as_list(s.get("Resource")), not_actions=_as_list(s.get("NotAction")), not_resources=_as_list(s.get("NotResource")),
            has_condition=bool(s.get("Condition")), has_principal=("Principal" in s or "NotPrincipal" in s), sid=str(s.get("Sid", ""))))
    return doc


# ---------------------------------------------------------------------------
# plan JSON → world
# ---------------------------------------------------------------------------
def _walk_planned(mod: Dict[str, Any], out: List[Dict[str, Any]]) -> None:
    for r in mod.get("resources") or []:
        out.append(r)
    for c in mod.get("child_modules") or []:
        _walk_planned(c, out)


def _walk_config(mod: Dict[str, Any], out: List[Dict[str, Any]], prefix: str = "") -> None:
    for r in mod.get("resources") or []:
        rr = dict(r)
        rr["_address"] = (prefix + r.get("address", "")) if prefix else r.get("address", "")
        out.append(rr)
    for name, call in (mod.get("module_calls") or {}).items():
        sub = call.get("module") or {}
        _walk_config(sub, out, prefix=f"{prefix}module.{name}.")


def _ref_to_address(refs: List[str], want_type: str) -> Optional[str]:
    """references ["aws_iam_policy.app.arn", "aws_iam_policy.app"] → "aws_iam_policy.app"."""
    for r in refs or []:
        parts = r.split(".")
        # module.x.aws_iam_policy.app.arn 형태도 허용
        for i in range(len(parts) - 1):
            if parts[i] == want_type:
                return ".".join(parts[: i + 2])
    return None


def build_iam_world(plan: Dict[str, Any]) -> IamWorld:
    if not isinstance(plan, dict) or "planned_values" not in plan:
        raise PlanParseError("plan JSON has no planned_values")
    world = IamWorld()
    planned: List[Dict[str, Any]] = []
    _walk_planned((plan.get("planned_values") or {}).get("root_module") or {}, planned)
    unknown_attrs: Dict[str, List[str]] = {}
    for rc in plan.get("resource_changes") or []:
        au = (rc.get("change") or {}).get("after_unknown") or {}
        unknown_attrs[rc.get("address", "")] = [k for k, v in au.items() if v is True]
    config: List[Dict[str, Any]] = []
    _walk_config((plan.get("configuration") or {}).get("root_module") or {}, config)
    cfg_by_addr = {c["_address"]: c for c in config}

    for r in planned:
        t, addr, vals = r.get("type"), r.get("address", ""), r.get("values") or {}
        if t in POLICY_TYPES:
            pol_text = vals.get("policy")
            if pol_text is None and "policy" in unknown_attrs.get(addr, []):
                doc = IamPolicyDoc(addr, unknown_reason="policy value unknown at plan time (computed)")
            else:
                doc = parse_policy_document(addr, pol_text)
            world.policies[addr] = doc
        elif t == "aws_iam_role":
            role = IamRole(addr, name=str(vals.get("name") or ""), trust_policy=str(vals.get("assume_role_policy") or ""))
            for i, ip in enumerate(vals.get("inline_policy") or []):
                if isinstance(ip, dict) and ip.get("policy"):
                    role.inline_docs.append(parse_policy_document(f"{addr}.inline_policy[{i}]", ip.get("policy")))
            if "inline_policy" in unknown_attrs.get(addr, []) and not role.inline_docs:
                pass  # provider 가 계산하는 속성 — 실제 인라인 정책이 없을 때도 unknown 으로 뜬다
            mp = vals.get("managed_policy_arns")
            if isinstance(mp, list):
                role.managed_policy_arns = [str(x) for x in mp]
            world.roles[addr] = role
        elif t in UNSUPPORTED_ATTACH_TYPES:
            world.notes.append(f"{addr}: {t} is not evaluated in Tier 1 (attached policies unknown)")

    # 연결: aws_iam_role_policy_attachment / aws_iam_role_policy → configuration 의 references 로 (plan 값은 미확정일 수 있다)
    for r in planned:
        t, addr, vals = r.get("type"), r.get("address", ""), r.get("values") or {}
        if t not in ("aws_iam_role_policy_attachment", "aws_iam_role_policy"):
            continue
        cfg = cfg_by_addr.get(addr) or {}
        ex = cfg.get("expressions") or {}
        role_addr = _ref_to_address((ex.get("role") or {}).get("references") or [], "aws_iam_role")
        if role_addr is None:
            # 리터럴 역할 이름 → 이름으로 찾는다
            rname = str(vals.get("role") or (ex.get("role") or {}).get("constant_value") or "")
            role_addr = next((a for a, ro in world.roles.items() if ro.name and ro.name == rname), None)
        if role_addr is None or role_addr not in world.roles:
            world.notes.append(f"{addr}: role reference could not be resolved in plan ({vals.get('role')!r})")
            continue
        role = world.roles[role_addr]
        if t == "aws_iam_role_policy_attachment":
            pol_addr = _ref_to_address((ex.get("policy_arn") or {}).get("references") or [], "aws_iam_policy")
            if pol_addr and pol_addr in world.policies:
                role.attached_policies.append(pol_addr)
            else:
                arn = vals.get("policy_arn") or (ex.get("policy_arn") or {}).get("constant_value")
                if isinstance(arn, str) and arn:
                    role.managed_policy_arns.append(arn)
                else:
                    role.unknown_reasons.append(f"{addr}: policy_arn unresolved (not a plan policy, not a literal ARN)")
        else:  # aws_iam_role_policy (inline via separate resource)
            if addr in world.policies:
                role.attached_policies.append(addr)
    return world


# ---------------------------------------------------------------------------
# 패턴 포함
# ---------------------------------------------------------------------------
def _glob_regex(q: str, ignore_case: bool) -> "re.Pattern[str]":
    parts = [re.escape(p) for p in q.split("*")]
    return re.compile("^" + ".*".join(parts) + "$", re.IGNORECASE if ignore_case else 0)


def pattern_subset(p: str, q: str, ignore_case: bool) -> bool:
    """P ⊆ Q ?  ('*' 만 지원)"""
    probe = p.replace("*", _SENTINEL)
    return bool(_glob_regex(q, ignore_case).match(probe))


def pattern_matches(pattern: str, concrete: str, ignore_case: bool) -> bool:
    return bool(_glob_regex(pattern, ignore_case).match(concrete))


# ---------------------------------------------------------------------------
# 판정
# ---------------------------------------------------------------------------
@dataclass
class IamScopeResult:
    scope_id: str                    # 대상 주소
    verdict: Verdict
    excess: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    unknown_reasons: List[str] = field(default_factory=list)
    evaluated_docs: List[str] = field(default_factory=list)
    allowed_pairs: int = 0


@dataclass
class IamOracleReport:
    verdict: Verdict
    summary: str
    scopes: List[IamScopeResult]
    intent_id: str
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"verdict": self.verdict.value, "summary": self.summary, "intent_id": self.intent_id, "kind": "iam", "notes": self.notes,
                "scopes": [{"scope_id": s.scope_id, "verdict": s.verdict.value, "excess": s.excess, "missing": s.missing,
                            "unknown_reasons": s.unknown_reasons, "evaluated_docs": s.evaluated_docs, "allowed_pairs": s.allowed_pairs}
                           for s in self.scopes]}


def _combine(verdicts: List[Verdict]) -> Verdict:
    if any(v == Verdict.FAIL for v in verdicts):
        return Verdict.FAIL
    if any(v == Verdict.UNKNOWN for v in verdicts):
        return Verdict.UNKNOWN
    return Verdict.PASS if verdicts else Verdict.UNKNOWN


def _evaluate_docs(scope_id: str, docs: List[IamPolicyDoc], intent: IamIntentSpec, extra_unknown: List[str]) -> IamScopeResult:
    res = IamScopeResult(scope_id, Verdict.PASS, unknown_reasons=list(extra_unknown))
    allow_stmts: List[IamStatement] = []
    for doc in docs:
        res.evaluated_docs.append(doc.address)
        if doc.unknown_reason:
            res.unknown_reasons.append(f"{doc.address}: {doc.unknown_reason}")
            continue
        for st in doc.statements:
            bad = st.unsupported_reasons()
            if bad:
                res.unknown_reasons.extend(bad)
                continue
            allow_stmts.append(st)
            for a in st.actions:
                for r in st.resources:
                    res.allowed_pairs += 1
                    ok = any(any(pattern_subset(a, qa, True) for qa in ap.actions) and any(pattern_subset(r, qr, False) for qr in ap.resources)
                             for ap in intent.approved)
                    if not ok:
                        res.excess.append(f"{st.origin}: {a} on {r}")
    had_unsupported = bool(res.unknown_reasons)
    for req in intent.required:
        hit = any(any(pattern_matches(a, req.action, True) for a in st.actions) and any(pattern_matches(r, req.resource, False) for r in st.resources)
                  for st in allow_stmts)
        if not hit:
            if had_unsupported:
                # 평가 못 한 문(NotAction/Condition/미확정 정책)이 그 권한을 줄 수도 있다 → MISSING 이 아니라 판단 불가
                res.unknown_reasons.append(f"{req.label}: {req.action} on {req.resource} is not granted by any evaluated Allow statement; "
                                           "only unevaluated statements could grant it")
            else:
                res.missing.append(f"{req.label}: {req.action} on {req.resource} not allowed by any evaluated Allow statement")
    if res.excess or res.missing:
        res.verdict = Verdict.FAIL
    elif res.unknown_reasons:
        res.verdict = Verdict.UNKNOWN
    else:
        res.verdict = Verdict.PASS
    return res


def evaluate(world: IamWorld, intent: IamIntentSpec) -> IamOracleReport:
    scopes: List[IamScopeResult] = []
    for p in intent.target_policies:
        if p not in world.policies:
            scopes.append(IamScopeResult(p, Verdict.FAIL, missing=[f"target policy {p} is absent from the plan (deleted or renamed)"]))
            continue
        scopes.append(_evaluate_docs(p, [world.policies[p]], intent, []))
    for ra in intent.target_roles:
        role = world.roles.get(ra)
        if role is None:
            scopes.append(IamScopeResult(ra, Verdict.FAIL, missing=[f"target role {ra} is absent from the plan (deleted or renamed)"]))
            continue
        docs = [world.policies[a] for a in role.attached_policies if a in world.policies] + list(role.inline_docs)
        extra = list(role.unknown_reasons)
        for arn in role.managed_policy_arns:
            if arn not in intent.approved_managed_policy_arns:
                extra.append(f"{ra}: managed policy {arn} attached — content not evaluated (not in approved_managed_policy_arns)")
        if not docs and not extra:
            extra.append(f"{ra}: no policy attached in plan — required permissions cannot be satisfied")
        scopes.append(_evaluate_docs(ra, docs, intent, extra))
    for n in world.notes:
        # Tier 1 밖의 연결 방식이 plan 에 있으면 판단 불가로 남긴다 (대상 역할에 붙었을 수 있으므로)
        for s in scopes:
            if s.verdict != Verdict.FAIL:
                s.unknown_reasons.append(n)
                s.verdict = Verdict.UNKNOWN if not (s.excess or s.missing) else s.verdict
    verdict = _combine([s.verdict for s in scopes])
    parts: List[str] = []
    for s in scopes:
        if s.verdict == Verdict.FAIL:
            parts.append(f"{s.scope_id}: FAIL — " + "; ".join((["EXCESS " + e for e in s.excess[:3]] + ["MISSING " + m for m in s.missing[:3]])))
        elif s.verdict == Verdict.UNKNOWN:
            parts.append(f"{s.scope_id}: UNKNOWN — {s.unknown_reasons[0] if s.unknown_reasons else 'unresolved'}")
        else:
            parts.append(f"{s.scope_id}: PASS ({s.allowed_pairs} allowed action×resource pairs all within approved set; required present)")
    summary = f"{verdict.value}: " + " | ".join(parts) if parts else f"{verdict.value}: no targets"
    return IamOracleReport(verdict, summary, scopes, intent.intent_id, notes=list(world.notes))
