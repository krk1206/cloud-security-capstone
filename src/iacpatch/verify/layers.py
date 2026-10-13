"""검증 계층 V1 ~ V5 (배포 전, 결정론적).

  V1 대상 finding 제거      : 패치 후 Trivy 재스캔에서 지목된 (룰, 파일, 리소스) 키가 사라졌는가
  V2 finding 집합 비교      : 전후 finding 을 키 집합으로 비교. 새 finding 이 생겼는가 (개수 비교 아님)
  V3 terraform validate     : 문법 + 스키마/참조 정합성
  V4 terraform plan         : plan 생성 성공 여부
  V5 plan diff 정책         : planned_values 구조 비교 + resource_changes 액션으로 허용 범위 밖 변경/삭제/교체 탐지

각 함수는 LayerResult 를 돌려준다. 도구가 없으면 SKIPPED (PASS 아님).
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from ..models import Finding, LayerResult, Verdict
from ..tools.terraform import StepOutput
from ..tools.trivy import TrivyScan
from .plan_model import iter_planned_resources, resource_actions

# ---------------------------------------------------------------------------
# V1
# ---------------------------------------------------------------------------
def v1_target_finding(target: Finding, before: TrivyScan, after: TrivyScan,
                      candidate_resource_present: Optional[bool] = None) -> LayerResult:
    tool = f"trivy {after.version}" if after.version else "trivy"
    if not after.ok:
        return LayerResult("V1", "target finding removed", Verdict.ERROR, f"re-scan failed: {after.error}", {}, True, tool)
    if after.parse_errors:
        # Trivy 는 파싱 못 한 파일을 건너뛰고 나머지 검사를 '성공' 으로 세므로, 이 상태의 '경고 없음' 은 통과가 아니다 (팀 PC 실습 09-29: 속성 중복 파일이 V1 PASS 로 나옴)
        return LayerResult("V1", "target finding removed", Verdict.ERROR,
                           "re-scan could not parse the candidate (Trivy skipped it, so 'no finding' means 'not scanned'): " + "; ".join(after.parse_errors[:2]),
                           {"parse_errors": after.parse_errors}, True, tool)
    if after.summary.get("checks_executed", 0) == 0:
        return LayerResult("V1", "target finding removed", Verdict.ERROR,
                           "re-scan executed 0 checks — cannot distinguish 'passed' from 'not scanned'", after.summary, True, tool)
    before_keys = {f.key for f in before.findings} if before.ok else set()
    after_keys = {f.key for f in after.findings}
    details: Dict[str, Any] = {
        "target_key": target.key,
        "present_before": target.key in before_keys,
        "present_after": target.key in after_keys,
        "checks_executed_after": after.summary.get("checks_executed"),
    }
    if target.key in after_keys:
        return LayerResult("V1", "target finding removed", Verdict.FAIL, f"{target.rule_id} still reported on {target.resource}", details, True, tool)
    summary = f"{target.rule_id} no longer reported on {target.resource}"
    if candidate_resource_present is False:
        summary += " — NOTE: the resource itself is absent from the candidate plan (deletion is judged by V5/V6, not here)"
        details["resource_absent_in_candidate"] = True
    return LayerResult("V1", "target finding removed", Verdict.PASS, summary, details, True, tool)


# ---------------------------------------------------------------------------
# V2
# ---------------------------------------------------------------------------
def v2_finding_diff(before: TrivyScan, after: TrivyScan, block_severities: Iterable[str] = ("CRITICAL", "HIGH"),
                    ignore_rules: Iterable[str] = ()) -> LayerResult:
    tool = f"trivy {after.version}" if after.version else "trivy"
    if not before.ok or not after.ok:
        return LayerResult("V2", "new findings introduced?", Verdict.ERROR, f"scan failed: before={before.error!r} after={after.error!r}", {}, True, tool)
    if after.parse_errors or before.parse_errors:
        return LayerResult("V2", "new findings introduced?", Verdict.ERROR, "a scan could not parse its input (Trivy skips unparseable files): "
                           + "; ".join((after.parse_errors or before.parse_errors)[:2]), {"before": before.parse_errors, "after": after.parse_errors}, True, tool)
    if after.summary.get("checks_executed", 0) == 0 or before.summary.get("checks_executed", 0) == 0:
        return LayerResult("V2", "new findings introduced?", Verdict.ERROR, "a scan executed 0 checks", {"before": before.summary, "after": after.summary}, True, tool)
    bmap = {f.key: f for f in before.findings}
    amap = {f.key: f for f in after.findings}
    new_keys = sorted(set(amap) - set(bmap))
    resolved_keys = sorted(set(bmap) - set(amap))
    ignore = set(ignore_rules)
    block = {s.upper() for s in block_severities}
    new_list = [amap[k] for k in new_keys]
    blocking = [f for f in new_list if f.severity.upper() in block and f.rule_id not in ignore]
    # 같은 룰이 다른 리소스 키로 옮겨간 경우(inline → 별도 규칙 리소스 등)를 표시
    moved = []
    for f in new_list:
        for g in (bmap[k] for k in resolved_keys):
            if f.rule_id == g.rule_id and f.filename == g.filename:
                moved.append({"rule": f.rule_id, "from": g.resource, "to": f.resource})
    details = {
        "before_count": len(bmap), "after_count": len(amap),
        "new": [f.to_dict() for f in new_list],
        "resolved": [bmap[k].to_dict() for k in resolved_keys],
        "possibly_moved": moved,
        "checks_executed": {"before": before.summary.get("checks_executed"), "after": after.summary.get("checks_executed")},
        "block_severities": sorted(block), "ignored_rules": sorted(ignore),
    }
    if blocking:
        return LayerResult("V2", "new findings introduced?", Verdict.FAIL,
                           "new " + ", ".join(f"{f.rule_id}({f.severity}) on {f.resource}" for f in blocking), details, True, tool)
    if new_list:
        return LayerResult("V2", "new findings introduced?", Verdict.WARN,
                           "new non-blocking findings: " + ", ".join(f"{f.rule_id}({f.severity}) on {f.resource}" for f in new_list), details, True, tool)
    return LayerResult("V2", "new findings introduced?", Verdict.PASS,
                       f"no new findings (resolved {len(resolved_keys)}, unchanged {len(set(bmap) & set(amap))})", details, True, tool)


# ---------------------------------------------------------------------------
# V3 / V4  (terraform 어댑터 결과를 LayerResult 로)
# ---------------------------------------------------------------------------
def v3_validate(steps: Dict[str, StepOutput], tool: str) -> LayerResult:
    init = steps.get("init")
    if init is None or (init.result is None and not init.ok):
        return LayerResult("V3", "terraform validate", Verdict.SKIPPED, f"terraform not available: {init.error if init else 'no init step'}", {}, False, tool)
    if not init.ok:
        return LayerResult("V3", "terraform validate", Verdict.ERROR, f"init failed: {init.error[:500]}", {}, True, tool)
    v = steps.get("validate")
    if v is None:
        return LayerResult("V3", "terraform validate", Verdict.ERROR, "validate did not run", {}, True, tool)
    fmt = steps.get("fmt")
    details = {"diagnostics": (v.data or {}).get("diagnostics", []), "needs_format": bool(fmt and fmt.data.get("needs_format"))}
    if not v.ok:
        return LayerResult("V3", "terraform validate", Verdict.FAIL, v.error[:500] or "invalid", details, True, tool)
    summary = "valid (syntax + schema/reference consistency)"
    if details["needs_format"]:
        summary += "; fmt would reformat the files (not blocking)"
    return LayerResult("V3", "terraform validate", Verdict.PASS, summary, details, True, tool)


def v4_plan(steps: Dict[str, StepOutput], tool: str, offline: bool) -> LayerResult:
    if "plan" not in steps:
        v = steps.get("validate")
        why = "validate failed, plan not attempted" if v is not None and not v.ok else "plan not attempted"
        if steps.get("init") is None or (steps["init"].result is None and not steps["init"].ok):
            return LayerResult("V4", "terraform plan", Verdict.SKIPPED, "terraform not available", {}, False, tool)
        return LayerResult("V4", "terraform plan", Verdict.ERROR, why, {}, True, tool)
    p = steps["plan"]
    show = steps.get("show")
    details = {"offline_mode": offline, "plan_stdout_tail": (p.result.stdout[-1500:] if p.result else "")}
    if not p.ok:
        return LayerResult("V4", "terraform plan", Verdict.FAIL, p.error[:800] or "plan failed", details, True, tool)
    if show is None or not show.ok:
        return LayerResult("V4", "terraform plan", Verdict.ERROR, f"show -json failed: {show.error if show else 'missing'}", details, True, tool)
    plan = show.data
    actions = resource_actions(plan)
    details["actions"] = actions
    summary = "plan generated"
    if offline:
        summary += " (offline mode: no state, every resource appears as create — V5 uses structural diff)"
    return LayerResult("V4", "terraform plan", Verdict.PASS, summary, details, True, tool)


# ---------------------------------------------------------------------------
# V5
# ---------------------------------------------------------------------------
def _flatten(plan: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for r in iter_planned_resources(plan):
        if r.get("mode") != "managed":
            continue
        out[r["address"]] = {"type": r.get("type"), "values": r.get("values") or {}}
    return out


def _changed_attrs(a: Dict[str, Any], b: Dict[str, Any]) -> List[str]:
    keys = set(a) | set(b)
    changed = []
    for k in sorted(keys):
        if a.get(k) != b.get(k):
            changed.append(k)
    return changed


def _provider_config_diff(bp: Dict[str, Any], cp: Dict[str, Any]) -> List[str]:
    b = (bp.get("configuration") or {}).get("provider_config") or {}
    c = (cp.get("configuration") or {}).get("provider_config") or {}
    diffs = []
    for k in sorted(set(b) | set(c)):
        if b.get(k) != c.get(k):
            diffs.append(k)
    return diffs


def v5_plan_diff(baseline_plan: Optional[Dict[str, Any]], candidate_plan: Optional[Dict[str, Any]], policy: Dict[str, Any],
                 tool: str = "") -> LayerResult:
    if baseline_plan is None or candidate_plan is None:
        return LayerResult("V5", "plan diff within policy", Verdict.SKIPPED, "plan json missing (V4 did not produce both plans)", {}, False, tool)
    base = _flatten(baseline_plan)
    cand = _flatten(candidate_plan)
    removed = sorted(set(base) - set(cand))
    added = sorted(set(cand) - set(base))
    common = sorted(set(base) & set(cand))
    changed: Dict[str, List[str]] = {}
    type_changed: List[str] = []
    for addr in common:
        if base[addr]["type"] != cand[addr]["type"]:
            type_changed.append(addr)
            continue
        attrs = _changed_attrs(base[addr]["values"], cand[addr]["values"])
        if attrs:
            changed[addr] = attrs
    actions = resource_actions(candidate_plan)
    deletes = [a for a, acts in actions.items() if acts == ["delete"]]
    replaces = [a for a, acts in actions.items() if set(acts) == {"create", "delete"}]

    violations: List[str] = []
    allow_delete = bool(policy.get("allow_delete", False))
    allow_replace = bool(policy.get("allow_replace", False))
    allowed_change = set(policy.get("allowed_change_resource_types") or [])
    allowed_create = set(policy.get("allowed_create_resource_types") or [])
    allowed_attrs = policy.get("allowed_attribute_changes") or {}
    max_changed = int(policy.get("max_changed_resources", 3))

    for addr in removed:
        if not allow_delete:
            violations.append(f"resource removed from configuration: {addr} ({base[addr]['type']})")
    for addr in deletes:
        if not allow_delete and addr not in removed:
            violations.append(f"plan deletes {addr}")
    for addr in replaces:
        if not allow_replace:
            violations.append(f"plan replaces (destroy+create) {addr}")
    for addr in type_changed:
        violations.append(f"resource type changed for {addr}: {base[addr]['type']} → {cand[addr]['type']}")
    for addr in added:
        t = cand[addr]["type"]
        if t not in allowed_create:
            violations.append(f"new resource {addr} of type {t} is not in allowed_create_resource_types")
    for addr, attrs in changed.items():
        t = cand[addr]["type"]
        if allowed_change and t not in allowed_change:
            violations.append(f"changed resource {addr} of type {t} is not in allowed_change_resource_types")
        allowed_for_type = allowed_attrs.get(t)
        if allowed_for_type is not None:
            bad = [a for a in attrs if a not in allowed_for_type]
            if bad:
                violations.append(f"{addr}: attributes changed outside allowlist: {', '.join(bad)}")
    total = len(removed) + len(added) + len(changed) + len(type_changed)
    if total > max_changed:
        violations.append(f"{total} resources touched > max_changed_resources={max_changed}")
    pdiff = _provider_config_diff(baseline_plan, candidate_plan)
    if pdiff and not policy.get("provider_config_change_allowed", False):
        violations.append(f"provider configuration changed: {', '.join(pdiff)}")

    details = {
        "removed": removed, "added": [{"address": a, "type": cand[a]["type"]} for a in added],
        "changed": changed, "type_changed": type_changed,
        "plan_actions_delete": deletes, "plan_actions_replace": replaces,
        "provider_config_diff": pdiff, "violations": violations,
        "policy_version": policy.get("policy_version", ""),
        "touched_resources": total,
    }
    if violations:
        return LayerResult("V5", "plan diff within policy", Verdict.FAIL, "; ".join(violations)[:1200], details, True, tool)
    if total == 0:
        return LayerResult("V5", "plan diff within policy", Verdict.WARN, "no resource-level change between baseline and candidate plans", details, True, tool)
    return LayerResult("V5", "plan diff within policy", Verdict.PASS,
                       f"changes within policy: changed={list(changed)} added={[a for a in added]} removed={removed}", details, True, tool)
