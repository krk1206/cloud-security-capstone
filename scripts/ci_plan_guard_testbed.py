#!/usr/bin/env python3
"""워크플로 ② 시험 환경 — 패치 plan 점검 (stdlib 만).

입력: `terraform show -json patch.tfplan` 결과 파일.
출력(stdout, GITHUB_OUTPUT 형식 key=value 한 줄씩):
  plan_check     OK | BLOCKED
  destructive    패치 대상(module.sg.* 또는 aws_security_group*) 중 삭제·교체되는 주소 (쉼표)
  testbed_churn  시험 환경 자체 리소스 중 삭제·교체되는 주소 (쉼표) — 차단하지 않고 기록만
  updated        제자리 수정(update)되는 주소 (쉼표)
  replace_why    교체되는 리소스마다 "주소:속성경로|속성경로" (세미콜론) — 교체를 강제한 속성

차단 기준을 "패치 대상" 으로 한정하는 이유: 시험 환경의 EC2 는 V8 의 과녁일 뿐이라
AMI 갱신 등으로 교체돼도 패치의 안전성과 무관하다. 패치가 보안 그룹을 지우거나 다시 만들면 차단한다.
"""
from __future__ import annotations

import json
import sys


def _is_target(address: str, rtype: str) -> bool:
    return address.startswith("module.sg.") or rtype.startswith("aws_security_group")


def _paths(replace_paths) -> list[str]:
    out = []
    for p in replace_paths or []:
        out.append(".".join(str(x) for x in p) if isinstance(p, list) else str(p))
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: ci_plan_guard_testbed.py <patch-plan.json>", file=sys.stderr)
        return 2
    d = json.load(open(argv[1], encoding="utf-8"))
    bad, churn, upd, why = [], [], [], []
    for c in d.get("resource_changes", []) or []:
        ch = c.get("change") or {}
        actions = ch.get("actions") or []
        addr = c.get("address", "")
        rtype = c.get("type", "")
        if actions == ["update"]:
            upd.append(addr)
        if "delete" in actions:
            (bad if _is_target(addr, rtype) else churn).append(addr)
            if len(actions) > 1:  # replace = ["delete","create"] or ["create","delete"]
                why.append(addr + ":" + "|".join(_paths(ch.get("replace_paths"))))
    print("plan_check=" + ("BLOCKED" if bad else "OK"))
    print("destructive=" + ",".join(bad))
    print("testbed_churn=" + ",".join(churn))
    print("updated=" + ",".join(upd))
    print("replace_why=" + ";".join(why))
    if churn:
        print(f"::warning::시험 환경 자체 리소스 교체·삭제 (차단 안 함): {','.join(churn)} — 이유: {';'.join(why) or '-'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
