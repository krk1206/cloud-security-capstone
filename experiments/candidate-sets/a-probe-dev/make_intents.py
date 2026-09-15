#!/usr/bin/env python3
"""A 의 Trivy 우회 실험 케이스 9종(experiments/trivy-sg-probe/cases/) 에 대한 **개발용** intent 파일을 만든다.

- 대상 SG 주소는 A 의 experiments/trivy-sg-probe/RESULTS.md 표와 main.tf 의 resource 이름에서 그대로 옮겼다.
- 승인 출처 10.0.0.0/8 은 **예제 값**이다 (examples/bc/case00/intent.json 과 같음). 팀이 정한 승인 CIDR 이 아니므로
  이 세트의 결과는 개발용(dev)이며 발표 수치에 쓰지 않는다. 팀 값이 정해지면 APPROVED 만 바꿔 다시 만들면 된다.
- 케이스 07(ipv6) 은 승인 v6 출처가 없다 → 규칙 기반은 규칙 삭제가 필요해 NOT_SUPPORTED 가 정상.

    python3 experiments/candidate-sets/a-probe-dev/make_intents.py
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
APPROVED_V4 = ["10.0.0.0/8"]          # 예제 값 — 팀 승인 CIDR 아님
CASES = {
    "00-baseline":     (["aws_security_group.baseline"], []),
    "01-cidr-split":   (["aws_security_group.cidr_split"], []),
    "02-var-default":  (["aws_security_group.var_default"], []),
    "03-string-build": (["aws_security_group.string_build"], []),
    "04-dynamic":      (["aws_security_group.dynamic_rules"], []),
    "05-separate":     (["aws_security_group.clean"], []),
    "06-prefix-list":  (["aws_security_group.prefix_list"], []),
    "07-ipv6-only":    (["aws_security_group.ipv6_only"], []),
    "08-second-sg":    (["aws_security_group.app", "aws_security_group.legacy"], ["aws_instance.app"]),
}


def main() -> None:
    out = HERE / "intents"
    out.mkdir(exist_ok=True)
    for case, (sgs, aps) in CASES.items():
        doc = {
            "intent_version": "1",
            "intent_id": f"a-probe-dev-{case}",
            "status": "active",
            "description": f"개발용 intent (A 의 trivy-sg-probe 케이스 {case}). 승인 출처 {APPROVED_V4} 는 예제 값이며 팀 승인 CIDR 이 아니다.",
            "target_dir": f"scenarios/eval/a-probe/{case}",
            "targets": {"security_groups": sgs, "attachment_points": aps},
            "guarded_services": [
                {"label": "ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
                 "approved_sources": {"cidrs_v4": APPROVED_V4, "cidrs_v6": [], "security_group_refs": [], "prefix_list_refs": []}},
                {"label": "rdp", "direction": "ingress", "protocol": "tcp", "from_port": 3389, "to_port": 3389,
                 "approved_sources": {"cidrs_v4": [], "cidrs_v6": [], "security_group_refs": [], "prefix_list_refs": []}},
            ],
            "required_access": [
                {"label": "admin-ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "source_cidr": APPROVED_V4[0]},
            ],
        }
        (out / f"{case}.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("wrote", out / f"{case}.json")


if __name__ == "__main__":
    main()
