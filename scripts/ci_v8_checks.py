#!/usr/bin/env python3
"""워크플로 ②: 임시 시험 환경의 EC2 공인 IP 로 V8(통신 확인) 체크 정의 파일을 만든다.

    python scripts/ci_v8_checks.py --host 3.35.x.x --out v8-checks.json [--intent-id sg-baseline]

관측 지점(vantage) 은 GitHub 러너 = 인터넷. 러너의 공인 IP 는 승인 출처(10.0.0.0/8) 밖이므로
"승인 밖에서 막혀야 하는 통신(22, 3389)" 의 closed 검사를 러너에서 바로 돌릴 수 있다.
80 은 공개 웹이라 열려야 한다(정상 기능 보존). 승인 출처 안에서의 22 접속(required_access) 은 러너에서 재지 못한다 —
그 확인은 V7(규칙 실측) 이 맡고, 내부 관측 지점(SSM) 은 범위 밖으로 둔다. 표준 라이브러리만 쓴다.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path


def build(host: str, intent_id: str) -> dict:
    ipaddress.ip_address(host)
    local = {"host": host, "vantage": "local", "timeout_s": 5}
    return {
        "_comment": "워크플로 ② 가 terraform output 으로 만든 파일. 러너(인터넷) = 승인 밖 관측 지점.",
        "intent_id": intent_id,
        "checks": [
            {"label": "web-http-open-from-internet", "service_label": "public-http", "port": 80, "expect": "open",
             "source_class": "approved", **local},
            {"label": "ssh-closed-from-unapproved-runner", "service_label": "ssh", "port": 22, "expect": "closed",
             "source_class": "unapproved", **local},
            {"label": "rdp-closed-from-unapproved-runner", "service_label": "rdp", "port": 3389, "expect": "closed",
             "source_class": "unapproved", **local},
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="terraform output target_public_ip")
    ap.add_argument("--intent-id", default="sg-baseline")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    doc = build(a.host, a.intent_id)
    Path(a.out).write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"썼음: {a.out} (검사 {len(doc['checks'])}개, host {a.host})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
