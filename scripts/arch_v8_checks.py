#!/usr/bin/env python3
"""아키텍처(scenarios/arch/webapp-2tier) 배포 뒤 V8(통신 확인) 체크 정의 파일을 만든다.

    IaCPatch-console.exe --exec scripts/arch_v8_checks.py --web-ip 3.35.x.x --app-ip 10.0.2.x
    python3 scripts/arch_v8_checks.py --web-ip 3.35.x.x --app-ip 10.0.2.x [--out scenarios/arch/webapp-2tier/sandbox/v8-checks.json]

값은 `terraform output` 의 web_public_ip / app_private_ip. 이 PC 는 평가용 intent(승인 출처 10.0.0.0/8) 밖의 출처이므로
"승인 밖에서 막혀야 하는 통신" 의 관측 지점(vantage) 이 된다 — 그래서 핫스팟 없이도 ssh/rdp/app-8080 의 closed 검사가 성립한다.
80 은 공개 웹이라 열려 있어야 한다(expect open). 모델 호출·AWS 접속 없음. 파일만 쓴다.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import argparse
import ipaddress
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = "scenarios/arch/webapp-2tier/sandbox/v8-checks.json"


def build(web_ip: str, app_ip: str, intent_id: str = "arch-webapp-sg") -> dict:
    for ip in (web_ip, app_ip):
        ipaddress.ip_address(ip)   # 형식 검사 — 틀리면 ValueError
    return {
        "_comment": [
            "scripts/arch_v8_checks.py 가 만든 V8 체크 정의. 실행: iacpatch postdeploy --review <id> --intent <intent> --v8-checks 이 파일 --execute",
            "이 PC 의 공인 IP 는 승인 출처(10.0.0.0/8) 밖이므로 source_class=unapproved 의 closed 검사는 여기서 바로 돌릴 수 있다.",
            "취약한 원본을 apply 한 상태에서는 ssh-closed 검사가 '열림' 으로 나와 V8 FAIL 이 정상이다(설정 오류가 실제로 뚫린다는 증거). 패치 apply 뒤에는 PASS 여야 한다.",
        ],
        "intent_id": intent_id,
        "checks": [
            {"label": "web-http-open", "service_label": "public-http", "host": web_ip, "port": 80, "expect": "open",
             "vantage": "local", "source_class": "approved", "timeout_s": 5,
             "_note": "공개 웹 서버 — 누구에게나 열려 있어야 한다(정상 기능). 부팅 직후 1~2분은 nginx 설치 중이라 닫혀 보일 수 있다"},
            {"label": "ssh-closed-from-unapproved-pc", "service_label": "ssh", "host": web_ip, "port": 22, "expect": "closed",
             "vantage": "local", "source_class": "unapproved", "timeout_s": 5,
             "_note": "이 PC 는 10.0.0.0/8 밖 → 막혀야 한다. 원본(0.0.0.0/0)에서는 열려서 FAIL, 패치 뒤 timeout 으로 PASS"},
            {"label": "rdp-closed-from-unapproved-pc", "service_label": "rdp", "host": web_ip, "port": 3389, "expect": "closed",
             "vantage": "local", "source_class": "unapproved", "timeout_s": 5},
            {"label": "app-8080-closed-from-unapproved-pc", "service_label": "app-8080", "host": app_ip, "port": 8080, "expect": "closed",
             "vantage": "local", "source_class": "unapproved", "timeout_s": 5,
             "_note": "앱 서버는 사설 IP 뿐이라 인터넷에서 닿지 않는다(timeout=closed). 'SG 가 막았다' 가 아니라 '경로가 없다' 는 뜻 — 기록에 그렇게 적는다"},
            {"label": "ssh-closed-from-hotspot", "service_label": "ssh", "host": web_ip, "port": 22, "expect": "closed",
             "vantage": "phone-hotspot", "source_class": "unapproved", "observed": None,
             "_note": "선택. 휴대폰 핫스팟에 붙여 PowerShell 에서 Test-NetConnection <web_ip> -Port 22 → TcpTestSucceeded False 면 observed 를 \"timeout\" 으로 적는다. 비워 두면 NOT_RUN"},
        ],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="아키텍처 V8 체크 정의 생성")
    ap.add_argument("--web-ip", required=True, help="terraform output web_public_ip")
    ap.add_argument("--app-ip", required=True, help="terraform output app_private_ip")
    ap.add_argument("--out", default=DEFAULT_OUT)
    a = ap.parse_args(argv)
    try:
        doc = build(a.web_ip, a.app_ip)
    except ValueError as e:
        print(f"IP 형식이 아니다: {e}", file=sys.stderr)
        return 2
    out = Path(a.out) if Path(a.out).is_absolute() else ROOT / a.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"썼음: {out}  (검사 {len(doc['checks'])}개 — 로컬 {sum(1 for c in doc['checks'] if c['vantage'] == 'local')}개)")
    print("다음: IaCPatch-console.exe --exec scripts/iacpatch_cli.py postdeploy --review <기록 id> "
          "--intent experiments/candidate-sets/arch-webapp-sg/intents/arch-webapp-sg.json --v8-checks " + a.out + " --execute")
    return 0


if __name__ == "__main__":
    sys.exit(main())
