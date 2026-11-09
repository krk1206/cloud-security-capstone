"""외부 기준 — 판정의 근거가 되는 공식 문서 항목.

원칙
- 원문이나 공식 문서에서 확인한 것만 적는다. 확인한 날짜와 확인 상태를 같이 적는다.
- 확인 안 된 것은 status 에 그대로 적는다 ("원문 대조 전"). 화면은 status 를 숨기지 않는다.
- Trivy 규칙과 기준 항목이 1:1 이라고 가정하지 않는다. Trivy 가 자기 메타데이터에 적은 태그는 'Trivy 가 선언한 것' 으로 따로 둔다.
- 우리 설계 요구사항(어떤 서버끼리 통신하나, 관리자 대역)은 외부 기준이 아니다. TEAM_REQUIREMENTS 로 따로 둔다.

확인 기록 (2026-10-22)
- AWS Security Hub CSPM 문서 'CIS AWS Foundations Benchmark in Security Hub CSPM': 지원 판 v5.0.0·v3.0.0·v1.4.0·v1.2.0,
  EC2.13 ↔ CIS v1.2.0 4.1, EC2.14 ↔ v1.2.0 4.2, EC2.53 ↔ v5.0.0 5.3 / v3.0.0 5.2, EC2.54 ↔ v5.0.0 5.4 / v3.0.0 5.3.
- AWS 문서 'Security Hub CSPM controls for Amazon EC2': EC2.13 관련 요구사항(CIS v1.2.0/4.1, NIST 800-53 r5 AC-4·SC-7 등,
  PCI DSS v4.0.1/1.3.1), 심각도 High. EC2.19 고위험 포트 목록(22, 3306, 3389, 5432 …), 심각도 Critical.
- CIS 'CIS Benchmarks April 2026 Update' 글: CIS Amazon Web Services Foundations Benchmark v7.0.0 발표.
- CIS v5.0.0 5.3 · v7.0.0 6.3 의 문구(TCP·UDP·ALL 프로토콜 포함)는 2차 출처에서 확인 — CIS 원문 PDF 대조 전.
- SK쉴더스 '2024 클라우드 보안 가이드북'(2024-04-03, AWS·Azure·GCP 3종): 존재는 기사로 확인. 항목 번호는 2차 출처 — 원문 PDF 확인 필요.
"""
from __future__ import annotations

from typing import Any, Dict, List

CHECKED = "2026-10-22"

AWS_EC2_CONTROLS = "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html"
AWS_CIS_IN_SECHUB = "https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html"
CIS_2026_04 = "https://www.cisecurity.org/insights/blog/cis-benchmarks-april-2026-update"

# 규칙(Trivy AVD ID) → 외부 기준. 'trivy' 칸의 값은 화면에서 이 PC 의 trivy 바이너리에서 다시 읽어 대조한다 (calibrate.trivy_rule_meta).
RULES: Dict[str, Dict[str, Any]] = {
    "AVD-AWS-0107": {
        "what": "관리용 포트(SSH 22 · RDP 3389)를 모든 IP 에 허용하는 보안 그룹 규칙",
        "trivy": {"title": "Security groups should not allow unrestricted ingress to SSH or RDP from any IP address.",
                  "severity": "HIGH", "frameworks": {"cis-aws-1.2": ["4.1", "4.2"]},
                  "source": "Trivy 0.74.0 바이너리에 들어 있는 규칙 메타데이터 (scripts/trivy_check_meta.py)"},
        "external": [
            {"org": "AWS", "doc": "Security Hub CSPM — Amazon EC2 컨트롤", "item": "EC2.13",
             "text": "Security groups should not allow ingress from 0.0.0.0/0 or ::/0 to port 22",
             "detail": "심각도 High · 관련: CIS v1.2.0 4.1, NIST 800-53 r5 AC-4·SC-7, PCI DSS v4.0.1 1.3.1",
             "url": AWS_EC2_CONTROLS + "#ec2-13", "checked": CHECKED, "status": "공식 문서 확인"},
            {"org": "AWS", "doc": "Security Hub CSPM — CIS 판별 대응표", "item": "EC2.53 ↔ CIS v5.0.0 5.3 (v3.0.0 5.2)",
             "text": "EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports",
             "detail": "IPv6(::/0)는 EC2.54 ↔ CIS v5.0.0 5.4",
             "url": AWS_CIS_IN_SECHUB, "checked": CHECKED, "status": "공식 문서 확인"},
            {"org": "CIS", "doc": "CIS Amazon Web Services Foundations Benchmark", "item": "v5.0.0 5.3 · 최신 v7.0.0 6.3",
             "text": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
             "detail": "문구상 TCP·UDP·ALL 프로토콜 포함. v7.0.0 발표는 CIS 공식 글에서 확인",
             "url": CIS_2026_04, "checked": CHECKED, "status": "번호는 AWS 대응표로 확인 · CIS 원문 PDF 대조 전"},
            {"org": "SK쉴더스", "doc": "2024 클라우드 보안 가이드북 (AWS)", "item": "3.1 보안 그룹 인/아웃바운드 ANY 설정 관리",
             "text": "양호: 인/아웃바운드 포트가 Any 로 허용돼 있지 않음 / 취약: Any 허용",
             "detail": "", "url": "", "checked": "", "status": "2차 출처 — 원문 PDF 로 번호·페이지 확인 필요"},
        ],
    },
    "AVD-AWS-0104": {
        "what": "아웃바운드 통신을 모든 IP 로 허용하는 보안 그룹 규칙",
        "trivy": {"title": "A security group rule should not allow unrestricted egress to any IP address.", "severity": "CRITICAL",
                  "frameworks": {}, "source": "Trivy 0.74.0 바이너리 규칙 메타데이터"},
        "external": [],
    },
}

# 고위험 포트 — AWS EC2.19 (심각도 Critical). Trivy 0.74.0 의 AVD-AWS-0107 은 22·3389 만 본다 (규칙 제목 기준).
EC2_19_PORTS: List[int] = [20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 3306, 3389, 4333, 5000, 5432, 5500, 5601, 8080, 8088, 8888, 9200, 9300]
EC2_19 = {"org": "AWS", "doc": "Security Hub CSPM — Amazon EC2 컨트롤", "item": "EC2.19",
          "text": "Security groups should not allow unrestricted access to ports with high risk",
          "detail": "심각도 Critical · 0.0.0.0/0 또는 ::/0 → 고위험 포트(22, 3306, 3389, 5432 …)", "url": AWS_EC2_CONTROLS + "#ec2-19",
          "checked": CHECKED, "status": "공식 문서 확인"}

# 우리 요구사항 — 외부 기준이 아니다
TEAM_REQUIREMENTS = {
    "design": {"what": "설계 기준 경로 9개만 허용, 그 외 인바운드 통신은 모두 차단",
               "file": "experiments/candidate-sets/arch-3tier-sg/intents/arch-3tier-flows.json",
               "status": "팀 설계 요구사항 (2026-10-20 실행 전 고정)"},
    "admin_allowlist": {"what": "관리자 접속 허용 대역", "value": ["203.0.113.0/24", "198.51.100.0/24"],
                        "status": "환경 요구사항 — 현재 값은 문서용 예시 대역(TEST-NET). 실제 배포 시 팀이 지정"},
    "policy": {"what": "수정 허용 범위 (변경 가능한 리소스·속성, 삭제·교체 금지, 최대 리소스 수)",
               "file": "policy/patch_policy.json", "status": "팀 정책"},
}


def for_rule(rule_id: str) -> Dict[str, Any]:
    r = RULES.get(rule_id)
    if r:
        return r
    return {"what": "", "trivy": {}, "external": []}
