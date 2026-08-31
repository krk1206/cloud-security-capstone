# [C안] 클라우드 인프라 보안 설정 오류(Misconfiguration) 실시간 탐지 및 자동 조치 시스템

## 1. 프로젝트 개요
- **핵심 컨셉:** 클라우드(AWS) 환경에서 발생하는 포트 전체 개방, 과도한 IAM 권한 부여 등 보안 설정 오류를 감지하고 자동 안전 원복하는 시스템.
- **주요 기능:**
  - AWS Security Group 및 IAM 권한 실시간 모니터링
  - 최소 권한 원칙(Least Privilege) 위반 시 Slack/이메일 알림
  - 고위험 설정 오류에 대한 자동 정책 원복 (Auto-Remediation)
- **기술 스택:** AWS (VPC, Security Group, IAM, CloudWatch), Python, Shell Script, Slack API
