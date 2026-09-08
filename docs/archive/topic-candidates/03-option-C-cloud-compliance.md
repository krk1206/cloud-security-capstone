# [C안] 클라우드 인프라 보안 설정 오류(Misconfiguration) 실시간 탐지 및 자동 조치 시스템

##  [기본 버전] 1. 배경 및 필요성
- 클라우드 보안 사고의 80% 이상은 시스템 결함이 아닌 **운영자의 설정 실수(인간의 실수)**에서 발생함.
- 포트 과다 개방(`0.0.0.0/0`), 과도한 IAM 권한 등을 실시간으로 감지하고 자동으로 원래의 안전한 상태로 복구하는 침해 예방 체계 필요.

##  [기본 버전] 2. 시스템 아키텍처 및 핵심 기능
1. **클라우드 자원 모니터링:** **AWS EventBridge / CloudWatch**를 연동하여 Security Group 변경, IAM Role 변경 이벤트를 실시간 감지.
2. **보안 컴플라이언스 진단 엔진:** Python 기반 엔진이 설정값을 평가하여 '최소 권한 원칙(Least Privilege)' 및 보안 가이드라인 위반 여부 검증.
3. **자동 조치(Auto-Remediation) 및 알림:** 고위험 설정 감지 시 **Boto3 SDK**를 이용해 즉시 기존 안전 정책으로 자동 원복하고 **Slack Webhook API**로 알림 통보.

---

##  [AI Agent 고도화 확장 버전]
- **핵심 컨셉:** 고정된 규칙 기반 원복이 아닌, **AI Agent가 설정 변경의 정당성/맥락을 판단하여 자율 복구(Auto-Remediation)**하는 컴플라이언스 체계 구축.
- **Agent 동작 흐름:**
  1. **Reasoning:** 변경된 보안 정책의 위험도 및 운영 맥락 자율 평가.
  2. **Action (Tool Calling):** `AWS Boto3 SDK` 도구를 실행해 위험 규칙 원복 및 안전 Baseline 재적용 $\rightarrow$ `Slack Bot API` 도구로 사고 경위 및 조치 결과 보고.
