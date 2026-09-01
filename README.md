#  Cloud Security Capstone Project Proposals

본 저장소는 **클라우드 인프라, 컨테이너, 보안**을 결합한 캡스톤 디자인 기획안 5종을 관리하는 공간입니다.  
*(각 기획서 내부에는 **[기본 구현 버전]**과 **[AI Agent 고도화 확장 버전]**이 함께 포함되어 있습니다.)*

---

##  캡스톤 디자인 기획안 목록 (Topic Proposals)

교수님 면담 및 인프라 방향성에 따라 아래 5가지 제안서 중 최종 채택하여 진행합니다.

1. **[A안] AWS/도커 기반 구역(Zone) 분리 및 AI 연동 통합 보안 관제 시스템**
   -  [기획서 상세 보기](docs/01-option-A-ai-soc.md)
2. **[B안] 도커/쿠버네티스 CI/CD 환경에서의 AI 기반 보안 취약점 자동 진단 파이프라인**
   -  [기획서 상세 보기](docs/02-option-B-devsecops.md)
3. **[C안] 클라우드 인프라 보안 설정 오류(Misconfiguration) 실시간 탐지 및 자동 조치 시스템**
   -  [기획서 상세 보기](docs/03-option-C-cloud-compliance.md)
4. **[D안] 쿠버네티스/도커 기반 AI 모델 자동 배포 및 컨테이너 보안 경량화 플랫폼**
   -  [기획서 상세 보기](docs/04-option-D-container-sec.md)
5. **[E안] 하이브리드 클라우드(온프레미스 ↔ AWS) 연동 및 통합 보안 모니터링 구축**
   -  [기획서 상세 보기](docs/05-option-E-hybrid-cloud.md)

---

##  공통 기술 스택 (Tech Stack)
- **Infra:** AWS, Docker, Kubernetes, Linux
- **AI & Automation:** LangChain/LangGraph (Agentic Workflow), Python, LLM API
- **Security & Monitoring:** Trivy, Security Group, Boto3, Grafana
