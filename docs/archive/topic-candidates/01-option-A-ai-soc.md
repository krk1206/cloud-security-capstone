# [A안] AWS/도커 기반 구역(Zone) 분리 및 AI 연동 통합 보안 관제 시스템

##  [기본 버전] 1. 배경 및 필요성
- 기존 클라우드/데이터센터 환경에서는 네트워크 경계가 모호해짐에 따라, **망 분리(Zero Trust Zone) 및 실시간 보안 관제**의 중요성이 급증함.
- 보안 전문 인력 부족 문제를 해결하기 위해, 난해한 보안 로그 및 취약점 정보를 **AI(LLM)가 해석하여 직관적인 조치 가이드를 제공**하는 관제 시스템 필요.

##  [기본 버전] 2. 시스템 아키텍처 및 핵심 기능
1. **망 분리 및 인프라 구축:** AWS VPC 및 Docker Network를 활용해 `External(외부망)`, `DMZ(완충구간)`, `Management(관리/내부망)` 구역으로 서브넷 및 보안그룹 격리.
2. **실시간 보안 스캐닝:** 각 Zone에 배치된 컨테이너 및 서버의 오픈 포트, CVE 취약점, 설정 오류(Misconfiguration)를 **Trivy / Nmap** 기반으로 주기적 자동 스캔.
3. **AI 기반 위협 분석 & 자동 리포팅:** 수집된 보안 로그를 **OpenAI/Claude API**로 전달하여 위험도(Low/Medium/High/Critical) 판정 및 한글 대응 가이드 자동 생성.
4. **통합 관제 대시보드 시각화:** **Grafana / Streamlit**을 활용하여 Zone별 보안 상태, 실시간 이벤트, AI 리포트를 한눈에 모니터링하는 SOC 대시보드 제공.

---

##  [AI Agent 고도화 확장 버전]
- **핵심 컨셉:** 단순 알림 생성을 넘어, **AI Agent가 자율 판단(Reasoning) 및 인프라 제어 도구(Action/Tool Calling)**를 조합해 위협을 능동 격리하는 Zero-Touch SOC 구현.
- **Agent 동작 흐름:**
  1. **Reasoning:** 이상 트래픽 발생 시 AI Agent가 로그 문맥 및 위협 수준 자율 분석.
  2. **Action (Tool Calling):** Agent가 `Nmap/Trivy API` 도구를 직접 실행해 정밀 스캔 수행 $\rightarrow$ 고위험군 판정 시 `AWS CLI / iptables` 도구를 호출해 공격 IP 및 포트 자동 차단.
  3. **Visualizing:** Agent의 사고 과정(Thought-Action-Observation)을 관제 대시보드에 실시간 시각화.
