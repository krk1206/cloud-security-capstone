# Cloud Security Capstone Project

> **AWS 및 Docker 기반 구역(Zone) 분리 및 AI 연동 통합 보안 관제 시스템**

---

## 프로젝트 개요
본 프로젝트는 클라우드/컨테이너 인프라 환경에서 네트워크 구역(Zone)을 분리 구축하고, 오픈소스 보안 스캐너와 AI(LLM)를 연동하여 보안 취약점 감지 및 자동 조치 리포팅을 수행하는 통합 보안 관제 시스템입니다.

---

## 핵심 아키텍처 및 기능
- **네트워크 구역 격리:** External, DMZ, Management 등 구역별 Subnet/Security Group 설정
- **컨테이너 보안 스캐닝:** Trivy 기반의 Docker 이미지 및 인프라 취약점 실시간 감지
- **AI 기반 보안 분석:** 감지된 보안 위험 로그를 AI API로 전달하여 한글 요약 리포트 자동 생성
- **관제 대시보드 시각화:** 실시간 보안 이벤트 및 시스템 상태 모니터링

---

## 기술 스택 (Tech Stack)
- **Infra / Cloud:** AWS (VPC, EC2, IAM), Docker, Linux
- **Security & Analysis:** Trivy, Python, LLM API
- **Monitoring:** Grafana
