# [A안] AWS/도커 기반 구역(Zone) 분리 및 AI 연동 통합 보안 관제 시스템

## 1. 프로젝트 개요
- **핵심 컨셉:** 클라우드 데이터센터 네트워크를 구역별(ext, dmz, mgmt)로 격리 구축하고, 발생한 보안 취약점 로그를 AI(LLM)가 분석해 실시간 대시보드에 시각화하는 시스템.
- **주요 기능:**
  - AWS VPC 및 Docker Network 기반 구역 격리
  - Trivy 보안 스캐너 기반 실시간 취약점/오픈포트 탐지
  - AI API 연동 한글 보안 위협 요약 리포트 자동 생성
  - Grafana/Streamlit 통합 관제 대시보드 시각화
- **기술 스택:** AWS, Docker, Python, Trivy, LLM API, Grafana
