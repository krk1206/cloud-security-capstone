# [D안] 쿠버네티스/도커 기반 AI 모델 자동 배포 및 컨테이너 보안 경량화 플랫폼

## 1. 배경 및 필요성
- AI 서비스 도입이 활발해짐에 따라 AI 모델(HuggingFace, Ollama 등)을 클라우드/컨테이너 환경에 안전하게 배포하는 인프라 수요 급증.
- 거대한 AI 모델 컨테이너의 용량을 줄이고 불필요한 공격 표면(Attack Surface)을 제거하는 컨테이너 경량화/보안화 필수.

## 2. 시스템 아키텍처 및 핵심 기능
1. **AI 모델 원클릭 컨테이너화:**
   - 사용자가 지정한 오픈소스 AI 모델을 **Docker / Kubernetes** 상에 마이크로서비스 형태(API)로 자동 패키징 및 배포.
2. **보안 경량화 이미지 빌드:**
   - 멀티 스테이지 빌드(Multi-stage build) 및 경량 Base 이미지(Distroless/Alpine)를 적용하여 컨테이너 용량 최적화 및 불필요한 Shell/유틸리티 제거.
3. **자원 및 통신 보안 제어:**
   - Kubernetes ResourceQuota / LimitRange 설정을 통한 자원 독점 방지.
   - NetworkPolicy를 적용하여 컨테이너 간 불필요한 통신 차단.

## 3. 기대 효과
- 오케스트로(OKESTRO)의 핵심 사업인 **가상화/컨테이너(Docker/K8s) 및 Cloud Native 인프라** 기술에 완벽 대응.
- AI 서비스를 인프라 관점에서 안전하게 운용하는 차별화된 역량 강조.
