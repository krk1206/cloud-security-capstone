# 프로젝트가 끝났을 때 우리에게 남아야 하는 것 — 체크리스트 (2026-09-22)

지도교수 9/22: "프로젝트를 해도 우리에게 남는 게 있어야 한다. 최소한 AWS·Terraform 네트워크 구성 정도는 할 줄 알아야 한다."
아래는 "설명할 수 있고, 직접 만들 수 있다" 를 기준으로 한 체크리스트다. ☐ 를 ☑ 로 바꿀 때는 **증거 링크**(파일·커밋·캡처)를 옆에 적는다. AI 가 대신 만든 것은 증거가 안 된다.

## 1. 개인별

### A — AWS / Terraform / IaC
- ☐ 손으로 그린 샌드박스 네트워크 구성도 (VPC, public/private subnet, route table, IGW, SG, EC2, IAM role, S3) → `docs/ARCHITECTURE_AWS.md`
- ☐ 같은 구성을 Terraform 으로 직접 작성 (provider, variable, output, 모듈 1개) → `infrastructure/sandbox-net/`
- ☐ `terraform init/fmt/validate/plan` 을 돌리고 `plan -out` + `show -json` 의 `planned_values`/`resource_changes` 를 읽어 설명
- ☐ 세 가지 취약 설정(과다 개방 SG, IAM 과다 권한, Public S3)을 직접 만들고 직접 고친 3쌍 → `ground-truth/`
- ☐ `trivy config` 결과 원문(JSON)에서 룰 ID·심각도·원인 줄을 찾아 읽기
- ☐ 배포 후 `aws ec2 describe-security-groups` 로 실제 상태 확인, V7 1회 실측 기록
- ☐ 계정 안전장치(예산 알림, MFA, 작업용 IAM 사용자) 설정 증거

### B — AI / Oracle / 위험도
- ☐ `docs/walkthroughs/B.md`: SG 오라클(CIDR 합집합·prefix list·ENI 합산)과 IAM 오라클(Action×Resource 포함 관계·역할 합산·UNKNOWN 규칙)을 자기 말로 + 예제 손 추적
- ☐ IAM 정책 평가 논리를 설명 (Allow/Deny/NotAction/Condition 이 왜 Tier 1 밖인가)
- ☐ 위험도 기준표 v2 의 각 항목을 "왜 이 점수인가" 로 설명, 게이트(검증→위험도→검토 수준) 흐름 설명
- ☐ LLM 을 신뢰하지 않는 구조(권한 분리·정책 검증·근거 기록)를 코드 위치로 짚어 설명
- ☐ Claude Code 후보 36개 수집(고정 프롬프트, 새 세션, 라벨은 실행 전) 과 결과 표
- ☐ 교차검증 1회차 5개 항목 재현·서명

### C — CI / Validator / 평가
- ☐ GitHub Actions 첫 실행 기록(unit test → scan → artifact) 과 워크플로 각 단계 설명
- ☐ 직접 작성한 미니 검증기 `student/v1v2_compare.py` (Trivy JSON 전/후 비교) 와 저장소 결과 대조
- ☐ plan JSON diff(V5) 가 무엇을 잡고 무엇을 못 잡는지 설명
- ☐ `docs/EVALUATION_PLAN.md`: 지표 정의·표본·검토 수준별 calibration 표, 결과 CSV
- ☐ 실제 PR 1건 생성(`iacpatch pr --review`)과 브랜치 보호·리뷰 흐름 설명
- ☐ V8 체크 정의(승인 밖 관측 지점 포함) 와 1회 실측

### 공통
- ☐ Git 브랜치/PR/리뷰 흐름을 팀 안에서 실제로 돌림 (서로 코드 리뷰 1회 이상)
- ☐ Trivy 동작 원리: 내장 Rego 체크 번들, `--skip-check-update`, deprecated 체크(AVD-AWS-0057)가 있다는 것, AVDID/ID 표기, `--include-non-failures`
- ☐ 다른 파트의 최소 동작 원리를 설명 (A→B→C 입출력 명세 `docs/IO_SPEC_A_B_C.md`)

## 2. 팀 산출물 (요구서 14절의 18개 ↔ 현재)

| 산출물 | 현재 | 남은 것 |
|---|---|---|
| 1 직접 그린 AWS 구성도 | 없음 | A, 이번 주 |
| 2 Terraform 테스트 인프라 | `infrastructure/sg-baseline` (SG 만) | A: `sandbox-net/` 전체 |
| 3 취약 Terraform 데이터셋 | A 의 우회 9종, IAM probe 5, seeded 24(AI 작성) | 사람이 만든 `ground-truth/` 3쌍 |
| 4 정답(Safe) Terraform | seeded correct 3 (AI 작성) | `ground-truth/*/expected_safe` |
| 5 Trivy 스캔 파이프라인 | 됨 (로컬·CI 파일) | Actions 첫 실행 |
| 6 AI 패치 생성기 | 규칙 기반 + Claude Code 수동 흐름 | 후보 36개 |
| 7 Terraform Validator (V3~V5) | 됨·실측 | — |
| 8 Security Validator (V1/V2/V6) | 됨·실측 | S3 |
| 9 Confidence/Risk Gate | 됨 (v2 확정안) | 팀 OK, calibration 표 |
| 10 GitHub Actions 파이프라인 | 파일 3개 | 실행 0회 → 실행 |
| 11 평가 결과 CSV/JSON | results.md/labels.json/results-history | CSV 내보내기 (C) |
| 12 Before/After 비교 자료 | review.md 마다 diff·계층표 | 발표용 정리 |
| 13 기술 문서 | docs/ 다수 | walkthrough 3편 |
| 14 데모 스크립트 | 없음 | 11월 |
| 15 포트폴리오 저장소 | 있음 (비공개) | README 정리 |
| 16 배운 기술 목록 | 이 문서 | ☑ 채우기 |
| 17 설계 결정 ADR | `docs/DECISIONS.md` D-1~D-9 | 계속 |
| 18 테스트 결과·실패 사례 | results-history, CROSS_VERIFICATION(false PASS 7종) | LLM 실패 사례 |
