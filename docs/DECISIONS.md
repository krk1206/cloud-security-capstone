# 결정 기록 (누가·언제·무엇을·왜)

실험 결과를 보고 기준을 바꾸지 않기 위해, 실행 전에 정한 것을 여기에 남긴다. 바꾸면 새 항목을 추가하고 이전 항목은 지우지 않는다.

| ID | 날짜 | 결정 | 근거 / 비고 | 결정자 |
|---|---|---|---|---|
| D-1 | 2026-09-15 | 제목: **LLM이 생성한 AWS IaC 보안 수정의 실효성 검증 시스템 구현** (영문: Implementation of an Effectiveness Verification System for LLM-Generated AWS IaC Security Fixes) | 지도교수 지시(하는 일이 드러나고 동사로 끝날 것) + 팀 의견(짧게, '파이프라인' 빼고, 핵심은 검증). 대안 "…실효성 검증 및 위험도 기반 승인 구현"(38자) 은 보류. 이전 긴 제목은 README 주석에 이력으로 남김 | B (팀 확인 필요) |
| D-2 | 2026-09-15 | 평가용 승인 출처 = `10.0.0.0/8` (SSH 22). RDP 3389 는 승인 출처 없음(규칙이 남아 있으면 안 됨). 필수 접근 = 10.0.0.0/8 → 22 | 승인 출처가 없으면 "규칙 삭제" 패치가 만점으로 통과해 V6 가 Trivy 재탕이 된다. 값 자체는 실제 조직 IP 일 필요가 없고 **실행 전에 고정**되는 것이 중요. 배포 후 접속 검증(V8) 때만 실제 공인 IP /32 가 필요 → 그때 `sg-baseline.sandbox.json` 별도 | B (위임받아 확정) |
| D-3 | 2026-09-15 | 개발용 세트(`example-dev`, `a-probe-dev`) 숫자는 발표에 쓰지 않는다. 평가용 세트는 `eval-*` 이름으로 manifest·expected 를 먼저 고정하고 돌린다. 실행 결과는 `results-history/` 에 환경별로 누적한다 | 결과 보고 기준 바꾸기 금지 (docs/EXPERIMENT_GUIDE.md 2절) | B |
| D-4 | 2026-09-15 | `expected` 라벨 정정은 manifest 의 `expected_history` 에 이유와 함께 남긴다 (첫 사례: a-probe-dev 07-ipv6-only unsupported→correct) | 라벨을 조용히 바꾸지 않기 위해 | B |

## 아직 안 정한 것

- 위험도 기준표 고정 (`docs/RISK_RUBRIC_DRAFT.md` 4절) — 평가용 LLM 후보 세트 돌리기 전에
- Claude Code 후보 프롬프트 고정본 승인 (`experiments/candidate-sets/eval-claude-code/prompt.md` 초안) 과 케이스당 반복 횟수
- V8 체크 정의와 sandbox 용 intent (실제 공인 IP)
