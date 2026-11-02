# 예제 4건 집계 (후보는 전부 예제/mock; V1~V4 값은 예제 fixture, V5/V6 는 로컬 계산)

- 실행 수: 4
- 후보 출처: {'manual': 3, 'mock': 1}  (mock/manual/예제는 LLM 출력이 아님)
- 최종 상태: {'REVIEW_REQUIRED': 2, 'VALIDATION_FAILED': 2}
- 검토 수준/게이트: {'LIGHT_REVIEW': 1, 'BLOCKED': 2, 'PENDING': 1}
- 검증 상태: {'COMPLETE': 1, 'FAILED': 2, 'PENDING': 1}
- 스캐너 통과(V1 PASS) ∧ 오라클 실패(V6 FAIL): 1건
- 오라클 판정 불가(V6 UNKNOWN): 0건

| 계층 | 판정 분포 |
|---|---|
| V1 | {'PASS': 2, 'FAIL': 1, 'NOT_RUN': 1} |
| V2 | {'PASS': 2, 'NOT_RUN': 2} |
| V3 | {'PASS': 3, 'NOT_RUN': 1} |
| V4 | {'PASS': 2, 'NOT_RUN': 2} |
| V5 | {'PASS': 2, 'NOT_RUN': 2} |
| V6 | {'PASS': 1, 'NOT_RUN': 2, 'FAIL': 1} |

| run | 시나리오 | 출처 | 상태 | 검토수준 | 검증 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 20260915-063845-106eac | ex02-case00-fixed | manual | REVIEW_REQUIRED | LIGHT_REVIEW | COMPLETE | LOW | PASS | PASS | PASS | PASS | PASS | PASS |
| 20260915-063845-1d04dc | ex04-v1-fail | mock | VALIDATION_FAILED | BLOCKED | FAILED | LOW | FAIL | NOT_RUN | PASS | NOT_RUN | NOT_RUN | NOT_RUN |
| 20260915-063845-251317 | ex01-manual-pending | manual | REVIEW_REQUIRED | PENDING | PENDING | LOW | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN |
| 20260915-063845-a3ab97 | ex03-case00-cidr-split | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | PASS | PASS | PASS | PASS | PASS | FAIL |
