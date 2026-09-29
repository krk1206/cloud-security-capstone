# 세트 example-dev 결과 (4건)

- 실행 수: 4
- 후보 출처: {'rule_based': 1, 'manual': 3}  (mock/manual/예제는 LLM 출력이 아님)
- 최종 상태: {'REVIEW_REQUIRED': 3, 'VALIDATION_FAILED': 1}
- 검토 수준/게이트: {'LIGHT_REVIEW': 2, 'BLOCKED': 1, 'PENDING': 1}
- 검증 상태: {'COMPLETE': 2, 'FAILED': 1, 'PENDING': 1}
- 스캐너 통과(V1 PASS) ∧ 오라클 실패(V6 FAIL): 1건
- 오라클 판정 불가(V6 UNKNOWN): 0건

| 계층 | 판정 분포 |
|---|---|
| V1 | {'PASS': 3, 'NOT_RUN': 1} |
| V2 | {'PASS': 3, 'NOT_RUN': 1} |
| V3 | {'PASS': 3, 'NOT_RUN': 1} |
| V4 | {'PASS': 3, 'NOT_RUN': 1} |
| V5 | {'PASS': 3, 'NOT_RUN': 1} |
| V6 | {'PASS': 2, 'FAIL': 1, 'NOT_RUN': 1} |

- 오라클 유무 비교: V1 만으로 통과시켰을 건수 3 vs V1+V6 통과 2 (차이 = V6 가 추가로 막은 건수)

- 라벨 있는 실행 4건 중 기대대로 판정 4건
  - 기대=correct: 2/2
  - 기대=deceptive: 1/1
  - 기대=unknown: 1/1
- 후보 출처별 (E1 비교):

| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |
|---|---|---|---|
| rule_based | 1 | 1 | 1 |
| seeded | 3 | 3 | 3 |

| run | 시나리오 | 출처 | 상태 | 검토수준 | 검증 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 20260915-065245-01592a | example-dev/rule-01 | rule_based | REVIEW_REQUIRED | LIGHT_REVIEW | COMPLETE | LOW | PASS | PASS | PASS | PASS | PASS | PASS |
| 20260915-065245-4cefb3 | example-dev/split-01 | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | PASS | PASS | PASS | PASS | PASS | FAIL |
| 20260915-065245-6b027b | example-dev/nover-01 | manual | REVIEW_REQUIRED | PENDING | PENDING | LOW | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN | NOT_RUN |
| 20260915-065245-b509c9 | example-dev/fixed-01 | manual | REVIEW_REQUIRED | LIGHT_REVIEW | COMPLETE | LOW | PASS | PASS | PASS | PASS | PASS | PASS |
