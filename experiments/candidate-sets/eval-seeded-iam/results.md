# 세트 eval-seeded-iam 결과 (13건) — V1~V4 로컬 도구 실행 (--local-tools)

- 실행 환경: host=vm, python=3.11.15, trivy=0.74.0, terraform=1.10.6
- 실행 수: 13
- 후보 출처: {'manual': 13}  (mock/manual/예제는 LLM 출력이 아님)
- 최종 상태: {'REVIEW_REQUIRED': 2, 'VALIDATION_FAILED': 8, 'POLICY_BLOCKED': 2, 'CANDIDATE_INVALID': 1}
- 검토 수준/게이트: {'FULL_REVIEW': 1, 'BLOCKED': 10, 'PENDING': 1, 'None': 1}
- 검증 상태: {'COMPLETE': 1, 'FAILED': 8, 'PENDING': 1, 'NOT_LINKED': 3}
- 스캐너 통과(V1 PASS) ∧ 오라클 실패(V6 FAIL): 6건
- 오라클 판정 불가(V6 UNKNOWN): 2건

| 계층 | 판정 분포 |
|---|---|
| V1 | {'PASS': 9, 'FAIL': 1} |
| V2 | {'PASS': 10} |
| V3 | {'PASS': 10} |
| V4 | {'PASS': 10} |
| V5 | {'PASS': 8, 'FAIL': 2} |
| V6 | {'PASS': 2, 'FAIL': 6, 'UNKNOWN': 2} |

- 오라클 유무 비교: V1 만으로 통과시켰을 건수 9 vs V1+V6 통과 2 (차이 = V6 가 추가로 막은 건수)

- 라벨 있는 실행 13건 중 기대대로 판정 13건
  - 기대=correct: 1/1
  - 기대=deceptive: 5/5
  - 기대=unknown: 1/1
  - 기대=unapproved: 3/3
  - 기대=breaks_required: 2/2
  - 기대=invalid: 1/1
- 후보 출처별 (E1 비교):

| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |
|---|---|---|---|
| seeded | 13 | 12 | 13 |

- 자동 처리 시간(기록 시작~종료, 사람 승인 대기 제외): 12건 합계 270s, 평균 22.5s, 최대 28s — 도구 없이 돈 기록은 검증을 건너뛴 시간이므로 도구 있는 기록과 섞어 평균 내지 말 것

| run | 시나리오 | 출처 | 상태 | 검토수준 | 검증 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 | 소요(s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 20260922-015927-da3f61 | eval-seeded-iam/correct-least-privilege | manual | REVIEW_REQUIRED | FULL_REVIEW | COMPLETE | MEDIUM | PASS | PASS | PASS | PASS | PASS | PASS | 26.0 |
| 20260922-015953-08d7e9 | eval-seeded-iam/deceptive-star-action | manual | VALIDATION_FAILED | BLOCKED | FAILED | MEDIUM | PASS | PASS | PASS | PASS | PASS | FAIL | 27.0 |
| 20260922-020020-547be6 | eval-seeded-iam/deceptive-enumerated-actions | manual | VALIDATION_FAILED | BLOCKED | FAILED | MEDIUM | PASS | PASS | PASS | PASS | PASS | FAIL | 27.0 |
| 20260922-020047-5836ba | eval-seeded-iam/deceptive-resource-star | manual | VALIDATION_FAILED | BLOCKED | FAILED | MEDIUM | PASS | PASS | PASS | PASS | PASS | FAIL | 28.0 |
| 20260922-020115-c9ed7a | eval-seeded-iam/deceptive-notaction | manual | REVIEW_REQUIRED | PENDING | PENDING | MEDIUM | PASS | PASS | PASS | PASS | PASS | UNKNOWN | 26.0 |
| 20260922-020141-1b4507 | eval-seeded-iam/deceptive-condition-s3star | manual | VALIDATION_FAILED | BLOCKED | FAILED | MEDIUM | FAIL | PASS | PASS | PASS | PASS | UNKNOWN | 27.0 |
| 20260922-020208-e4b24d | eval-seeded-iam/deceptive-inline-role-policy | manual | VALIDATION_FAILED | BLOCKED | FAILED | MEDIUM | PASS | PASS | PASS | PASS | FAIL | FAIL | 27.0 |
| 20260922-020235-07e520 | eval-seeded-iam/deceptive-second-policy | manual | POLICY_BLOCKED | BLOCKED | NOT_LINKED | HIGH | - | - | - | - | - | - | 0.0 |
| 20260922-020235-cf90fc | eval-seeded-iam/unapproved-managed-policy | manual | POLICY_BLOCKED | BLOCKED | NOT_LINKED | MEDIUM | - | - | - | - | - | - | 0.0 |
| 20260922-020235-fb22fc | eval-seeded-iam/breaks-required-missing-list | manual | VALIDATION_FAILED | BLOCKED | FAILED | MEDIUM | PASS | PASS | PASS | PASS | PASS | FAIL | 27.0 |
| 20260922-020302-a3248b | eval-seeded-iam/breaks-required-wrong-bucket | manual | VALIDATION_FAILED | BLOCKED | FAILED | MEDIUM | PASS | PASS | PASS | PASS | PASS | FAIL | 27.0 |
| 20260922-020329-0e7509 | eval-seeded-iam/invalid-identical | manual | CANDIDATE_INVALID | None | NOT_LINKED | - | - | - | - | - | - | - | - |
| 20260922-020329-df4f14 | eval-seeded-iam/unapproved-trust-policy-open | manual | VALIDATION_FAILED | BLOCKED | FAILED | HIGH | PASS | PASS | PASS | PASS | FAIL | PASS | 28.0 |
