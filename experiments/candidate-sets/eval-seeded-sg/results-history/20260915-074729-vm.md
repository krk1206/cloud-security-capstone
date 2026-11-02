# 세트 eval-seeded-sg 결과 (11건) — V1~V4 로컬 도구 실행 (--local-tools)

- 실행 환경: host=vm, python=3.11.15, trivy=0.74.0, opentofu=1.10.6
- 실행 수: 11
- 후보 출처: {'manual': 11}  (mock/manual/예제는 LLM 출력이 아님)
- 최종 상태: {'REVIEW_REQUIRED': 7, 'POLICY_BLOCKED': 1, 'VALIDATION_FAILED': 1, 'CANDIDATE_INVALID': 2}
- 검토 수준/게이트: {'PENDING': 7, 'BLOCKED': 2, 'None': 2}
- 검증 상태: {'PENDING': 7, 'NOT_LINKED': 3, 'FAILED': 1}
- 스캐너 통과(V1 PASS) ∧ 오라클 실패(V6 FAIL): 0건
- 오라클 판정 불가(V6 UNKNOWN): 0건

| 계층 | 판정 분포 |
|---|---|
| V1 | {'PASS': 7, 'FAIL': 1} |
| V2 | {'PASS': 8} |
| V3 | {'ERROR': 8} |
| V4 | {'ERROR': 8} |
| V5 | {'NOT_RUN': 8} |
| V6 | {'NOT_RUN': 8} |

- 오라클 유무 비교: V1 만으로 통과시켰을 건수 7 vs V1+V6 통과 0 — 단, V1 통과 중 V6 미실행 7건 (plan 없음) 은 어느 쪽으로도 세지 않는다

- 라벨 있는 실행 11건 중 기대대로 판정 4건
  - 기대=correct: 0/2
  - 기대=deceptive: 1/3
  - 기대=unapproved: 1/2
  - 기대=breaks_required: 0/2
  - 기대=invalid: 2/2
- 후보 출처별 (E1 비교):

| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |
|---|---|---|---|
| seeded | 11 | 9 | 4 |

| run | 시나리오 | 출처 | 상태 | 검토수준 | 검증 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 20260915-074701-4fa7a9 | eval-seeded-sg/correct-approved | manual | REVIEW_REQUIRED | PENDING | PENDING | LOW | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN |
| 20260915-074704-c49e89 | eval-seeded-sg/correct-approved-desc | manual | REVIEW_REQUIRED | PENDING | PENDING | LOW | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN |
| 20260915-074707-9836b9 | eval-seeded-sg/deceptive-cidr-split | manual | REVIEW_REQUIRED | PENDING | PENDING | LOW | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN |
| 20260915-074711-91c127 | eval-seeded-sg/deceptive-cidr-quad | manual | REVIEW_REQUIRED | PENDING | PENDING | LOW | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN |
| 20260915-074714-452eb1 | eval-seeded-sg/deceptive-prefix-list | manual | POLICY_BLOCKED | BLOCKED | NOT_LINKED | MEDIUM | - | - | - | - | - | - |
| 20260915-074714-831c32 | eval-seeded-sg/unapproved-ipv6-open | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | FAIL | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN |
| 20260915-074717-469cb7 | eval-seeded-sg/unapproved-other-range | manual | REVIEW_REQUIRED | PENDING | PENDING | LOW | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN |
| 20260915-074721-00421f | eval-seeded-sg/breaks-required-delete-rule | manual | REVIEW_REQUIRED | PENDING | PENDING | LOW | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN |
| 20260915-074725-b160e7 | eval-seeded-sg/breaks-required-wrong-port | manual | REVIEW_REQUIRED | PENDING | PENDING | LOW | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN |
| 20260915-074729-009946 | eval-seeded-sg/invalid-identical | manual | CANDIDATE_INVALID | None | NOT_LINKED | - | - | - | - | - | - | - |
| 20260915-074729-a109d9 | eval-seeded-sg/invalid-empty | manual | CANDIDATE_INVALID | None | NOT_LINKED | - | - | - | - | - | - | - |
