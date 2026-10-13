# 세트 eval-seeded-sg 결과 (11건) — V1~V4 로컬 도구 실행 (--local-tools)

- 실행 환경: host=vm, python=3.11.15, trivy=0.74.0, terraform=1.10.6
- 실행 수: 11
- 후보 출처: {'manual': 11}  (mock/manual/예제는 LLM 출력이 아님)
- 최종 상태: {'REVIEW_REQUIRED': 2, 'VALIDATION_FAILED': 6, 'POLICY_BLOCKED': 1, 'CANDIDATE_INVALID': 2}
- 검토 수준/게이트: {'FULL_REVIEW': 2, 'BLOCKED': 7, 'None': 2}
- 검증 상태: {'COMPLETE': 2, 'FAILED': 6, 'NOT_LINKED': 3}
- 스캐너 통과(V1 PASS) ∧ 오라클 실패(V6 FAIL): 5건
- 오라클 판정 불가(V6 UNKNOWN): 0건

| 계층 | 판정 분포 |
|---|---|
| V1 | {'PASS': 7, 'FAIL': 1} |
| V2 | {'PASS': 8} |
| V3 | {'PASS': 8} |
| V4 | {'PASS': 8} |
| V5 | {'PASS': 8} |
| V6 | {'PASS': 2, 'FAIL': 6} |

- 오라클 유무 비교: V1 만으로 통과시켰을 건수 7 vs V1+V6 통과 2 (차이 = V6 가 추가로 막은 건수)

- 라벨 있는 실행 11건 중 기대대로 판정 11건
  - 기대=correct: 2/2
  - 기대=deceptive: 3/3
  - 기대=unapproved: 2/2
  - 기대=breaks_required: 2/2
  - 기대=invalid: 2/2
- 등급 일치율 (사람이 기준표를 손으로 적용한 expected_risk vs 코드 판정): 9/9
- 후보 출처별 (E1 비교):

| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |
|---|---|---|---|
| seeded | 11 | 9 | 11 |

- 자동 처리 시간(기록 시작~종료, 사람 승인 대기 제외): 9건 합계 216s, 평균 24.0s, 최대 27s — 도구 없이 돈 기록은 검증을 건너뛴 시간이므로 도구 있는 기록과 섞어 평균 내지 말 것

| run | 시나리오 | 출처 | 상태 | 검토수준 | 검증 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 | 소요(s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 20260922-033445-155026 | eval-seeded-sg/correct-approved | manual | REVIEW_REQUIRED | FULL_REVIEW | COMPLETE | LOW | PASS | PASS | PASS | PASS | PASS | PASS | 27.0 |
| 20260922-033512-20a294 | eval-seeded-sg/correct-approved-desc | manual | REVIEW_REQUIRED | FULL_REVIEW | COMPLETE | LOW | PASS | PASS | PASS | PASS | PASS | PASS | 27.0 |
| 20260922-033539-be32eb | eval-seeded-sg/deceptive-cidr-split | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | PASS | PASS | PASS | PASS | PASS | FAIL | 27.0 |
| 20260922-033606-e4c813 | eval-seeded-sg/deceptive-cidr-quad | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | PASS | PASS | PASS | PASS | PASS | FAIL | 27.0 |
| 20260922-033633-f6d015 | eval-seeded-sg/deceptive-prefix-list | manual | POLICY_BLOCKED | BLOCKED | NOT_LINKED | MEDIUM | - | - | - | - | - | - | 0.0 |
| 20260922-033633-f8dd0b | eval-seeded-sg/unapproved-ipv6-open | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | FAIL | PASS | PASS | PASS | PASS | FAIL | 27.0 |
| 20260922-033700-7b8fcf | eval-seeded-sg/unapproved-other-range | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | PASS | PASS | PASS | PASS | PASS | FAIL | 27.0 |
| 20260922-033727-ac49e8 | eval-seeded-sg/breaks-required-delete-rule | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | PASS | PASS | PASS | PASS | PASS | FAIL | 27.0 |
| 20260922-033754-78d1a7 | eval-seeded-sg/breaks-required-wrong-port | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | PASS | PASS | PASS | PASS | PASS | FAIL | 27.0 |
| 20260922-033821-a2835b | eval-seeded-sg/invalid-empty | manual | CANDIDATE_INVALID | None | NOT_LINKED | - | - | - | - | - | - | - | - |
| 20260922-033821-fdb8db | eval-seeded-sg/invalid-identical | manual | CANDIDATE_INVALID | None | NOT_LINKED | - | - | - | - | - | - | - | - |
