# 세트 arch-webapp-sg 결과 (7건) — V1~V4 로컬 도구 실행 (--local-tools)

- 실행 환경: host=vm, python=3.11.15, trivy=0.74.0, terraform=1.10.6
- 이번 실행: 새로 돌림 7건, 이전 기록 재사용 0건 (재사용 = 원본·후보·입력 스캔·intent·정책·코드·도구 버전이 전부 같은 기록. run 열이 원래 실행 시각. `--fresh` 로 강제 재실행)
- 실행 수: 7
- 후보 출처: {'rule_based': 1, 'manual': 6}  (mock/manual/예제는 LLM 출력이 아님)
- 최종 상태: {'REVIEW_REQUIRED': 2, 'VALIDATION_FAILED': 5}
- 검토 수준/게이트: {'LIGHT_REVIEW': 1, 'FULL_REVIEW': 1, 'BLOCKED': 5}
- 검증 상태: {'COMPLETE': 2, 'FAILED': 5}
- 스캐너 통과(V1 PASS) ∧ 오라클 실패(V6 FAIL): 5건
- 오라클 판정 불가(V6 UNKNOWN): 0건

| 계층 | 판정 분포 |
|---|---|
| V1 | {'PASS': 7} |
| V2 | {'PASS': 7} |
| V3 | {'PASS': 7} |
| V4 | {'PASS': 7} |
| V5 | {'PASS': 7} |
| V6 | {'PASS': 2, 'FAIL': 5} |

- 오라클 유무 비교: V1 만으로 통과시켰을 건수 7 vs V1+V6 통과 2 (차이 = V6 가 추가로 막은 건수)

- 라벨 있는 실행 7건 중 기대대로 판정 7건
  - 기대=correct: 2/2
  - 기대=deceptive: 1/1
  - 기대=unapproved: 2/2
  - 기대=breaks_required: 2/2
- 등급 일치율 (기준표를 따로 읽고 적은 expected_risk vs 코드 판정 — 작성 주체는 manifest 참조): 7/7
- 후보 출처별 (E1 비교):

| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |
|---|---|---|---|
| rule_based | 1 | 1 | 1 |
| seeded | 6 | 6 | 6 |

- 자동 처리 시간(기록 시작~종료, 사람 승인 대기 제외): 7건 합계 67s, 평균 9.6s, 최대 16s — 도구 없이 돈 기록은 검증을 건너뛴 시간이므로 도구 있는 기록과 섞어 평균 내지 말 것

| run | 시나리오 | 출처 | 상태 | 검토수준 | 검증 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 | 소요(s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 20261004-031523-6de2ee | arch-webapp-sg/rule-based | rule_based | REVIEW_REQUIRED | LIGHT_REVIEW | COMPLETE | LOW | PASS | PASS | PASS | PASS | PASS | PASS | 16.0 |
| 20261004-031539-db1e6e | arch-webapp-sg/correct-approved | manual | REVIEW_REQUIRED | FULL_REVIEW | COMPLETE | LOW | PASS | PASS | PASS | PASS | PASS | PASS | 9.0 |
| 20261004-031548-fabcee | arch-webapp-sg/deceptive-cidr-split | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | PASS | PASS | PASS | PASS | PASS | FAIL | 8.0 |
| 20261004-031556-78a420 | arch-webapp-sg/unapproved-other-range | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | PASS | PASS | PASS | PASS | PASS | FAIL | 8.0 |
| 20261004-031604-9342d7 | arch-webapp-sg/breaks-required-delete-rule | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | PASS | PASS | PASS | PASS | PASS | FAIL | 9.0 |
| 20261004-031613-330236 | arch-webapp-sg/breaks-required-http-closed | manual | VALIDATION_FAILED | BLOCKED | FAILED | LOW | PASS | PASS | PASS | PASS | PASS | FAIL | 8.0 |
| 20261004-031621-3baac0 | arch-webapp-sg/unapproved-app-port-open | manual | VALIDATION_FAILED | BLOCKED | FAILED | MEDIUM | PASS | PASS | PASS | PASS | PASS | FAIL | 9.0 |
