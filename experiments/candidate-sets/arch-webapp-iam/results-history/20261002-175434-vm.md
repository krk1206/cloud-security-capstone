# 세트 arch-webapp-iam 결과 (6건) — V1~V4 로컬 도구 실행 (--local-tools)

- 실행 환경: host=vm, python=3.11.15, trivy=0.74.0, terraform=1.10.6
- 이번 실행: 새로 돌림 6건, 이전 기록 재사용 0건 (재사용 = 원본·후보·입력 스캔·intent·정책·코드·도구 버전이 전부 같은 기록. run 열이 원래 실행 시각. `--fresh` 로 강제 재실행)
- 실행 수: 6
- 후보 출처: {'manual': 5, 'rule_based': 1}  (mock/manual/예제는 LLM 출력이 아님)
- 최종 상태: {'REVIEW_REQUIRED': 1, 'INFO_INSUFFICIENT': 1, 'VALIDATION_FAILED': 4}
- 검토 수준/게이트: {'FULL_REVIEW': 1, 'None': 1, 'BLOCKED': 4}
- 검증 상태: {'COMPLETE': 1, 'NOT_LINKED': 1, 'FAILED': 4}
- 스캐너 통과(V1 PASS) ∧ 오라클 실패(V6 FAIL): 4건
- 오라클 판정 불가(V6 UNKNOWN): 0건

| 계층 | 판정 분포 |
|---|---|
| V1 | {'PASS': 5} |
| V2 | {'PASS': 5} |
| V3 | {'PASS': 5} |
| V4 | {'PASS': 5} |
| V5 | {'PASS': 4, 'FAIL': 1} |
| V6 | {'PASS': 1, 'FAIL': 4} |

- 오라클 유무 비교: V1 만으로 통과시켰을 건수 5 vs V1+V6 통과 1 (차이 = V6 가 추가로 막은 건수)

- 라벨 있는 실행 6건 중 기대대로 판정 5건
  - 기대=correct: 1/2
  - 기대=deceptive: 2/2
  - 기대=breaks_required: 1/1
  - 기대=unapproved: 1/1
- 등급 일치율 (기준표를 따로 읽고 적은 expected_risk vs 코드 판정 — 작성 주체는 manifest 참조): 5/6 — 불일치: arch-webapp-iam/rule-based: 기대 MEDIUM, 실제 판정 없음
- 후보 출처별 (E1 비교):

| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |
|---|---|---|---|
| seeded | 5 | 5 | 5 |
| rule_based | 1 | 0 | 0 |

- 자동 처리 시간(기록 시작~종료, 사람 승인 대기 제외): 5건 합계 105s, 평균 21.0s, 최대 21s — 도구 없이 돈 기록은 검증을 건너뛴 시간이므로 도구 있는 기록과 섞어 평균 내지 말 것

| run | 시나리오 | 출처 | 상태 | 검토수준 | 검증 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 | 소요(s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 20261002-175249-8090a5 | arch-webapp-iam/correct-least-privilege | manual | REVIEW_REQUIRED | FULL_REVIEW | COMPLETE | MEDIUM | PASS | PASS | PASS | PASS | PASS | PASS | 21.0 |
| 20261002-175249-eef954 | arch-webapp-iam/rule-based | rule_based | INFO_INSUFFICIENT | None | NOT_LINKED | - | - | - | - | - | - | - | - |
| 20261002-175310-752e53 | arch-webapp-iam/deceptive-enumerated-actions | manual | VALIDATION_FAILED | BLOCKED | FAILED | MEDIUM | PASS | PASS | PASS | PASS | PASS | FAIL | 21.0 |
| 20261002-175331-358c57 | arch-webapp-iam/deceptive-resource-star | manual | VALIDATION_FAILED | BLOCKED | FAILED | MEDIUM | PASS | PASS | PASS | PASS | PASS | FAIL | 21.0 |
| 20261002-175352-e34d0b | arch-webapp-iam/breaks-required-wrong-bucket | manual | VALIDATION_FAILED | BLOCKED | FAILED | MEDIUM | PASS | PASS | PASS | PASS | PASS | FAIL | 21.0 |
| 20261002-175413-cbd0ae | arch-webapp-iam/unapproved-trust-policy-open | manual | VALIDATION_FAILED | BLOCKED | FAILED | HIGH | PASS | PASS | PASS | PASS | FAIL | FAIL | 21.0 |
