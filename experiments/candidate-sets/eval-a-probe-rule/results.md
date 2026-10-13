# 세트 eval-a-probe-rule 결과 (9건) — V1~V4 로컬 도구 실행 (--local-tools)

- 실행 환경: host=vm, python=3.11.15, trivy=0.74.0, terraform=1.10.6
- 실행 수: 9
- 후보 출처: {'rule_based': 7, '-': 2}  (mock/manual/예제는 LLM 출력이 아님)
- 최종 상태: {'REVIEW_REQUIRED': 4, 'INFO_INSUFFICIENT': 3, 'NO_FINDING': 2}
- 검토 수준/게이트: {'LIGHT_REVIEW': 4, 'None': 5}
- 검증 상태: {'COMPLETE': 4, 'NOT_LINKED': 5}
- 스캐너 통과(V1 PASS) ∧ 오라클 실패(V6 FAIL): 0건
- 오라클 판정 불가(V6 UNKNOWN): 0건

| 계층 | 판정 분포 |
|---|---|
| V1 | {'PASS': 4} |
| V2 | {'PASS': 4} |
| V3 | {'PASS': 4} |
| V4 | {'PASS': 4} |
| V5 | {'PASS': 4} |
| V6 | {'PASS': 4} |

- 오라클 유무 비교: V1 만으로 통과시켰을 건수 4 vs V1+V6 통과 4 (차이 = V6 가 추가로 막은 건수)

- 라벨 있는 실행 9건 중 기대대로 판정 9건
  - 기대=correct: 4/4
  - 기대=unsupported: 3/3
  - 기대=not_triggered: 2/2
- 등급 일치율 (사람이 기준표를 손으로 적용한 expected_risk vs 코드 판정): 4/4
- 후보 출처별 (E1 비교):

| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |
|---|---|---|---|
| rule_based | 9 | 4 | 9 |

- 자동 처리 시간(기록 시작~종료, 사람 승인 대기 제외): 4건 합계 107s, 평균 26.8s, 최대 27s — 도구 없이 돈 기록은 검증을 건너뛴 시간이므로 도구 있는 기록과 섞어 평균 내지 말 것

| run | 시나리오 | 출처 | 상태 | 검토수준 | 검증 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 | 소요(s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 20260922-033258-468022 | eval-a-probe-rule/00-baseline | rule_based | REVIEW_REQUIRED | LIGHT_REVIEW | COMPLETE | LOW | PASS | PASS | PASS | PASS | PASS | PASS | 26.0 |
| 20260922-033324-53a291 | eval-a-probe-rule/03-string-build | rule_based | INFO_INSUFFICIENT | None | NOT_LINKED | - | - | - | - | - | - | - | - |
| 20260922-033324-633128 | eval-a-probe-rule/04-dynamic | rule_based | INFO_INSUFFICIENT | None | NOT_LINKED | - | - | - | - | - | - | - | - |
| 20260922-033324-6b5c78 | eval-a-probe-rule/01-cidr-split | - | NO_FINDING | None | NOT_LINKED | - | - | - | - | - | - | - | - |
| 20260922-033324-b216f3 | eval-a-probe-rule/02-var-default | rule_based | INFO_INSUFFICIENT | None | NOT_LINKED | - | - | - | - | - | - | - | - |
| 20260922-033324-fd6f11 | eval-a-probe-rule/05-separate | rule_based | REVIEW_REQUIRED | LIGHT_REVIEW | COMPLETE | LOW | PASS | PASS | PASS | PASS | PASS | PASS | 27.0 |
| 20260922-033351-05973f | eval-a-probe-rule/06-prefix-list | - | NO_FINDING | None | NOT_LINKED | - | - | - | - | - | - | - | - |
| 20260922-033351-be512e | eval-a-probe-rule/07-ipv6-only | rule_based | REVIEW_REQUIRED | LIGHT_REVIEW | COMPLETE | LOW | PASS | PASS | PASS | PASS | PASS | PASS | 27.0 |
| 20260922-033418-a9e7ca | eval-a-probe-rule/08-second-sg | rule_based | REVIEW_REQUIRED | LIGHT_REVIEW | COMPLETE | LOW | PASS | PASS | PASS | PASS | PASS | PASS | 27.0 |
