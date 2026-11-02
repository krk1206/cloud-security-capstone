# 세트 eval-iam-rule 결과 (5건) — V1~V4 로컬 도구 실행 (--local-tools)

- 실행 환경: host=vm, python=3.11.15, trivy=0.74.0, terraform=1.10.6
- 실행 수: 5
- 후보 출처: {'rule_based': 5}  (mock/manual/예제는 LLM 출력이 아님)
- 최종 상태: {'REVIEW_REQUIRED': 2, 'INFO_INSUFFICIENT': 3}
- 검토 수준/게이트: {'FULL_REVIEW': 2, 'None': 3}
- 검증 상태: {'COMPLETE': 2, 'NOT_LINKED': 3}
- 스캐너 통과(V1 PASS) ∧ 오라클 실패(V6 FAIL): 0건
- 오라클 판정 불가(V6 UNKNOWN): 0건

| 계층 | 판정 분포 |
|---|---|
| V1 | {'PASS': 2} |
| V2 | {'PASS': 2} |
| V3 | {'PASS': 2} |
| V4 | {'PASS': 2} |
| V5 | {'PASS': 2} |
| V6 | {'PASS': 2} |

- 오라클 유무 비교: V1 만으로 통과시켰을 건수 2 vs V1+V6 통과 2 (차이 = V6 가 추가로 막은 건수)

- 라벨 있는 실행 5건 중 기대대로 판정 5건
  - 기대=correct: 2/2
  - 기대=unsupported: 3/3
- 후보 출처별 (E1 비교):

| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |
|---|---|---|---|
| rule_based | 5 | 2 | 5 |

- 자동 처리 시간(기록 시작~종료, 사람 승인 대기 제외): 2건 합계 54s, 평균 27.0s, 최대 27s — 도구 없이 돈 기록은 검증을 건너뛴 시간이므로 도구 있는 기록과 섞어 평균 내지 말 것

| run | 시나리오 | 출처 | 상태 | 검토수준 | 검증 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 | 소요(s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 20260922-015833-622c6a | eval-iam-rule/00-literal-list | rule_based | REVIEW_REQUIRED | FULL_REVIEW | COMPLETE | MEDIUM | PASS | PASS | PASS | PASS | PASS | PASS | 27.0 |
| 20260922-015900-05e086 | eval-iam-rule/03-data-policy-document | rule_based | INFO_INSUFFICIENT | None | NOT_LINKED | - | - | - | - | - | - | - | - |
| 20260922-015900-2a57e4 | eval-iam-rule/02-two-statements | rule_based | INFO_INSUFFICIENT | None | NOT_LINKED | - | - | - | - | - | - | - | - |
| 20260922-015900-34fff3 | eval-iam-rule/01-var-actions | rule_based | INFO_INSUFFICIENT | None | NOT_LINKED | - | - | - | - | - | - | - | - |
| 20260922-015900-6c98cc | eval-iam-rule/04-string-action | rule_based | REVIEW_REQUIRED | FULL_REVIEW | COMPLETE | MEDIUM | PASS | PASS | PASS | PASS | PASS | PASS | 27.0 |
