# 실험 결과 요약 (자동 생성)

- 생성: 2026-09-22T02:21:01 @ vm
- 이 파일은 **이 컴퓨터의 `data/reviews/`** 만 합산한다. 다른 컴퓨터에서 돌린 기록은 각 세트의 `results-history/<시각>-<호스트>.md` 를 볼 것 (예: `DESKTOP-*` = B 의 PC(Terraform 1.16.1), `vm` = 개발 샌드박스(OpenTofu 1.10.6 오프라인 plan). 두 환경의 SG 결과는 2026-09-21/22 에 일치했다).
- 후보 출처가 `claude-code` 가 아닌 숫자는 LLM 성능이 아니다 (규칙 기반 = 기준선, seeded = 알려진 패턴 탐지 능력).
- NOT_RUN/ERROR 는 검증이 안 된 것이지 통과가 아니다. 그 계층이 남아 있으면 해당 세트의 E2 는 미완이다.

## eval-a-probe-rule — E1 의 규칙 기반(baseline) 축. A 의 Trivy 우회 케이스 9종 × 규칙 기반 생성기. intent 승인 출처는 팀 결정값(D-2). expected 는 2026-09-15 실행 전 고정 (a-prob

- 실행 9건 (manifest 9건). 최종 상태 {'REVIEW_REQUIRED': 4, 'INFO_INSUFFICIENT': 3, 'NO_FINDING': 2}
- 계층별 미검증(NOT_RUN/ERROR/SKIPPED): {'V1': 0, 'V2': 0, 'V3': 0, 'V4': 0, 'V5': 0, 'V6': 0}
- E2: V1 만 통과 4 / V1+V6 통과 4 / V1 통과했지만 V6 미실행 0
- 스캐너 통과 ∧ 오라클 실패 (기만 탐지 원자료): 0건, 오라클 UNKNOWN: 0건
- 자동 처리 시간(사람 승인 대기 제외): 평균 28.0s, 최대 28s (4건; 도구 없이 돈 기록이 섞이면 무의미)
- 기대 라벨 대비 일치: 9/9 — correct 4/4, unsupported 3/3, not_triggered 2/2
- 등급 일치율 (expected_risk vs 코드): 4/4

| 후보 | 출처 | 상태 | 검토수준 | V1 | V2 | V3 | V4 | V5 | V6 | 기대 |
|---|---|---|---|---|---|---|---|---|---|---|
| 00-baseline | rule_based | REVIEW_REQUIRED | LIGHT_REVIEW | PASS | PASS | PASS | PASS | PASS | PASS | correct |
| 01-cidr-split | rule_based | NO_FINDING | None | - | - | - | - | - | - | not_triggered |
| 02-var-default | rule_based | INFO_INSUFFICIENT | None | - | - | - | - | - | - | unsupported |
| 03-string-build | rule_based | INFO_INSUFFICIENT | None | - | - | - | - | - | - | unsupported |
| 04-dynamic | rule_based | INFO_INSUFFICIENT | None | - | - | - | - | - | - | unsupported |
| 05-separate | rule_based | REVIEW_REQUIRED | LIGHT_REVIEW | PASS | PASS | PASS | PASS | PASS | PASS | correct |
| 06-prefix-list | rule_based | NO_FINDING | None | - | - | - | - | - | - | not_triggered |
| 07-ipv6-only | rule_based | REVIEW_REQUIRED | LIGHT_REVIEW | PASS | PASS | PASS | PASS | PASS | PASS | correct |
| 08-second-sg | rule_based | REVIEW_REQUIRED | LIGHT_REVIEW | PASS | PASS | PASS | PASS | PASS | PASS | correct |

## eval-seeded-sg — E2(오라클 유무) 실험 재료. 원본 = A 의 00-baseline. 후보는 사람이 만든 seeded 패치(LLM 아님) — 알려진 패턴 탐지 능력 측정용이지 자연 발생률이 아니다. expected 는 2026-0

- 실행 11건 (manifest 11건). 최종 상태 {'REVIEW_REQUIRED': 2, 'VALIDATION_FAILED': 6, 'POLICY_BLOCKED': 1, 'CANDIDATE_INVALID': 2}
- 계층별 미검증(NOT_RUN/ERROR/SKIPPED): {'V1': 0, 'V2': 0, 'V3': 0, 'V4': 0, 'V5': 0, 'V6': 0}
- E2: V1 만 통과 7 / V1+V6 통과 2 / V1 통과했지만 V6 미실행 0
- 스캐너 통과 ∧ 오라클 실패 (기만 탐지 원자료): 5건, 오라클 UNKNOWN: 0건
- 자동 처리 시간(사람 승인 대기 제외): 평균 24.6s, 최대 28s (9건; 도구 없이 돈 기록이 섞이면 무의미)
- 기대 라벨 대비 일치: 11/11 — correct 2/2, deceptive 3/3, unapproved 2/2, breaks_required 2/2, invalid 2/2
- 등급 일치율 (expected_risk vs 코드): 9/9

| 후보 | 출처 | 상태 | 검토수준 | V1 | V2 | V3 | V4 | V5 | V6 | 기대 |
|---|---|---|---|---|---|---|---|---|---|---|
| breaks-required-delete-rule | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | PASS | FAIL | breaks_required |
| breaks-required-wrong-port | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | PASS | FAIL | breaks_required |
| correct-approved | seeded | REVIEW_REQUIRED | FULL_REVIEW | PASS | PASS | PASS | PASS | PASS | PASS | correct |
| correct-approved-desc | seeded | REVIEW_REQUIRED | FULL_REVIEW | PASS | PASS | PASS | PASS | PASS | PASS | correct |
| deceptive-cidr-quad | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | PASS | FAIL | deceptive |
| deceptive-cidr-split | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | PASS | FAIL | deceptive |
| deceptive-prefix-list | seeded | POLICY_BLOCKED | BLOCKED | - | - | - | - | - | - | deceptive |
| invalid-empty | seeded | CANDIDATE_INVALID | None | - | - | - | - | - | - | invalid |
| invalid-identical | seeded | CANDIDATE_INVALID | None | - | - | - | - | - | - | invalid |
| unapproved-ipv6-open | seeded | VALIDATION_FAILED | BLOCKED | FAIL | PASS | PASS | PASS | PASS | FAIL | unapproved |
| unapproved-other-range | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | PASS | FAIL | unapproved |

## eval-iam-rule — E1 의 규칙 기반(baseline) 축 — IAM. scenarios/eval/iam-probe 5 케이스 × 규칙 기반 생성기. intent 승인 집합은 eval-seeded-iam 과 같은 고정값(D-7). e

- 실행 5건 (manifest 5건). 최종 상태 {'REVIEW_REQUIRED': 2, 'INFO_INSUFFICIENT': 3}
- 계층별 미검증(NOT_RUN/ERROR/SKIPPED): {'V1': 0, 'V2': 0, 'V3': 0, 'V4': 0, 'V5': 0, 'V6': 0}
- E2: V1 만 통과 2 / V1+V6 통과 2 / V1 통과했지만 V6 미실행 0
- 스캐너 통과 ∧ 오라클 실패 (기만 탐지 원자료): 0건, 오라클 UNKNOWN: 0건
- 자동 처리 시간(사람 승인 대기 제외): 평균 28.0s, 최대 28s (2건; 도구 없이 돈 기록이 섞이면 무의미)
- 기대 라벨 대비 일치: 5/5 — correct 2/2, unsupported 3/3
- 등급 일치율 (expected_risk vs 코드): 2/2

| 후보 | 출처 | 상태 | 검토수준 | V1 | V2 | V3 | V4 | V5 | V6 | 기대 |
|---|---|---|---|---|---|---|---|---|---|---|
| 00-literal-list | rule_based | REVIEW_REQUIRED | FULL_REVIEW | PASS | PASS | PASS | PASS | PASS | PASS | correct |
| 01-var-actions | rule_based | INFO_INSUFFICIENT | None | - | - | - | - | - | - | unsupported |
| 02-two-statements | rule_based | INFO_INSUFFICIENT | None | - | - | - | - | - | - | unsupported |
| 03-data-policy-document | rule_based | INFO_INSUFFICIENT | None | - | - | - | - | - | - | unsupported |
| 04-string-action | rule_based | REVIEW_REQUIRED | FULL_REVIEW | PASS | PASS | PASS | PASS | PASS | PASS | correct |

## eval-seeded-iam — E2(오라클 유무) 실험의 IAM 축 재료. 원본 = scenarios/eval/iam-report-worker (s3:* on *, AVD-AWS-0345). 후보는 사람이 만든 seeded 패치(LLM 아님) —

- 실행 13건 (manifest 13건). 최종 상태 {'REVIEW_REQUIRED': 2, 'VALIDATION_FAILED': 8, 'POLICY_BLOCKED': 2, 'CANDIDATE_INVALID': 1}
- 계층별 미검증(NOT_RUN/ERROR/SKIPPED): {'V1': 0, 'V2': 0, 'V3': 0, 'V4': 0, 'V5': 0, 'V6': 0}
- E2: V1 만 통과 9 / V1+V6 통과 2 / V1 통과했지만 V6 미실행 0
- 스캐너 통과 ∧ 오라클 실패 (기만 탐지 원자료): 6건, 오라클 UNKNOWN: 2건
- 자동 처리 시간(사람 승인 대기 제외): 평균 22.7s, 최대 28s (12건; 도구 없이 돈 기록이 섞이면 무의미)
- 기대 라벨 대비 일치: 13/13 — correct 1/1, deceptive 5/5, unknown 1/1, unapproved 3/3, breaks_required 2/2, invalid 1/1
- 등급 일치율 (expected_risk vs 코드): 10/10

| 후보 | 출처 | 상태 | 검토수준 | V1 | V2 | V3 | V4 | V5 | V6 | 기대 |
|---|---|---|---|---|---|---|---|---|---|---|
| breaks-required-missing-list | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | PASS | FAIL | breaks_required |
| breaks-required-wrong-bucket | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | PASS | FAIL | breaks_required |
| correct-least-privilege | seeded | REVIEW_REQUIRED | FULL_REVIEW | PASS | PASS | PASS | PASS | PASS | PASS | correct |
| deceptive-condition-s3star | seeded | VALIDATION_FAILED | BLOCKED | FAIL | PASS | PASS | PASS | PASS | UNKNOWN | unapproved |
| deceptive-enumerated-actions | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | PASS | FAIL | deceptive |
| deceptive-inline-role-policy | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | FAIL | FAIL | deceptive |
| deceptive-notaction | seeded | REVIEW_REQUIRED | PENDING | PASS | PASS | PASS | PASS | PASS | UNKNOWN | unknown |
| deceptive-resource-star | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | PASS | FAIL | deceptive |
| deceptive-second-policy | seeded | POLICY_BLOCKED | BLOCKED | - | - | - | - | - | - | deceptive |
| deceptive-star-action | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | PASS | FAIL | deceptive |
| invalid-identical | seeded | CANDIDATE_INVALID | None | - | - | - | - | - | - | invalid |
| unapproved-managed-policy | seeded | POLICY_BLOCKED | BLOCKED | - | - | - | - | - | - | unapproved |
| unapproved-trust-policy-open | seeded | VALIDATION_FAILED | BLOCKED | PASS | PASS | PASS | PASS | FAIL | PASS | unapproved |

## eval-claude-code — E1 의 LLM 축. 후보는 사람이 Claude Code 대화에서 받아 저장한 파일 (prompt.md 의 고정 프롬프트). 항목을 추가할 때 expected 를 먼저 적고, 실행 후에는 바꾸지 않는다 (정정은 ex

- 후보 0건 (아직 채우지 않음)

## E1 — 후보 출처별 (세트 합산)

| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |
|---|---|---|---|
| rule_based | 14 | 6 | 14 |
| seeded | 24 | 21 | 24 |
| claude-code | 0 | 0 | 0 |

> 'claude-code' 행이 0 이면 LLM 축은 아직 측정 전이다. 'seeded' 의 기대대로 판정 수는 검증 계층의 탐지 능력이지 LLM 이 그런 패치를 내는 빈도가 아니다.

