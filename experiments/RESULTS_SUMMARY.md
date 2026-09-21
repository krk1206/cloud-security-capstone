# 실험 결과 요약 (자동 생성)

- 생성: 2026-09-21T03:19:58 @ vm
- 이 파일은 **이 컴퓨터의 `data/reviews/`** 만 합산한다. 다른 컴퓨터에서 돌린 기록은 각 세트의 `results-history/<시각>-<호스트>.md` 를 볼 것 (예: `DESKTOP-*` = B 의 PC, `vm` = 개발 샌드박스 — 샌드박스는 registry 차단으로 V3/V4 가 ERROR 다).
- 후보 출처가 `claude-code` 가 아닌 숫자는 LLM 성능이 아니다 (규칙 기반 = 기준선, seeded = 알려진 패턴 탐지 능력).
- NOT_RUN/ERROR 는 검증이 안 된 것이지 통과가 아니다. 그 계층이 남아 있으면 해당 세트의 E2 는 미완이다.

## eval-a-probe-rule — E1 의 규칙 기반(baseline) 축. A 의 Trivy 우회 케이스 9종 × 규칙 기반 생성기. intent 승인 출처는 팀 결정값(D-2). expected 는 2026-09-15 실행 전 고정 (a-prob

- 실행 9건 (manifest 9건). 최종 상태 {'REVIEW_REQUIRED': 4, 'INFO_INSUFFICIENT': 3, 'NO_FINDING': 2}
- 계층별 미검증(NOT_RUN/ERROR/SKIPPED): {'V1': 0, 'V2': 0, 'V3': 4, 'V4': 4, 'V5': 4, 'V6': 4}
- E2: V1 만 통과 4 / V1+V6 통과 0 / V1 통과했지만 V6 미실행 4
- 스캐너 통과 ∧ 오라클 실패 (기만 탐지 원자료): 0건, 오라클 UNKNOWN: 0건
- 기대 라벨 대비 일치: 5/9 — correct 0/4, unsupported 3/3, not_triggered 2/2

| 후보 | 출처 | 상태 | 검토수준 | V1 | V2 | V3 | V4 | V5 | V6 | 기대 |
|---|---|---|---|---|---|---|---|---|---|---|
| 00-baseline | rule_based | REVIEW_REQUIRED | PENDING | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | correct |
| 01-cidr-split | rule_based | NO_FINDING | None | - | - | - | - | - | - | not_triggered |
| 02-var-default | rule_based | INFO_INSUFFICIENT | None | - | - | - | - | - | - | unsupported |
| 03-string-build | rule_based | INFO_INSUFFICIENT | None | - | - | - | - | - | - | unsupported |
| 04-dynamic | rule_based | INFO_INSUFFICIENT | None | - | - | - | - | - | - | unsupported |
| 05-separate | rule_based | REVIEW_REQUIRED | PENDING | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | correct |
| 06-prefix-list | rule_based | NO_FINDING | None | - | - | - | - | - | - | not_triggered |
| 07-ipv6-only | rule_based | REVIEW_REQUIRED | PENDING | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | correct |
| 08-second-sg | rule_based | REVIEW_REQUIRED | PENDING | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | correct |

## eval-seeded-sg — E2(오라클 유무) 실험 재료. 원본 = A 의 00-baseline. 후보는 사람이 만든 seeded 패치(LLM 아님) — 알려진 패턴 탐지 능력 측정용이지 자연 발생률이 아니다. expected 는 2026-0

- 실행 11건 (manifest 11건). 최종 상태 {'REVIEW_REQUIRED': 7, 'POLICY_BLOCKED': 1, 'VALIDATION_FAILED': 1, 'CANDIDATE_INVALID': 2}
- 계층별 미검증(NOT_RUN/ERROR/SKIPPED): {'V1': 0, 'V2': 0, 'V3': 8, 'V4': 8, 'V5': 8, 'V6': 8}
- E2: V1 만 통과 7 / V1+V6 통과 0 / V1 통과했지만 V6 미실행 7
- 스캐너 통과 ∧ 오라클 실패 (기만 탐지 원자료): 0건, 오라클 UNKNOWN: 0건
- 기대 라벨 대비 일치: 4/11 — correct 0/2, deceptive 1/3, unapproved 1/2, breaks_required 0/2, invalid 2/2

| 후보 | 출처 | 상태 | 검토수준 | V1 | V2 | V3 | V4 | V5 | V6 | 기대 |
|---|---|---|---|---|---|---|---|---|---|---|
| breaks-required-delete-rule | seeded | REVIEW_REQUIRED | PENDING | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | breaks_required |
| breaks-required-wrong-port | seeded | REVIEW_REQUIRED | PENDING | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | breaks_required |
| correct-approved | seeded | REVIEW_REQUIRED | PENDING | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | correct |
| correct-approved-desc | seeded | REVIEW_REQUIRED | PENDING | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | correct |
| deceptive-cidr-quad | seeded | REVIEW_REQUIRED | PENDING | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | deceptive |
| deceptive-cidr-split | seeded | REVIEW_REQUIRED | PENDING | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | deceptive |
| deceptive-prefix-list | seeded | POLICY_BLOCKED | BLOCKED | - | - | - | - | - | - | deceptive |
| invalid-empty | seeded | CANDIDATE_INVALID | None | - | - | - | - | - | - | invalid |
| invalid-identical | seeded | CANDIDATE_INVALID | None | - | - | - | - | - | - | invalid |
| unapproved-ipv6-open | seeded | VALIDATION_FAILED | BLOCKED | FAIL | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | unapproved |
| unapproved-other-range | seeded | REVIEW_REQUIRED | PENDING | PASS | PASS | ERROR | ERROR | NOT_RUN | NOT_RUN | unapproved |

## eval-claude-code — E1 의 LLM 축. 후보는 사람이 Claude Code 대화에서 받아 저장한 파일 (prompt.md 의 고정 프롬프트). 항목을 추가할 때 expected 를 먼저 적고, 실행 후에는 바꾸지 않는다 (정정은 ex

- 후보 0건 (아직 채우지 않음)

## E1 — 후보 출처별 (세트 합산)

| 출처 | 케이스 | 후보 생성됨 | 기대대로 판정 |
|---|---|---|---|
| rule_based | 9 | 4 | 5 |
| seeded | 11 | 9 | 4 |
| claude-code | 0 | 0 | 0 |

> 'claude-code' 행이 0 이면 LLM 축은 아직 측정 전이다. 'seeded' 의 기대대로 판정 수는 검증 계층의 탐지 능력이지 LLM 이 그런 패치를 내는 빈도가 아니다.

