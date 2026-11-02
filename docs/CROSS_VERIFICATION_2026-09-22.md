# 교차검증 기록 — 2026-09-22 (AI 가 만든 것을 다른 AI 세션이 공격, 사람이 재현할 것)

> 원칙(지도교수 9/22): AI 가 만든 산출물은 다른 방법으로 교차검증한다. 이 문서는 첫 회차다.
> 검토자: B 세션과 **별개의 AI 세션**(같은 모델, 다른 컨텍스트)에게 "주장을 깨라" 는 지시만 주고 돌렸다. 검토자의 원문은 아래 요약이며, 재현 명령은 각 항목에 있다.
> **사람이 할 일:** 표의 "재현" 열을 각자 PC 에서 돌려 결과가 같은지 확인하고, 확인자·날짜를 마지막 열에 적는다. 그래야 "AI 가 AI 를 검증했다" 가 아니라 "사람이 확인했다" 가 된다.

## 1. 대상과 방법

| 대상 | 방법 |
|---|---|
| IAM Intent Oracle (`src/iacpatch/verify/iam_oracle.py`) | 정책 문서 43종 변형(`attack_oracle.py`) + 실제 OpenTofu plan 12종(모듈, 참조 세탁, 미확정 값 등) |
| `experiments/ORACLE_RESULTS.md` 의 IAM 숫자 | fixture 에서 독립 재계산, sha256 대조, Trivy 재스캔 |
| 실험 경로에 LLM API 없음 (D-5) | 런타임 import 그래프 추적 |
| `docs/PLAN_CHECK`, `docs/IAM_SCOPE` 의 주장 | 코드·기록과 대조 |
| 위험도 기준표 v2 구현 | `iam_trust_policy_changed`, medium floor 단조성, 병합 max |

## 2. 발견 → 조치

| # | 심각도 | 발견 | 조치 (커밋) | 재현 | 사람 확인 |
|---|---|---|---|---|---|
| 1 | **HIGH** | 역할의 `managed_policy_arns` 가 plan 시점 미확정이면 조용히 무시 → `AdministratorAccess` 를 함수로 감춘 후보가 V1~V6 **전부 PASS** | 설정에 `managed_policy_arns` 가 있는데 plan 값이 없으면 UNKNOWN | `tests/fixtures/plans/iam-x-b9c` → 오라클 UNKNOWN | |
| 2 | MEDIUM | attachment 의 `policy_arn` 값이 확정된 관리형 ARN 인데 `references` 에 대상 정책이 섞이면 대상 정책을 붙인 것으로 오인 (텍스트 정책이 차단은 함) | 값이 확정돼 있으면 값을 쓰고 참조를 믿지 않음 | `iam-x-b1-ref-launder` → UNKNOWN | |
| 3 | MEDIUM | `policy_arn` 이 정책 둘을 참조하면 첫 번째만 사용 | 참조가 둘 이상이면 UNKNOWN | `iam-x-b13-two-refs` → UNKNOWN | |
| 4 | MEDIUM | `inline_policy` 의 policy 값이 미확정이면 누락 (V5 가 잡긴 함) | 이름만 있는 inline 항목은 UNKNOWN | `iam-x-b2-inline-unknown` → UNKNOWN | |
| 5 | MEDIUM | `aws_iam_role_policy_attachments_exclusive`(provider 의 `managed_policy_arns` 대체) 무시 | `*_attachments_exclusive`/`*_policies_exclusive` 를 UNKNOWN 타입에 추가 | `iam-x-b4-attachments-exclusive` → UNKNOWN | |
| 6 | MEDIUM | 모듈 안 `aws_iam_policy.worker` 참조가 루트의 같은 이름으로 해소(주소 충돌) | 참조에 참조하는 리소스의 모듈 접두를 붙임 | `iam-x-b3-module` → FAIL | |
| 7 | MEDIUM | JSON 중복 키(`"Action"` 두 번) 는 마지막 값만 읽힘 | 중복 키 → UNKNOWN | `test_document_tricks_never_pass` | |
| 8 | MEDIUM | 유니코드 대소문자 접기(`ſ3:GetObject`, 켈빈 K) 가 승인/필수 둘 다 통과, `\n` 끝 문자열이 `$` 매칭 | `re.ASCII` + `\Z`, 공백·비ASCII 토큰은 UNKNOWN | 같은 테스트 | |
| 9 | MEDIUM | `iam_trust_policy_changed` 가 루트 주소만, plan 기반만 인식. 텍스트 기반은 jsonencode 안 키(`Principal`)를 속성으로 보고해 hard HIGH 미발동 + 모든 IAM 후보에 +1 오점수 | 타입 기준 매칭(모듈 포함), 새 역할도 hard, 중첩 키를 상위 속성(`assume_role_policy`/`policy`)으로 귀속 | 도구 없이 `review` 실행 시 trust-policy-open = HIGH, correct = MEDIUM/0 | |
| 10 | MEDIUM | `docs/IAM_SCOPE.md` 가 구현과 모순 (V7 없이는 PASS 안 준다고 써놓고 정적 PASS 를 냄; 역할 합산을 미지원이라 써놓고 합산으로 탐지) | 1~3절을 구현 기준으로 다시 씀 | 문서 | |
| 11 | MEDIUM | "등급 일치율 25/25" 가 자기일관성 검사인데 그 caveat 없이 제시 | PLAN_CHECK·RUBRIC_V2 에 "블라인드 아님" 명시. LLM 세트부터 실행 전 기입 | 문서 | |
| 12 | LOW | `unapproved-trust-policy-open` 이 "정상(PASS)" 으로 집계; 00 과 invalid-identical 이 같은 plan | 신뢰 정책 전체 개방을 오라클 EXCESS 로 확장(expected PASS→FAIL 정정); 표에 "서로 다른 plan 13" 명시 | `ORACLE_RESULTS.md` | |
| 13 | LOW | PLAN_CHECK 가 내부적으로 낡음 (IAM "없음" 과 "됨" 이 같은 행에) | 해당 칸 갱신 | 문서 | |
| 14 | LOW | Effect 변형·BOM·비객체 Statement 등은 UNKNOWN (안전). 미확정 관리형 정책의 사유 문구 부정확 | 사유 문구만 유지(UNKNOWN 이면 충분) | — | |

깨지지 않은 것(검토자 보고): `pattern_subset` 전수 검사(`{a,b,*}` 패턴 ≤3 vs 문자열 ≤5) 불일치 0, Effect 대소문자, ARN 대소문자, Statement 형태 변형 전부 FAIL/UNKNOWN, `aws_iam_policy_attachment`·count·for_each 케이스 UNKNOWN, 실험 경로의 LLM 모듈 import 없음(D-5 성립), medium floor 단조성, 병합 max.

## 3. 이 검증이 말해 주지 않는 것

- 검토자도 AI 다. 사람이 "재현" 열을 실제로 돌려 서명하기 전까지는 "AI 가 AI 를 검증한 것" 이다.
- 공격 케이스는 검토자가 생각해 낸 7종이다. 다른 우회가 없다는 증명이 아니다. Tier 1 의 답은 언제나 "모르면 UNKNOWN(사람 검토)" 이지 "안전" 이 아니다.
- 오라클은 배포 전 plan 만 본다. 실제 계정의 SCP·permission boundary·리소스 정책은 보지 않는다 (V7-IAM 미구현).

## 4. 다음 회차

- 사람 재현·서명 (A/B/C 각 5개 항목씩).
- SG 오라클(`sg_oracle.py`)에 같은 방식의 공격 회차 — 아직 안 했다.
- LLM 후보가 생기면 그 후보에 대해 "AI 판단 → Trivy → 오라클 → plan → 가이드 매핑 → 사람" 6단 교차검증 표를 후보마다 남긴다 (PROJECT_REVIEW_WEEK4.md 17절).
