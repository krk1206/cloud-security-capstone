# IAM 과다 권한 — 지원 범위와 검증 방법 (Tier 1 구현됨, 2026-09-22)

> **구현 상태 (2026-09-22, 배포 전 슬라이스 완료 — 샌드박스 실측)**
> - 대상 룰: **AVD-AWS-0345**(무제한 S3 정책 `s3:*`), AVD-AWS-0342(`iam:PassRole`). `Action:"*"` 는 Trivy 0.74.0 내장 체크에서 잡히지 않는다 — AVD-AWS-0057 이 deprecated(빈 규칙) 다 (D-8). 이 사실 자체가 "s3:* → *" 기만 패치가 스캐너를 통과하는 이유다.
> - 코드: `src/iacpatch/iam_intent.py`(intent, `kind: iam`), `src/iacpatch/verify/iam_oracle.py`(V6-IAM), `verify/v6.py` 분기, `generator/rule_based.py` IAM 분기, `policy/patch_policy.json` sg-iam-v2, `policy/risk_rubric.json` risk-v2(D-6, D-9).
> - 시나리오: `scenarios/dev/iam-app-role`(개발), `scenarios/eval/iam-report-worker`(평가 원본), `scenarios/eval/iam-probe/`(규칙 기반 비교 5종).
> - 실험 재료: `experiments/candidate-sets/eval-seeded-iam`(seeded 13, intent D-7), `eval-iam-rule`(규칙 기반 5). 실제 plan: `tests/fixtures/plans/iam-*` 14개.
> - 실측(샌드박스, OpenTofu 1.10.6 + Trivy 0.74.0): seeded 13/13 기대 일치, V1만 통과 9 → V1+V6 통과 2; 오라클 단독(실제 plan 14, 서로 다른 plan 13) 스캐너 PASS∧오라클 FAIL 8, 오탐 0; 규칙 기반 5/5 기대 일치(후보 2/5). 배포 후(V7/V8) 는 IAM 도 미실행. 2026-09-22 교차검증에서 false PASS 7종이 발견돼 고쳤다 (`docs/CROSS_VERIFICATION_2026-09-22.md`).
> - IAM 변경의 검토 수준은 **최소 FULL_REVIEW**(사람 승인 필수). 신뢰 정책 변경(모듈 안·새 역할 포함)은 plan 기반·텍스트 기반 모두 hard HIGH (교차검증 #9 후).

아래 1~3절은 **구현된 것 기준으로 2026-09-22 에 고쳐 쓴 명세**다 (원래 초안은 git 이력에 있다). 구현 전 초안과 달라진 점: 역할 단위 합산을 지원하고,
신뢰 정책의 전체 개방(Principal `*`)을 FAIL 로 판정하며, 배포 후 IAM 시뮬레이션(V7-IAM)은 **아직 없다**. **범용 IAM 실효 권한 검증을 문자열 검사로 대체하지 않는다.**

## 1. 지원 범위 (Tier 1, 구현됨)

- 정책 문서 출처: `aws_iam_policy` / `aws_iam_role_policy` / `aws_iam_user_policy` / `aws_iam_group_policy` 의 `policy`(plan 에 확정된 JSON), `aws_iam_role.inline_policy`.
  `data.aws_iam_policy_document` 는 plan 에서 문자열로 해소되므로 그대로 읽힌다.
- **역할 단위 합산 (지원):** intent 의 `targets.roles` 에 적힌 역할에 붙는 정책을 모두 모아 본다 — `aws_iam_role_policy_attachment`(plan 안 정책 참조가 정확히 하나일 때),
  `aws_iam_role_policy`, `inline_policy`. 그래서 "대상 정책은 고치고 다른 정책으로 권한을 옮기는" 패치가 잡힌다 (seeded inline-role-policy, second-policy).
- Statement 문법 부분집합: `Effect: Allow` 만, `Action`/`Resource` 는 문자열 또는 문자열 리스트, 와일드카드는 `*` 만.
  포함 판정은 "패턴 ⊆ 승인 패턴" (예: `s3:GetObject` ⊆ `s3:Get*`, `s3:*` ⊄ `s3:Get*`). Action 은 대소문자 무시(ASCII 만), Resource 는 구분.
- 신뢰 정책(`assume_role_policy`): 권한 집합은 아니지만 `Principal: "*"`(또는 `{"AWS": "*"}`) 이고 `Condition` 이 없는 Allow 문은 EXCESS → FAIL.
- **판단하지 않음 (→ UNKNOWN, 자동 승인 금지):** `Deny`, `NotAction`/`NotResource`, `Condition`, `Principal`(자격 정책 안), 정책 변수 `${...}`, `?` 와일드카드,
  액션/ARN 의 공백·비ASCII 문자, JSON 중복 키, plan 시점 미확정 값(`policy`, `inline_policy.policy`, `managed_policy_arns`), AWS 관리형 정책(승인 목록에 없으면),
  `aws_iam_policy_attachment`(roles 목록형)·`*_policy_attachments_exclusive`·`*_policies_exclusive`, `policy_arn` 참조가 둘 이상인 attachment, 확정된 `policy_arn` 문자열이
  plan 안 정책을 가리키는 것처럼 참조를 섞은 경우(값을 우선하고 참조를 믿지 않는다), permission boundary, SCP, 리소스 정책.
- **6 절의 공격 케이스 7종**(교차검증)은 이 규칙으로 UNKNOWN/FAIL 이 된다. 회귀 테스트: `tests/unit/test_iam_slice.py::test_cross_verification_attacks_never_pass`.

## 2. Intent 형식 (구현됨 — `src/iacpatch/iam_intent.py`)

```json
{
  "kind": "iam", "intent_id": "iam-report-worker", "status": "active",
  "targets": {"policies": ["aws_iam_policy.worker"], "roles": ["aws_iam_role.worker"]},
  "approved_permissions": [{"actions": ["s3:GetObject", "s3:ListBucket"], "resources": ["arn:aws:s3:::report-archive", "arn:aws:s3:::report-archive/*"]}],
  "required_permissions": [{"label": "read-report-objects", "action": "s3:GetObject", "resource": "arn:aws:s3:::report-archive/*"}],
  "approved_managed_policy_arns": []
}
```
`approved_permissions`(허용 상한)와 `required_permissions`(반드시 남아야 할 것)는 **사람이 적는다**. 초안의 `forbidden_patterns` 는 쓰지 않는다 — 승인 집합 밖은 전부 EXCESS 이므로 금지 목록이 필요 없다.

## 3. 검증 방법 (V6-IAM, 배포 전) 과 아직 없는 것

1. **정적 집합 검사 (구현됨, `verify/iam_oracle.py`)** — 위 1절. EXCESS/MISSING 이 하나라도 있으면 FAIL, FAIL 이 없고 UNKNOWN 이 있으면 UNKNOWN, 둘 다 없으면 PASS.
   이 PASS 는 **배포 전 판정**이다. 파이프라인의 "종합 PASS" 도 V1~V6(배포 전)에 대한 것이다.
2. **AWS 정책 시뮬레이션 (배포 후, V7-IAM) — 미구현.** 계획: `aws iam simulate-custom-policy` 로 `required_permissions` 가 allowed 인지, 승인 밖 대표 액션이 implicitDeny 인지 확인.
   TerraProbe 의 "IAM 정책 시뮬레이터" 권고. A 가 SG V7 을 먼저 돌린 뒤 착수한다. 그때까지 IAM 후보의 배포 후 검증 상태는 UNVERIFIED 다.

## 4. 예상 실패 유형 (기록 대상)

- `Resource: "*"` 를 유지한 채 Action 만 좁힌 패치 (TerraProbe 의 기만적 패치 9/10 이 이 유형인 CKV2_AWS_11 관련)
- 필요한 권한을 함께 지워 애플리케이션이 동작하지 않는 패치 (MISSING)
- 정책을 여러 문으로 쪼개 스캐너 룰만 회피하는 패치

## 5. 일정상 위치

README 7주차 항목 — 2026-09-22 에 Tier 1 배포 전 슬라이스를 앞당겨 구현했다. 남은 것: 배포 후 V7(IAM 은 `get-policy-version`/`list-attached-role-policies` 실측, 미구현), LLM 후보(IAM 프롬프트 5종은 준비됨), Tier 2(Deny/Condition/관리형 정책 전개)는 범위 밖.

## 6. Tier 1 이 판정하지 않는 것 (UNKNOWN 으로 남김 — 자동 승인 금지)

Deny 문, NotAction/NotResource, Condition, Principal(리소스 정책), 정책 변수 `${...}`, `?` 와일드카드, plan 시점 미확정 policy, AWS 관리형 정책(승인 목록에 없으면), `aws_iam_policy_attachment`(roles 목록형) 등 다른 부착 방식. seeded 세트의 NotAction·Condition·관리형 정책 3건이 이 경로로 UNKNOWN(PENDING) 이 된다.
