# IAM 과다 권한 — 지원 범위와 검증 방법 (Tier 1 구현됨, 2026-09-22)

> **구현 상태 (2026-09-22, 배포 전 슬라이스 완료 — 샌드박스 실측)**
> - 대상 룰: **AVD-AWS-0345**(무제한 S3 정책 `s3:*`), AVD-AWS-0342(`iam:PassRole`). `Action:"*"` 는 Trivy 0.74.0 내장 체크에서 잡히지 않는다 — AVD-AWS-0057 이 deprecated(빈 규칙) 다 (D-8). 이 사실 자체가 "s3:* → *" 기만 패치가 스캐너를 통과하는 이유다.
> - 코드: `src/iacpatch/iam_intent.py`(intent, `kind: iam`), `src/iacpatch/verify/iam_oracle.py`(V6-IAM), `verify/v6.py` 분기, `generator/rule_based.py` IAM 분기, `policy/patch_policy.json` sg-iam-v2, `policy/risk_rubric.json` risk-v2-draft(D-6).
> - 시나리오: `scenarios/dev/iam-app-role`(개발), `scenarios/eval/iam-report-worker`(평가 원본), `scenarios/eval/iam-probe/`(규칙 기반 비교 5종).
> - 실험 재료: `experiments/candidate-sets/eval-seeded-iam`(seeded 13, intent D-7), `eval-iam-rule`(규칙 기반 5). 실제 plan: `tests/fixtures/plans/iam-*` 14개.
> - 실측(샌드박스, OpenTofu 1.10.6 + Trivy 0.74.0): seeded 13/13 기대 일치, V1만 통과 9 → V1+V6 통과 2, 오라클 FAIL 6·UNKNOWN 2; 오라클 단독(실제 plan 14) 스캐너 PASS∧오라클 FAIL 7, 오탐 0; 규칙 기반 5/5 기대 일치(후보 2/5). 배포 후(V7/V8) 는 IAM 도 미실행.
> - IAM 변경의 검토 수준은 **최소 FULL_REVIEW**(사람 승인 필수). 신뢰 정책 변경은 hard HIGH.

아래는 구현 전에 못 박은 범위 명세이며, 구현은 이 범위를 따랐다. **범용 IAM 실효 권한 검증을 문자열 검사로 대체하지 않는다.**

## 1. 지원할 정책 범위 (Tier 1)

- 리소스: `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_policy_document`(data) 의 인라인 JSON
- Statement 문법 부분집합: `Effect: Allow` 만, `Action`(문자열/리스트, `*` 와 접미 와일드카드 `s3:Get*` 허용), `Resource`(문자열/리스트, ARN 와일드카드 허용)
- **미지원(→ UNKNOWN, 자동 승인 금지):** `Deny` 문, `NotAction`/`NotResource`, `Condition`, `Principal`, 리소스 정책, permission boundary, SCP, 여러 정책의 결합(역할에 여러 정책이 붙는 경우), 정책 변수(`${aws:username}`)

## 2. Intent 형식 (초안)

```json
{
  "iam_targets": ["aws_iam_role_policy.app"],
  "required_permissions": [
    {"action": "s3:GetObject", "resource": "arn:aws:s3:::capstone-app-bucket/*"}
  ],
  "forbidden_patterns": [
    {"action": "*"}, {"action": "iam:*"}, {"resource": "*", "action_prefix": "s3:Put"}
  ]
}
```
`required_permissions` 는 애플리케이션이 실제로 필요로 하는 권한이며 **사람이 적는다** (코드가 추측하지 않는다).

## 3. 검증 방법 (V6-IAM)

두 단계를 모두 통과해야 PASS:

1. **정적 집합 검사 (자체 구현)** — Tier 1 문법 안에서 `Action × Resource` 를 와일드카드 확장 없이 "패턴 포함 관계" 로 비교한다.
   - EXCESS: 패치 후 정책이 `forbidden_patterns` 를 여전히 포함 (예: `Resource: "*"` + `s3:*`)
   - MISSING: `required_permissions` 의 각 항목이 어떤 Allow 문에도 매칭되지 않음
   - Tier 1 밖 문법이 하나라도 있으면 UNKNOWN
2. **AWS 정책 시뮬레이션 (배포 후, V7-IAM)** — `aws iam simulate-custom-policy --policy-input-list <patched json> --action-names ... --resource-arns ...` 로
   `required_permissions` 각각이 `allowed` 인지, `forbidden` 조합의 대표 액션(예: `s3:PutObject` on `arn:aws:s3:::*`)이 `implicitDeny` 인지 확인한다.
   TerraProbe 가 권고한 "IAM 정책 시뮬레이션" 에 해당한다. 이 단계 없이 정적 검사만으로 PASS 를 주지 않는다.

## 4. 예상 실패 유형 (기록 대상)

- `Resource: "*"` 를 유지한 채 Action 만 좁힌 패치 (TerraProbe 의 기만적 패치 9/10 이 이 유형인 CKV2_AWS_11 관련)
- 필요한 권한을 함께 지워 애플리케이션이 동작하지 않는 패치 (MISSING)
- 정책을 여러 문으로 쪼개 스캐너 룰만 회피하는 패치

## 5. 일정상 위치

README 7주차 항목 — 2026-09-22 에 Tier 1 배포 전 슬라이스를 앞당겨 구현했다. 남은 것: 배포 후 V7(IAM 은 `get-policy-version`/`list-attached-role-policies` 실측, 미구현), LLM 후보(IAM 프롬프트 5종은 준비됨), Tier 2(Deny/Condition/관리형 정책 전개)는 범위 밖.

## 6. Tier 1 이 판정하지 않는 것 (UNKNOWN 으로 남김 — 자동 승인 금지)

Deny 문, NotAction/NotResource, Condition, Principal(리소스 정책), 정책 변수 `${...}`, `?` 와일드카드, plan 시점 미확정 policy, AWS 관리형 정책(승인 목록에 없으면), `aws_iam_policy_attachment`(roles 목록형) 등 다른 부착 방식. seeded 세트의 NotAction·Condition·관리형 정책 3건이 이 경로로 UNKNOWN(PENDING) 이 된다.
