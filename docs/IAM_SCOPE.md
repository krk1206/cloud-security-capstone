# IAM 과다 권한 — 지원 범위와 검증 방법 (구현 전 명세)

현재 파이프라인은 **Security Group 만** 끝까지(V6 포함) 검증한다. IAM 은 `policy/patch_policy.json` 의
`supported_target_rules` 에 없으므로 `UNSUPPORTED_RULE` 로 종료하고, 어떤 경로로든 IAM 리소스가 바뀌면
Risk Rubric 의 hard condition(`iam_resource_touched`) 으로 위험도 HIGH → 자율성 LOW(REPORT_ONLY) 다.
즉 지금은 README 16절의 대체 경로 **"IAM 은 무조건 사람 승인"** 이 코드로 강제돼 있다.

IAM 을 다음 단계로 구현할 때의 범위를 먼저 못 박는다. **범용 IAM 실효 권한 검증을 문자열 검사로 대체하지 않는다.**

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

README 7주차 항목. 구현 난이도를 재평가해 Tier 1 도 어렵다고 판단되면 현재의 "IAM 은 사람 승인" 정책을 유지하고 그 사실을 보고한다.
