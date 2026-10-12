# policy/checks - 커스텀 Trivy 체크

Trivy는 `--config-check <디렉터리> --check-namespaces user`로 사용자 rego 체크를 함께 실행한다.

    trivy config scenarios/iam-overprivileged --config-check policy/checks --check-namespaces user

| 체크 | 심각도 | 왜 만들었나 |
|---|---|---|
| CAPSTONE-IAM-0001 iam-no-wildcards | HIGH | Trivy 내장 AWS-0057(IAM 와일드카드 금지)은 trivy-checks 커밋 c292eb67(2024-12-18, "add removed Go checks as deprecated")에서 본체가 제거되고 메타데이터만 남았다. `--include-deprecated-checks`를 줘도 deny 규칙이 없어 아무것도 잡지 않는다. 남은 IAM 체크(AWS-0345 `s3:*`, AWS-0346 `s3:get*`+`s3:put*`)는 `Action: "*"`를 보지 않는다. 시나리오 3(IAM 과다 권한) 탐지를 위해 같은 범위를 우리가 다시 구현했다 |

검증(2026-10-13, trivy 0.74.0 + trivy-checks 2026-10 로컬):

| 대상 | CAPSTONE-IAM-0001 |
|---|---|
| scenarios/iam-overprivileged | FAIL 2건 (Action "*", Resource "*") - `data.aws_iam_policy_document.web_overprivileged` |
| infrastructure/three-tier (정상 정책) | 0건 |
| infrastructure/sg-baseline | 0건 |

범위: 역할 인라인 정책, 독립 정책(aws_iam_policy), 사용자/그룹 정책. 신뢰 정책(assume_role_policy)은 보지 않는다. Condition이 있는 Statement도 와일드카드면 잡는다(v1에서는 Condition 예외를 두지 않는다).
