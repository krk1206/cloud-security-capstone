# iam-x-* — 교차검증(2026-09-22)에서 나온 IAM 오라클 공격 케이스

`docs/CROSS_VERIFICATION_2026-09-22.md` 의 검토자(별도 세션의 AI)가 만든 후보를 OpenTofu 1.10.6 + AWS provider 5.100.0 오프라인 plan 으로 만든 것.
수정 전 오라클은 전부 **PASS(false PASS)** 였고, 수정 후에는 UNKNOWN 또는 FAIL 이어야 한다 (tests/unit/test_iam_slice.py `test_cross_verification_attacks_never_pass`).

| 케이스 | 수법 | 수정 후 기대 |
|---|---|---|
| b1-ref-launder | policy_arn 값은 관리형 AdministratorAccess 인데 references 에 대상 정책이 섞임 | UNKNOWN (관리형 미평가) |
| b2-inline-unknown | 역할 inline_policy 의 policy 값이 plan 시점 미확정 | UNKNOWN |
| b3-module | 모듈 안 aws_iam_policy.worker(*) 를 역할에 부착 — 루트의 같은 이름과 주소 충돌 | FAIL |
| b4-attachments-exclusive | aws_iam_role_policy_attachments_exclusive 로 관리형 정책 부착 | UNKNOWN |
| b5-policy-attachment | aws_iam_policy_attachment(roles 목록형) | UNKNOWN |
| b9c | managed_policy_arns 가 함수 경유로 미확정 (새 리소스 없음, 스캐너 finding 없음) | UNKNOWN |
| b13-two-refs | policy_arn 이 두 정책을 참조 (문자열 조합) | UNKNOWN |
