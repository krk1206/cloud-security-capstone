# 스캐너 사각 탐색 실험 (자동 생성) — 겉모습만 다른 변형을 Trivy 와 오라클(V6)에 나란히

- 생성: 20260922-061649 · host=vm, trivy=0.74.0, terraform=terraform 1.10.6 · 원문: `experiments/fuzz/20260922-061649-vm/` (변형 main.tf, trivy.json, plan.json)
- 정답(truth)은 변형을 만들 때 구조적으로 정해진다 (`src/iacpatch/fuzz/*_variants.py`). 사람이 라벨을 적지 않았다.
- Trivy 열: SG 는 AVD-AWS-0107 이 FAIL 인가, IAM 은 aws_iam_* 리소스에 FAIL finding 이 하나라도 있는가. 오라클 열: V6 판정 (plan JSON 기준).
- 이 숫자는 '스캐너가 못 보는 겉모습이 몇 종인가' 이지 'LLM 이 이런 패치를 얼마나 내는가' 가 아니다.
**합계**: 잡혀야 하는 변형 59개 중 Trivy 사각 **44개**, 그중 오라클 탐지 **44개** · UNKNOWN 0개 · 오라클도 놓침 **0개**


## Security Group (SSH 22, 승인 출처 10.0.0.0/8) — 변형 42개
- 잡혀야 하는 변형 34개 중 **Trivy 가 못 본 것 27개** → 그중 오라클이 잡은 것 **27개**, 사람에게 넘긴 것(UNKNOWN) 0개, **오라클도 놓친 것 0개**
- 정상 수정 8개: 오라클 오탐 0개, 스캐너 오탐 1개
- plan 실패(V4 에서 걸림) 0개

| 재주(family) | 변형 | 잡혀야 함 | Trivy 사각 | 오라클 탐지 | 오라클 사각 |
|---|---|---|---|---|---|
| control | 3 | 2 | 1 | 2 | 0 |
| cidr-split | 11 | 10 | 10 | 10 | 0 |
| separate-rule | 5 | 4 | 4 | 4 | 0 |
| indirection | 8 | 6 | 4 | 6 | 0 |
| iteration | 3 | 3 | 3 | 3 | 0 |
| reference | 4 | 3 | 3 | 3 | 0 |
| port | 4 | 3 | 0 | 3 | 0 |
| ipv6 | 3 | 2 | 1 | 2 | 0 |
| aggregation | 1 | 1 | 1 | 1 | 0 |

| 변형 | 재주 | 정답 | Trivy | Trivy 룰 | plan | 오라클 | 판정 | 설명 |
|---|---|---|---|---|---|---|---|---|
| control-open | control | open | FAIL | AVD-AWS-0107 | OK | FAIL | 둘 다 탐지 | 취약 대조군: 0.0.0.0/0 그대로 |
| control-approved | control | approved | PASS | - | OK | PASS | 정상 통과 | 정상 수정: 승인 출처만 |
| control-unapproved-8 | control | unapproved | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 승인 밖 대역 하나 |
| split-2 | cidr-split | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 0.0.0.0/0 을 2 조각으로 한 규칙에 |
| split-4 | cidr-split | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 0.0.0.0/0 을 4 조각으로 한 규칙에 |
| split-8 | cidr-split | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 0.0.0.0/0 을 8 조각으로 한 규칙에 |
| split-16 | cidr-split | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 0.0.0.0/0 을 16 조각으로 한 규칙에 |
| split-64 | cidr-split | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 0.0.0.0/0 을 64 조각으로 한 규칙에 |
| split-uneven | cidr-split | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 크기가 다른 조각 |
| split-overlap | cidr-split | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 겹치는 조각 (중복 포함) |
| split-two-rules | cidr-split | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 두 ingress 블록에 반씩 |
| split-with-approved | cidr-split | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 승인 출처 옆에 조각을 끼움 |
| superset-of-approved | cidr-split | unapproved | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 승인 대역을 포함하는 더 큰 대역 |
| approved-split | cidr-split | approved | PASS | - | OK | PASS | 정상 통과 | 승인 대역을 조각낸 정상 수정 |
| vpc-rule-split-2 | separate-rule | open | PASS | AVD-AWS-0124 | OK | FAIL | 스캐너 사각 · 오라클 탐지 | aws_vpc_security_group_ingress_rule 2개로 분할 |
| vpc-rule-split-4 | separate-rule | open | PASS | AVD-AWS-0124 | OK | FAIL | 스캐너 사각 · 오라클 탐지 | aws_vpc_security_group_ingress_rule 4개로 분할 |
| legacy-rule-split-2 | separate-rule | open | PASS | AVD-AWS-0124 | OK | FAIL | 스캐너 사각 · 오라클 탐지 | aws_security_group_rule(레거시) 2개로 분할 |
| vpc-rule-approved | separate-rule | approved | PASS | AVD-AWS-0124 | OK | PASS | 정상 통과 | 별도 규칙 리소스로 승인 출처만 |
| vpc-rule-mixed-unapproved | separate-rule | unapproved | PASS | AVD-AWS-0124 | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 인라인 없음 + 별도 규칙 승인 1 · 미승인 1 |
| var-default-split | indirection | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 변수 기본값에 조각 |
| local-concat | indirection | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | locals + concat() |
| cidrsubnet-fn | indirection | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | cidrsubnet() 로 조각을 계산 |
| format-fn | indirection | open | FAIL | AVD-AWS-0107 | OK | FAIL | 둘 다 탐지 | format() 으로 0.0.0.0/0 조합 |
| join-fn | indirection | open | FAIL | AVD-AWS-0107 | OK | FAIL | 둘 다 탐지 | join() 으로 조합 |
| for-expr | indirection | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | for 식 |
| var-approved | indirection | approved | PASS | - | OK | PASS | 정상 통과 | 변수 경유 정상 수정 |
| cidrsubnets-approved | indirection | approved | PASS | - | OK | PASS | 정상 통과 | cidrsubnets() 로 승인 대역 조각 |
| dynamic-split | iteration | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | dynamic 블록 + 조각 |
| for-each-rules | iteration | open | PASS | AVD-AWS-0124 | OK | FAIL | 스캐너 사각 · 오라클 탐지 | for_each 규칙 리소스 |
| count-cidrsubnet | iteration | open | PASS | AVD-AWS-0124 | OK | FAIL | 스캐너 사각 · 오라클 탐지 | count + cidrsubnet() |
| prefix-list-split | reference | open | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | prefix list 안에 조각 |
| prefix-list-approved | reference | approved | PASS | - | OK | PASS | 정상 통과 | prefix list 안에 승인 대역만 |
| sg-ref-unapproved | reference | unapproved | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 다른 SG 참조 (승인 안 됨) |
| self-ref | reference | unapproved | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | self 참조 |
| port-range-cover | port | open | FAIL | AVD-AWS-0107 | OK | FAIL | 둘 다 탐지 | 포트 범위 20-30 이 22 포함 |
| all-ports | port | open | FAIL | AVD-AWS-0107 | OK | FAIL | 둘 다 탐지 | 0-65535 |
| all-protocols | port | open | FAIL | AVD-AWS-0107 | OK | FAIL | 둘 다 탐지 | protocol -1 |
| udp-only-22 | port | approved | FAIL | AVD-AWS-0107 | OK | PASS | 스캐너 오탐 | UDP 22 만 전체 개방 (SSH 는 TCP) |
| ipv6-open | ipv6 | unapproved | FAIL | AVD-AWS-0107 | OK | FAIL | 둘 다 탐지 | IPv4 는 승인, IPv6 ::/0 추가 (승인된 v6 없음) |
| ipv6-split | ipv6 | unapproved | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | IPv6 조각 |
| ipv6-approved | ipv6 | approved | PASS | - | OK | PASS | 정상 통과 | 승인된 IPv6 만 |
| second-sg-split | aggregation | open | PASS | AVD-AWS-0028, AVD-AWS-0131 | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 대상 SG 는 정상, 같은 인스턴스의 다른 SG 가 조각 개방 |

## IAM (report-worker, 승인 = s3:GetObject/ListBucket on report-archive) — 변형 32개
- 잡혀야 하는 변형 25개 중 **Trivy 가 못 본 것 17개** → 그중 오라클이 잡은 것 **17개**, 사람에게 넘긴 것(UNKNOWN) 0개, **오라클도 놓친 것 0개**
- 정상 수정 2개: 오라클 오탐 0개, 스캐너 오탐 0개
- Tier 1 밖 구조 5개: UNKNOWN(설계대로) 4개, FAIL(보수적) 1개, PASS 로 샘 0개
- plan 실패(V4 에서 걸림) 0개

| 재주(family) | 변형 | 잡혀야 함 | Trivy 사각 | 오라클 탐지 | 오라클 사각 |
|---|---|---|---|---|---|
| control | 2 | 1 | 0 | 1 | 0 |
| wildcard | 8 | 8 | 7 | 8 | 0 |
| enumeration | 7 | 6 | 3 | 6 | 0 |
| encoding | 5 | 5 | 2 | 5 | 0 |
| outside-tier1 | 5 | 0 | 0 | 0 | 0 |
| breaks | 3 | 3 | 3 | 3 | 0 |
| trust | 2 | 2 | 2 | 2 | 0 |

| 변형 | 재주 | 정답 | Trivy | Trivy 룰 | plan | 오라클 | 판정 | 설명 |
|---|---|---|---|---|---|---|---|---|
| control-s3-star | control | excess | FAIL | AVD-AWS-0345 | OK | FAIL | 둘 다 탐지 | 취약 대조군: s3:* on * (Trivy 0345 대상) |
| control-least | control | least | PASS | - | OK | PASS | 정상 통과 | 정상 수정: 승인 권한만 |
| star-action | wildcard | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | Action "*" (0057 deprecated 라 Trivy 가 못 봄) |
| star-action-list | wildcard | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | ["*"] 리스트 형태 |
| partial-wildcard-get | wildcard | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | s3:Get* (GetBucketPolicy 등 포함) |
| partial-wildcard-object | wildcard | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | s3:*Object (Put/Delete 포함) |
| service-upper | wildcard | excess | FAIL | AVD-AWS-0345 | OK | FAIL | 둘 다 탐지 | S3:* 대문자 (IAM 은 대소문자 무시) |
| resource-star-kept | wildcard | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 액션은 좁혔지만 Resource * 유지 (TerraProbe 의 기만 9/10 유형) |
| resource-s3-all | wildcard | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | Resource arn:aws:s3:::* (모든 버킷) |
| resource-prefix | wildcard | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | report-archive* (report-archive-backup 도 매치) |
| enumerated-extra | enumeration | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 와일드카드 없이 액션을 더 나열 |
| two-statements | enumeration | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 승인 문 + 추가 문 |
| two-policies | enumeration | excess | FAIL | AVD-AWS-0345 | OK | FAIL | 둘 다 탐지 | 정책 두 개를 같은 역할에 |
| inline-role-policy | enumeration | excess | FAIL | AVD-AWS-0345 | OK | FAIL | 둘 다 탐지 | aws_iam_role_policy 인라인으로 추가 |
| inline-policy-attr | enumeration | excess | FAIL | AVD-AWS-0345 | OK | FAIL | 둘 다 탐지 | role.inline_policy 블록 (deprecated 속성) |
| case-mixed-least | enumeration | least | PASS | - | OK | PASS | 정상 통과 | 대소문자만 다른 정상 수정 |
| action-string-least | enumeration | breaks | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 문자열 하나 = 필수 ListBucket 빠짐 |
| heredoc-json | encoding | excess | FAIL | AVD-AWS-0345 | OK | FAIL | 둘 다 탐지 | heredoc 문자열 JSON |
| data-policy-document | encoding | excess | PASS | AVD-AWS-0345 | OK | FAIL | 스캐너 사각 · 오라클 탐지 | data.aws_iam_policy_document (plan 때 계산) |
| version-2008 | encoding | excess | FAIL | AVD-AWS-0345 | OK | FAIL | 둘 다 탐지 | Version 2008-10-17 |
| statement-object | encoding | excess | FAIL | AVD-AWS-0345 | OK | FAIL | 둘 다 탐지 | Statement 가 리스트가 아니라 객체 |
| local-actions | encoding | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | locals 경유 액션 목록 |
| notaction | outside-tier1 | unknown | PASS | - | OK | UNKNOWN | 판단 불가 (설계대로 사람에게) | NotAction |
| condition-ip | outside-tier1 | unknown | FAIL | AVD-AWS-0345 | OK | UNKNOWN | 판단 불가 (설계대로 사람에게) | Condition 붙은 s3:* |
| deny-plus-star | outside-tier1 | unknown | FAIL | AVD-AWS-0345 | OK | FAIL | FAIL (보수적, 허용) | Allow s3:* + Deny |
| managed-full-access | outside-tier1 | unknown | FAIL | AVD-AWS-0345 | OK | UNKNOWN | 판단 불가 (설계대로 사람에게) | 관리형 정책 AmazonS3FullAccess 추가 |
| notresource | outside-tier1 | unknown | PASS | - | OK | UNKNOWN | 판단 불가 (설계대로 사람에게) | NotResource |
| breaks-missing-list | breaks | breaks | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | ListBucket 없음 |
| wrong-bucket | breaks | breaks | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | 다른 버킷 |
| object-only-resource | breaks | breaks | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | ListBucket 에 버킷 ARN 없음 |
| trust-principal-star | trust | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | assume_role_policy Principal * (누구나 역할을 맡음) |
| trust-aws-star | trust | excess | PASS | - | OK | FAIL | 스캐너 사각 · 오라클 탐지 | Principal { AWS = * } |
