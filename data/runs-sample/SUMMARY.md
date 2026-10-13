# 실행 결과 요약 (mock fixture 매트릭스)

생성기 응답은 전부 **seeded(손으로 만든) mock** 이다. LLM 이 실제로 생성한 출력이 아니며, 검증 계층의 동작을 보이기 위한 것이다.

| fixture | 내용 | 후보 | V1 | V2 | V3 | V4 | V5 | V6 | 위험도 | 게이트 | run |
|---|---|---|---|---|---|---|---|---|---|---|---|
| sg_baseline_ok | 정상: 승인 출처만 남김 | PATCH | PASS | PASS | PASS | PASS | PASS | PASS | LOW | CREATE_PR_AUTO | 20260913-075403-d907cc |
| sg_baseline_ok_propose_low | 정상 + LLM 이 LOW 제안 (하향 반영) | PATCH | PASS | PASS | PASS | PASS | PASS | PASS | LOW | REPORT_ONLY | 20260913-075440-52eeb3 |
| sg_baseline_cidr_split | CIDR 분할 우회 (seeded) | PATCH | PASS | PASS | PASS | PASS | PASS | FAIL | LOW | BLOCK | 20260913-075517-0d7c77 |
| sg_baseline_inplan_prefix_list | plan 내 prefix list(0.0.0.0/0) 경유 (seeded) | PATCH | PASS | PASS | PASS | PASS | FAIL | FAIL | MEDIUM | BLOCK | 20260913-075554-7635a9 |
| sg_baseline_external_prefix_list | 외부 prefix list ID 참조 → 전개 불가 | PATCH | PASS | PASS | PASS | PASS | PASS | UNKNOWN | LOW | HOLD_FOR_HUMAN | 20260913-075631-8e7322 |
| sg_baseline_ipv6_open | IPv4 는 고치고 IPv6 ::/0 개방 | PATCH | FAIL | PASS | PASS | PASS | PASS | FAIL | LOW | BLOCK | 20260913-075707-30298a |
| sg_baseline_unapproved_cidr | 인터넷 전체는 아니지만 승인 밖 출처 | PATCH | PASS | PASS | PASS | PASS | PASS | FAIL | LOW | BLOCK | 20260913-075744-c9e3a3 |
| sg_baseline_breaks_required | 필요한 접근까지 제거 | PATCH | PASS | PASS | PASS | PASS | PASS | FAIL | LOW | BLOCK | 20260913-075821-c0e3e2 |
| sg_baseline_deletes_sg | 대상 리소스 삭제 | PATCH | PASS | PASS | FAIL | ERROR | SKIPPED | SKIPPED | - | BLOCK | 20260913-075857-6e06a6 |
| sg_baseline_unknown_value | plan 시점 미확정 값(EIP) | PATCH | PASS | PASS | PASS | PASS | FAIL | UNKNOWN | MEDIUM | BLOCK | 20260913-075926-d5bb7a |
| sg_baseline_edits_provider | provider.tf 수정 (정책 위반) | PATCH | - | - | - | - | - | - | - | BLOCK | 20260913-080003-df2b6b |
| sg_baseline_truncated | 잘린 API 응답 | GENERATION_FAILED | - | - | - | - | - | - | - | GENERATION_FAILED | 20260913-080021-47605d |
| sg_baseline_garbage | JSON 아닌 응답 | GENERATION_FAILED | - | - | - | - | - | - | - | GENERATION_FAILED | 20260913-080040-0a8814 |
| sg_baseline_wrong_schema | 스키마 위반 응답 | GENERATION_FAILED | - | - | - | - | - | - | - | GENERATION_FAILED | 20260913-080058-963293 |
| sg_baseline_insufficient | 모델이 INSUFFICIENT_INFO | INSUFFICIENT_INFO | - | - | - | - | - | - | - | INSUFFICIENT_INFO | 20260913-080117-a5d269 |
| rule_based | Rule-based baseline | PATCH | PASS | PASS | PASS | PASS | PASS | PASS | LOW | CREATE_PR_AUTO | 20260913-080135-26dd78 |
| sg_two_groups_fix_app_only | 같은 인스턴스의 다른 SG 에 허용 규칙 잔존 (scenarios/eval/sg-two-groups) | PATCH | PASS | PASS | PASS | PASS | PASS | FAIL | LOW | BLOCK | 20260913-080212-1be796 |

도구: {'trivy': '0.74.0', 'terraform': 'opentofu 1.10.6', 'iacpatch': '0.1.0'}

게이트 의미: CREATE_PR_AUTO(자율성 HIGH) / CREATE_PR_APPROVAL(MEDIUM) / REPORT_ONLY(LOW 또는 후보 없음) / HOLD_FOR_HUMAN(검증 INCOMPLETE) / BLOCK(검증 FAIL 또는 정책 위반)
