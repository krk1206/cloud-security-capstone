# mock_llm fixtures — 사람이 미리 작성한 고정 응답

`iacpatch review --candidate mock:<이름>` 과 `predeploy --llm-provider mock` 이 읽는 canned 응답이다.
**LLM 이 생성한 출력이 아니다.** 검증 계층이 정의된 케이스(정상/기만/오류)에서 어떻게 판정하는지 시험하기 위해
개발 중 손으로 만든 예제이며, 각 파일의 `_note` 에 그 사실을 적어 두었다. 자연 발생률·성능 실험 자료로 쓰지 않는다.

| 파일 | 내용 |
|---|---|
| sg_baseline_ok | 정상: 승인 출처(테스트 값 203.0.113.0/24)만 남김 |
| sg_baseline_ok_propose_low | 정상 + 등급 하향 제안 |
| sg_baseline_cidr_split | SEEDED 기만적 패치: 0.0.0.0/1 + 128.0.0.0/1 |
| sg_baseline_inplan_prefix_list | SEEDED: plan 내 prefix list(0.0.0.0/0) 경유 |
| sg_baseline_external_prefix_list | 외부 prefix list ID → 전개 불가(UNKNOWN) |
| sg_baseline_ipv6_open | IPv4 는 고치고 IPv6 ::/0 개방 |
| sg_baseline_unapproved_cidr | 인터넷 전체는 아니지만 승인 밖 출처 |
| sg_baseline_breaks_required | 필요한 접근까지 제거 |
| sg_baseline_deletes_sg | 대상 리소스 삭제 |
| sg_baseline_unknown_value | plan 시점 미확정 값(EIP) |
| sg_baseline_edits_provider | provider.tf 수정 (정책 위반) |
| sg_baseline_truncated / garbage / wrong_schema | 잘린 응답 / JSON 아님 / 스키마 위반 |
| sg_baseline_insufficient | 정보 부족 선언 |
| sg_two_groups_fix_app_only | scenarios/eval/sg-two-groups 용: app 만 고치고 legacy 는 그대로 |
