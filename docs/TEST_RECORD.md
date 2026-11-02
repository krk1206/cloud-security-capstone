# 테스트·실행 기록 (2026-09-13, 샌드박스)

## 환경

| 도구 | 버전 | 비고 |
|---|---|---|
| Python | 3.11.15 (Linux x86_64) | 외부 패키지 없음 (pip 사용 불가 환경이라 표준 라이브러리로만 작성) |
| Trivy | 0.74.0 | 내장 체크 사용 (체크 번들 다운로드 불가 환경). 71 룰 실행 — 팀 기록(worklog 2026-09-11)과 동일 |
| Terraform 대체 | **OpenTofu 1.10.6** | hashicorp 릴리스 서버 차단으로 Terraform 1.16.1 미사용. plan JSON format_version 1.2 동일 |
| AWS provider | 5.100.0 (opentofu/terraform-provider-aws 미러) | 팀 환경과 같은 버전 |
| AWS CLI / 자격증명 | 없음 | V7/V8/apply/online plan 미실행 |
| LLM API | 없음 (mock 만) | 실제 API 미호출 |

## 단위·통합 테스트 (`scripts/run_tests.sh`)

```
Ran 116 tests in 209.935s
OK
```

| 파일 | 개수 | 내용 |
|---|---|---|
| test_netset.py | 9 | CIDR 집합: 2분할/4분할 collapse, 차집합, 포함, v4/v6 분리, strict 파싱 |
| test_intent.py | 7 | 플레이스홀더/draft/인터넷 전체 승인 거부, CIDR 오류 |
| test_oracle_fixtures.py | 22 | 실제 plan JSON 23종에 대한 V6 판정 (아래 표) |
| test_layers.py | 19 | V1(0 checks → ERROR 포함), V2(키 기반, 이동 감지, 심각도/무시 룰), V5(삭제/교체/타입/속성/provider) |
| test_policy_risk_gate.py | 18 | 정책 위반 유형, 위험도 hard condition, 게이트 매트릭스, LLM 하향만 |
| test_generators.py | 20 | 응답 파싱(잘림·비JSON·스키마·중복 경로), mock provider, 키 없는 실제 provider 의 오류 처리, rule-based 지원/미지원 |
| test_postdeploy.py | 14 | V7 (FakeCli: ENI 합산, prefix list 전개/실패, 참조 SG), V8 (로컬 소켓: 허용 성공/차단 실패/승인 밖 vantage 부재 → UNKNOWN) |
| test_pipeline_integration.py | 7 | 실제 Trivy + tofu 로 end-to-end: 정상/CIDR 분할/외부 prefix list/두 SG/잘린 응답/draft intent/rule-based |

도구가 없는 환경에서는 통합 7종이 skip 되고 109종이 통과한다 (`OK (skipped=7)` 확인).

### V6 fixture 판정표 (test_oracle_fixtures.py)

승인 출처(테스트 값) = 10.0.0.0/8, 필수 접근 = 10.0.0.0/8 → tcp/22. 케이스 내용을 읽고 기대값을 정했다.

| 케이스 | 내용 | 기대 | 결과 |
|---|---|---|---|
| 00-baseline | 취약한 대조군 0.0.0.0/0 | FAIL | FAIL |
| 00b-baseline-fixed | 정상 수정본 10.0.0.0/8 | PASS | PASS |
| 01-cidr-split | 0.0.0.0/1 + 128.0.0.0/1 | FAIL (실효 0.0.0.0/0) | FAIL |
| 02/03/04 | 변수/문자열 조합/dynamic | FAIL | FAIL |
| 05-separate | 별도 규칙 리소스 | FAIL | FAIL |
| 06-prefix-list | plan 내 prefix list(0.0.0.0/0) | FAIL (전개) | FAIL |
| 07-ipv6-only | ::/0 | FAIL (v6) | FAIL |
| 08-second-sg | 같은 인스턴스의 legacy SG 개방 | FAIL (인스턴스 범위 합산) | FAIL |
| 09-partial-port-range | 20-25 범위가 22 포함 | FAIL | FAIL |
| 10-all-protocols | protocol -1 | FAIL | FAIL |
| 11-sg-ref-source | 참조 SG 출처 (bastion 은 개방) | 승인 없음 FAIL / 참조 승인 PASS / bastion 대상 FAIL | 동일 |
| 12-two-enis | 다른 인스턴스의 legacy | app PASS / legacy FAIL | 동일 |
| 13-external-sg-attached | plan 밖 sg-… 부착 | UNKNOWN | UNKNOWN |
| 14-target-deleted | 대상 삭제 | FAIL | FAIL |
| 15-separate-rules-fixed | 별도 규칙으로 승인 출처만 | PASS + caveat | PASS |
| 17-unknown-value | EIP public_ip 참조 | UNKNOWN | UNKNOWN |
| 18-self-ref | self=true | 승인 없음 FAIL / "self" 승인 PASS | 동일 |
| 19-ipv6-approved | 2001:db8::/32 승인 | 정확 PASS / /33 승인 시 FAIL | 동일 |
| 20-icmp-only | icmp 전체 + ssh 승인 | PASS | PASS |
| 21-rdp-open | rdp 0.0.0.0/0 | ssh PASS, rdp FAIL | 동일 |
| 22-sg-rule-legacy | aws_security_group_rule 분할 | FAIL | FAIL |
| 00b + 승인 172.16.0.0/12 | 인터넷 전체 아님, 승인 밖 | FAIL (EXCESS+MISSING) | FAIL |

## 파이프라인 매트릭스 (`scripts/run_fixture_matrix.py`)

결과 표: `data/runs-sample/SUMMARY.md` (17 실행, 각 실행의 run.json/gate.json/verification.json/diff/PR 본문 포함).
핵심 행:

- `sg_baseline_cidr_split`: V1~V5 PASS, **V6 FAIL → BLOCK** (위험도 LOW 인데도 차단)
- `sg_two_groups_fix_app_only`: V1 PASS, V2 PASS(legacy 의 finding 은 기존 것), **V6 FAIL (aws_instance.app 범위)**
- `sg_baseline_external_prefix_list`: V6 UNKNOWN → **HOLD_FOR_HUMAN** (PASS 아님)
- `sg_baseline_ok_propose_low`: 검증 PASS, 위험도 LOW(상한 HIGH), LLM 제안 LOW → 최종 LOW → REPORT_ONLY
- `sg_baseline_truncated/garbage/wrong_schema`: GENERATION_FAILED, 후보 파일 없음
- `rule_based`: 정상 통과 (리터럴 치환)

자동 처리 시간(샌드박스, 사람 대기 없음): 1회 약 36초, 그중 plan 2회(init 포함) 약 34초. LLM 호출 시간(0.001초, mock)은 실제와 무관하다.

## 실행하지 못한 검증 (정직하게)

- V7 실제 AWS 실측, V8 실제 통신, apply, 복구 --execute, PR --execute, GitHub Actions 실행, 실제 LLM API, Terraform 1.16.1 재현.
- 위 항목은 `docs/STATUS.md` 의 "부분 구현" 에 필요한 조건과 함께 적었다.
