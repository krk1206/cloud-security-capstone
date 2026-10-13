# 패치 화이트리스트 v0.2 (A) ↔ 우리 코드가 실제로 막는 것 — 대조표 (2026-09-28, B)

A 가 `policy/patch-whitelist.md` v0.2 를 썼고(9/28), 같은 날 이 브랜치에는 이미 정책 파일 `policy/patch_policy.json`(sg-iam-v2) + Policy Validator + V5 + V6 가 돌아가고 있다. 둘이 따로 자랐으니 **항목마다 "어디서 막히나 / 같은가 / 다른가"** 를 적는다. 다른 것은 내가 고치지 않고 **팀 결정 항목**으로 뺐다 (정책은 사람이 바꾼다 — CLAUDE.md). 4주차 말 v1.0 고정 전에 이 표로 한 번에 정리하면 된다.

표기: ✅ 같음 · 🟡 부분(다른 계층에서 잡히거나 결과만 같음) · ❌ 다름(코드가 안 막거나 반대로 함)

## 1. 범위 규칙 (화이트리스트 3절)

| 화이트리스트 v0.2 | 우리 코드 | 판정 | 비고 / 제안 |
|---|---|---|---|
| 변경 파일: 시나리오 폴더 안 `.tf` 만 | `editable_file_globs: ["*.tf"]`, `protected_paths`(policy/tests/src/.github/…), Validator `path_editable/path_protected` | ✅ | |
| `variables.tf`, `provider.tf`, backend, lock 파일, 워크플로 금지 | `protected_file_names: provider.tf/versions.tf/backend.tf` + `.github/` 보호. **`variables.tf` 는 보호 목록에 없음** | 🟡 | 결정 A-4(변수 변경 금지)를 그대로 채택하면 `variables.tf` 를 protected_file_names 에, `variable`·`locals` 를 forbidden_block_changes 에 추가 → **결정 1** |
| 변경 리소스: finding 의 리소스 1개 (+ 같은 SG 를 가리키는 규칙 리소스) | `max_changed_resources: 3`, 타입 허용 목록(`allowed_change_resource_types`). "같은 SG" 조건은 V6 의 SG 모델(sgmodel)이 규칙→SG 로 묶어 계산하지만 V5 는 개수만 본다 | 🟡 | 실측(data/reviews 최신 38건): 리소스 2개가 바뀐 후보는 IAM 기만 2건(deceptive-inline-role-policy, unapproved-trust-policy-open)뿐이고 둘 다 이미 FAIL → 1개로 줄여도 통과 후보의 결과는 안 바뀜. **결정 2**: `max_changed_resources` 3 → 1(+규칙 리소스 예외) |
| plan action `update` 만. `create/delete/replace` 금지, `no-op` 만인 빈 패치 금지 | delete/replace: `allow_delete=false, allow_replace=false` (V5 + hard HIGH). **create: `allowed_create_resource_types` 에 SG 규칙 리소스 3종 허용**(inline → 별도 규칙 리소스로 옮기는 패치용). 빈 패치: Validator `diff_nonempty` + V5 WARN | 🟡 | 화이트리스트는 create 전면 금지. 실측: 현재 후보 38건 중 리소스를 새로 만드는 것 0건 → 금지로 바꿔도 결과 안 바뀜 → **결정 3** |
| 새 `resource/module/data/provider/terraform` 블록 금지 | terraform/provider: `forbidden_block_changes` ✅. 새 resource: 위 create 규칙. module: plan 에서 모듈 리소스가 새로 생기면 V5 위반 ✅. **data 블록 추가는 텍스트에서 안 봄**(`data "external"/"http"` 만 금지 토큰) | 🟡 | `data` 추가 자체를 막으려면 Validator 에 블록 개수 비교 추가 (작음). prefix list 를 data 로 끌어오는 우회(06)는 지금도 V6 가 잡는다 |
| `count/for_each/depends_on/lifecycle` 변경 금지 | count/for_each 는 주소가 바뀌어 V5 에서 removed+added 로 위반 ✅. depends_on/lifecycle 은 plan 값에 안 나와 **못 봄** | 🟡 | 텍스트 검사 1줄 추가 가능 (결정 필요 없음, C 의 V5 보강 과제) |
| 변수 추가·default 변경·변수 참조 도입 금지 (결정 4) | 안 막음. V5 는 실효 값만 비교하므로 변수를 거쳐도 결과 값이 허용 범위면 통과 | ❌ | **결정 1** 과 같은 항목. 참고: eval-a-probe-rule/02-var-default 는 규칙 기반 생성기가 "지원 안 함" 으로 끝냄(패치 없음) |
| 변경 규모: 리소스 1개, 속성 3개 이하, diff 30줄 이하 → 초과 시 차단 | 리소스 수는 위. 속성 수 제한 없음. 줄 수는 **차단이 아니라 위험도 +1** (`patch_lines_over_40`) | ❌ | 실측: 통과한 후보의 diff 는 최대 4줄, 전체 후보 최대 16줄 → 30줄 차단으로 바꿔도 결과 안 바뀜 → **결정 4**: 차단(화이트리스트) vs 감점(지금) |

## 2. Security Group 속성 규칙 (4절)

| 화이트리스트 v0.2 | 우리 코드 | 판정 | 비고 |
|---|---|---|---|
| `cidr_blocks/ipv6_cidr_blocks` 교체 — 교체 후 전부 승인 CIDR 의 부분집합, `0.0.0.0/0`·`::/0` 금지 | **V6 SG 오라클**: 실효 허용 대역(합집합) ⊆ 승인 출처. 0.0.0.0/1+128.0.0.0/1 도 잡음(01). V5 는 이 검사를 안 함 | 🟡 | 화이트리스트는 V5 에서 부분집합 검사(7절 6단계)를 요구. 우리는 V6 가 더 강하게 잡지만, "V5 도 검사" 로 이중화하려면 C 가 V5 에 `ipaddress` 부분집합 검사 추가 |
| `from_port/to_port` 범위 축소만 (확대 금지) | V6 는 "보호 서비스에 승인 밖 출처가 닿는가" 만 본다 → **승인 CIDR 에 대해 포트를 넓히는 패치는 안 잡힘** | ❌ | C 의 V5 보강 과제 1순위: before/after 규칙 짝짓기 후 포트 범위 ⊆ 검사 |
| `protocol` 축소만 (`-1` → tcp/udp) | 위와 같음 (V6 는 프로토콜을 서비스 기준으로만 봄) | ❌ | 같은 보강 |
| `description` 추가·수정 허용 | `core_attributes` 에 description 포함, V5 허용 속성 | ✅ | |
| 규칙 블록 삭제 허용, **등급 상한 Medium** | 삭제 = `ingress` 속성 변경으로 통과 → V6 `required_access`(필수 서비스 유지) 로 기능 파괴 탐지(breaks-required-delete-rule FAIL). **위험도 기준표에 '규칙 삭제 → 최소 MEDIUM' 항목 없음** | 🟡 | 기준표 v2 에 `rule_block_removed → medium floor` 추가 여부 → **결정 5** (B). 실측: 삭제 후보는 전부 V6 FAIL 이라 지금은 등급까지 안 감 |
| `prefix_list_ids` 추가·변경 금지 | V5 허용 속성(`ingress` 통째)이라 **V5 는 통과**. 실측(deceptive-prefix-list)은 새 리소스(`aws_ec2_managed_prefix_list`) 때문에 Validator 가 차단 → POLICY_BLOCKED. data 로 가져오면 V6 가 UNKNOWN/FAIL | 🟡 | V5 에 "before 에 없던 prefix_list_ids/security_groups/self 가 after 에 생기면 차단"(7절 7단계) 추가 — C 과제 |
| 참조 SG(`security_groups`)·`self=true` 추가 금지 | 위와 같음. V6 는 참조 SG 를 따라가 합산(18 self-ref FAIL) | 🟡 | 같은 보강 |
| 새 ingress/egress 블록 추가 금지 | V5 는 블록 수를 안 셈. V6 가 실효 대역으로 판정 | 🟡 | 같은 보강 (블록 짝짓기, 7절 5단계) |
| finding 방향이 아닌 규칙(egress) 변경 금지 | `egress_changed` 는 위험도 +1, 차단 아님 | ❌ | **결정 6**: 차단 vs 감점 |
| `vpc_id/name/name_prefix/tags/revoke_rules_on_delete` 변경 금지 | vpc_id/name/name_prefix 는 교체 유발 → `allow_replace=false` 로 차단 ✅. tags 는 허용 속성(**화이트리스트는 금지**) | 🟡 | **결정 7**: tags 변경 허용 여부 (지금 후보 중 tags 만 바꾸는 것 없음) |
| CIDR 를 변수 참조로 바꾸기 금지 | 결정 1 과 동일 | ❌ | |

## 3. 승인값 출처 (5절)

| 화이트리스트 v0.2 | 우리 코드 | 판정 |
|---|---|---|
| `policy/approved_cidrs.yaml` (전역 승인 CIDR + 금지 CIDR) | `policy/intent/<시나리오>.json` — 시나리오별 **승인 출처 + 보호 서비스 + 필수 접근**(V6·V8 이 같이 씀). 전체 인터넷 승인은 intent 로더가 거부 | ❌ 형식 다름 |

**결정 8**: 승인값 파일을 하나로. 제안: intent JSON 을 유지하고(필수 접근·보호 서비스가 있어야 V6/V8 이 됨) 화이트리스트 5절의 예시 값(샌드박스 VPC `10.0.0.0/16`, 운영자 `/32`)을 intent 로 옮긴다. `approved_cidrs.yaml` 을 따로 두면 두 파일이 어긋날 때 어느 쪽이 맞는지 정할 수 없다.

## 4. IAM (6절) — 초안끼리 비교

| 화이트리스트 v0.2 | 우리 코드 | 판정 |
|---|---|---|
| `Action:"*"`/`service:*` → 필수 권한 목록으로 교체 허용 (상한 Medium) | 규칙 기반 생성기가 그렇게 치환, V6 IAM 오라클이 Allow 문 Action×Resource ⊆ 승인 집합 검사, `medium_floor_conditions.iam_resource_touched` 로 최소 MEDIUM | ✅ |
| `Resource:"*"` → ARN 목록 허용 (상한 Medium) | 같음 (deceptive-resource-star 는 V6 FAIL) | ✅ |
| Effect/Principal/신뢰 정책 변경 금지 | `assume_role_policy` 변경 → Validator·V5 위반 + 기준표 hard HIGH | ✅ |
| 새 정책·관리형 정책 연결/해제·역할 생성 금지 | IAM 타입은 `allowed_create_resource_types` 에 없음 → 위반 (unapproved-managed-policy POLICY_BLOCKED) | ✅ |
| Condition 추가 보류 | V6 는 Condition 있으면 UNKNOWN → PENDING(사람) | ✅ |
| 초기 실효 판정 = TerraProbe 부록 B 방식(`*` 잔존 세기) | 우리는 더 강한 방식(Tier 1 집합 포함 검사)이 이미 있음. 부록 B 식 계수기는 없음 | 🟡 발표용으로 "부록 B 식 계수 + 우리 오라클" 둘 다 보여줄지 결정 |

## 5. V5 구현 지침 (7절) 과 우리 V5

지침 8단계 중 우리 `verify/layers.py v5_plan_diff` 가 하는 것: 1(변경 항목 수집) ✅, 2(리소스 수·주소) 🟡(개수만), 3(update 만) 🟡(delete/replace 차단, create 는 규칙 리소스 허용), 4(허용 속성) ✅, 5(블록 짝짓기) ❌, 6(CIDR 부분집합) ❌(V6 가 함), 7(prefix_list/참조/self 신규) ❌, 8(출력 형식) 🟡(LayerResult PASS/FAIL/WARN + details).
→ **C 의 V5 과제는 "새로 짜기" 가 아니라 5·6·7 단계 보강** 이다. 기존 함수에 규칙 블록 짝짓기 한 단계를 넣으면 세 개가 한 번에 된다. 회귀 fixture 는 `tests/fixtures/plans/` 에 실제 plan 23+14개가 있다.

## 6. 팀 결정 항목 (v1.0 고정 전)

| # | 항목 | 지금 코드 | 화이트리스트 | 실험 결과에 영향 |
|---|---|---|---|---|
| 1 | 변수 변경(variables.tf·variable/locals 블록) | 허용 | 금지 | 없음 (정상 후보 중 변수 바꾸는 것 0) |
| 2 | 변경 리소스 수 | ≤3 | 1 (+같은 SG 규칙) | 없음 |
| 3 | 규칙 리소스 신규 생성(create) | 허용 (3종) | 금지 | 없음 (실측: 리소스를 새로 만드는 후보 0건) |
| 4 | diff 규모 초과 | 위험도 +1 | 차단 | 없음 |
| 5 | 규칙 블록 삭제의 등급 상한 | 없음(V6 가 대부분 FAIL) | Medium | 없음 |
| 6 | finding 방향 아닌 규칙(egress) 변경 | 위험도 +1 | 차단 | 없음 (실측: egress 바꾸는 후보 0) |
| 7 | tags 변경 | 허용 | 금지 | 없음 (실측: tags 바꾸는 후보 0) |
| 8 | 승인값 파일 | intent JSON | approved_cidrs.yaml | 형식 통일 필요 |

결정이 나면 `policy/patch_policy.json` 의 `policy_version` 을 올리고(sg-iam-v3), 실험 4세트를 다시 돌려 `results-history` 에 남긴다 (기록 재사용 지문에 정책 파일이 들어 있어 자동으로 다시 돈다).
