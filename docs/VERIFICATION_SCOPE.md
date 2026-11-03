# 검증 범위 표 — 무엇을, 어떤 입력으로, 어떻게 판정하고, 어떻게 따로 확인하나 (2026-11-02, D-41)

검토 문서(11-02) 지적: "지원 리소스 · 문법 목록 · 변형 축(CIDR 분할 · 겹침, IPv4/IPv6, 포트 범위, 보안 그룹 여러 개, 참조) · IAM 의 지원 · 미지원 요소를 **코드 기준으로** 적고, 변형 수를 커버리지처럼 말하지 말 것. Trivy 가 못 본 것은 구체적으로."

원칙: 이 표의 모든 줄은 코드(docstring · 함수)와 단위 시험 이름으로 근거를 적는다. 시험이 없는 줄은 '시험 없음' 이라고 쓴다.
"변형 N개" 는 그 변형들을 돌려 봤다는 뜻일 뿐, 그 밖의 입력까지 보장한다는 뜻이 아니다. 지원 밖 입력은 PASS 가 아니라 **판정 불가(UNKNOWN)** 로 끝나야 하고, 그것도 시험으로 확인한다.

## 1. 추적 사슬 — 요구사항 · 규칙 → 검사 대상 → 분석 방식 → 입력 증거 → 판정 → 독립 확인

| 계층 | 요구사항 · 규칙 (어디서 왔나) | 검사 대상 | 분석 방식 | 입력 증거 (기록 폴더 `data/reviews/<id>/`) | 판정 값 | 독립 확인 방법 (프로그램 없이) |
|---|---|---|---|---|---|---|
| V1 기존 문제 해결 | Trivy 규칙 id (policy/patch_policy.json `supported_target_rules`: AVD-AWS-0107 · 0345 · 0342) | 수정안 폴더 | `trivy config` 재실행 → 대상 규칙 · 리소스의 지적이 사라졌나 | `input/trivy-after.json`, `verification.json` V1 | PASS / FAIL | 같은 Trivy 0.74.0 으로 `trivy config <수정안 폴더>` 를 직접 돌려 같은 id 가 없는지 |
| V2 새 보안 문제 | Trivy 전체 체크 (0.74.0 내장 번들) | 수정안 폴더 | 원본 보고서에 없던 CRITICAL · HIGH 지적이 생겼나 (`v2_block_severities`) | `input/trivy-before.json` · `trivy-after.json` | PASS / FAIL | 두 보고서의 지적 id · 리소스를 비교 |
| V3 코드 작성 오류 | Terraform 문법 | 수정안 폴더 | `terraform fmt -check` · `terraform validate` | `verification.json` V3 (명령 · 종료 코드 · 출력) | PASS / FAIL / ERROR | 같은 Terraform 1.16.1 로 직접 실행 |
| V4 변경 예정 계산 | Terraform | 수정안 폴더 | `terraform plan -out` (오프라인: provider 캐시 · refresh 없음) → `show -json` | `input/plan.json` (수정안) · 원본 plan | PASS / FAIL / ERROR | plan 을 직접 돌려 `resource_changes` 비교 |
| V5 수정 허용 범위 (정책) | 팀 정책 `policy/patch_policy.json` (sg-iam-v2) | 원본 plan ↔ 수정안 plan 의 차이 | 바뀌는 리소스 종류 · 수 · 속성 · 삭제 · 교체 · 금지 토큰 · 보호 파일 | `policy.json` (위반 목록) · 두 plan | PASS / BLOCKED | 정책 파일의 허용 목록과 plan 차이를 손으로 대조 |
| V6 고객 설계 일치 (SG) | 고객 설계도 (③, 버전 · 지문 · 확정 상태 — D-30 · D-38) | 수정안 plan 의 보안 그룹 · 부착 지점 | §2 의 토폴로지 오라클 | `input/design.json` (검사 당시 설계도 사본 + sha256), `verification.json` V6 (flows · excess · undesigned) | PASS / FAIL / UNKNOWN | 설계도 표와 plan 의 ingress 규칙을 손으로 대조 (부착 지점별 합집합) |
| V6 고객 설계 일치 (IAM) | IAM 요구사항 파일 (버전 · 지문 · 확정 — D-40) | 대상 정책 + 대상 역할에 붙는 정책 | §3 의 IAM 오라클 (Allow 문의 Action × Resource 집합 ⊆ 승인 집합, 필수 권한 유지) | `input/design.json`, `verification.json` V6 | PASS / FAIL / UNKNOWN | 정책 JSON 의 Allow 문을 승인 표와 대조 |
| 자체 보안 그룹 검사 (④ '자체 검사') | AWS Security Hub EC2.19 blockedPorts + 관리 포트 22 · 3389 (`verify/sg_scan.py` docstring, 2026-11-01 확인) | 원본 · 수정안 plan | §2.3 | `impact` 의 `sg_new` · `sg_resolved` · `sg_remaining` | 문제 목록 (심각도) | 규칙의 IP 대역 합집합을 손으로 계산 |
| 위험도 (등급) | `policy/risk_rubric.json` (RISK_RUBRIC_V2) | V4 · V5 결과 | 결정론 점수표 — AI 가 자기 등급을 정하지 않음 | `risk.json` | LOW / MEDIUM / HIGH (+ 검토 수준) | 점수표에 손으로 대입 |
| V7 시험 환경 적용 확인 | 설계도 (V6 과 같은 오라클) | AWS 시험 환경의 실제 보안 그룹 (describe-security-groups · ENI 의 SG 합산 · prefix list 전개) | V6 과 **같은 오라클**에 실측값을 넣음 | `postdeploy/<시각>/` (AWS 응답 원문 · 판정) | PASS / FAIL / UNKNOWN | AWS 콘솔 · CLI 로 같은 보안 그룹을 조회 |
| V8 시험 환경 연결 시험 | 설계도의 허용 통신 · 승인 밖 출처 | 시험 환경에서 실제 연결 시도 | 허용 통신은 열리고 승인 밖 출처는 막히나 — 승인 밖 관측 지점이 없으면 UNKNOWN | `postdeploy/<시각>/measure.json` | PASS / FAIL / UNKNOWN | 관측 지점에서 직접 접속해 봄 |

배포 전(V1~V6)은 코드만 본다 — **배포 성공이 아니다**. V7 · V8 은 AWS 시험 환경(샌드박스)에서 한 것이고 운영 반영 후 확인이 아니다 (D-39 세 단계 띠).

## 2. 보안 그룹 — 지원 문법 · 변형 축 (코드 기준)

### 2.1 plan 에서 읽는 것 (`verify/plan_model.py` docstring)

| 항목 | 지원 | 비고 · 시험 |
|---|---|---|
| `aws_security_group` inline `ingress` / `egress` | 지원 | `test_oracle_fixtures` (A 의 probe 사례 01~07) · `test_topology_oracle` · `test_sg_scan` |
| `aws_vpc_security_group_ingress_rule` / `_egress_rule` | 지원 (cidr_ipv4 · cidr_ipv6 · prefix_list_id · referenced_security_group_id) | 같음 |
| `aws_security_group_rule` (구형) | 지원 (type 속성으로 방향) | 같음 |
| `aws_ec2_managed_prefix_list` | 같은 plan 안에 선언된 것만 전개. 외부 `pl-…` id 는 전개 못 함 → **UNKNOWN** | `test_topology_oracle.test_unknown_source_is_not_pass` |
| 부착 지점 (보안 그룹이 붙는 리소스) | `aws_security_group` 을 참조하는 managed 리소스 전부 (instance · ENI · launch template · RDS · Lambda 등) + `aws_network_interface_sg_attachment` | 한 리소스에 여러 보안 그룹 → **실효 규칙 = 합집합** (`test_extra_sg_attached_to_tier_is_merged`) |
| 자식 모듈 | planned_values 는 읽음. 참조 해석(configuration.expressions)은 **루트 모듈만** → 자식 모듈의 미확정 값은 UNKNOWN | 시험: 미확정 → UNKNOWN 경로만 (`test_unresolved_source_means_undecided_not_broken`) |
| 미확정 값 (`after_unknown`) | 참조로 **모호하지 않게** 풀리는 경우만 채움. 모호하면 UNKNOWN (PASS 아님). inline 블록 전체가 미확정이고 소스 HCL 에 ingress 선언이 없으면 'provider computed' 로 기록 | `test_two_unknown_sg_slots_matched_by_source_block` · `test_no_unique_match_stays_unknown` · `test_without_source_stays_unknown` |
| 프로토콜 | `-1`/all, tcp · udp(이름 · 번호), icmp · icmpv6 (`verify/sgmodel.PROTOCOL_ALIASES`) | 그 밖의 번호는 소문자 문자열 그대로 — 설계 통신과 이름이 다르면 덮지 못해 위반으로 나옴 (시험 없음) |

### 2.2 설계도 비교 (V6 토폴로지 오라클, `verify/topology_oracle.py`)

| 변형 축 | 처리 | 시험 |
|---|---|---|
| CIDR 분할 · 겹침 · 순서 | 같은 (프로토콜, 포트 범위)로 들어오는 IPv4 대역의 **합집합**(`verify/netset.NetSet`, 인접 · 겹침 합치기) 을 구한 뒤 설계도의 허용 외부 대역을 빼고 남는 부분이 있으면 위반. `0.0.0.0/1 + 128.0.0.0/1` 도 인터넷 전체로 잡힘 | `test_netset` 9건 (분할 · 4분할 · 순서 섞임 · 겹침 · 차집합 · 호스트 비트 거절), `test_split_cidrs_are_unioned` |
| IPv4 / IPv6 | 별도 집합 (섞지 않음). 설계도는 IPv4 대역만 적는다(`cidrs_v4`). IPv6 출발지는 설계도가 그 포트에 **인터넷 전체(0.0.0.0/0)** 를 허용했을 때만 인터넷으로 보고, 그 밖에는 위반 | `test_netset.test_ipv6_separate` · `test_split_by_version`; 보안 그룹 형식 오라클은 `test_oracle_fixtures.test_07_ipv6_open`; 토폴로지 오라클의 IPv6 분기는 단위 시험이 없고 **실측 기록**만 (`bastion-ipv6-open`, 2026-10-23: V1 FAIL · V6 FAIL — `experiments/candidate-sets/arch-3tier-sg/RESULTS_2026-10-23_pc.md`) |
| 포트 범위 | 규칙의 범위 **전체**를 덮는 설계 통신이 있어야 함 (설계 3306, 규칙 0-65535 → 위반). `-1`/icmp 는 전체 범위로 봄 | `test_all_ports_from_designed_source_is_excess` |
| 보안 그룹 여러 개 | 부착 지점 기준 합집합 (계층의 보안 그룹 + 추가로 붙은 보안 그룹) | `test_extra_sg_attached_to_tier_is_merged` |
| 참조 출발지 (sg · self) | 참조 보안 그룹이 붙은 계층 → 그 계층 → 대상 통신이 설계도에 있나. 설계도의 어느 계층에도 없는 리소스에 붙은 보안 그룹이면 '설계 외 서버' 위반. **참조 SG 의 인바운드를 상속하지 않음** | `test_removing_redis_from_design_flags_api_to_redis` · `test_undesigned_*` |
| VPC 안 IP 대역 출처 | 'VPC 안 모든 서버' — 어느 계층인지 구분 못 하므로 계층 간 통신을 IP 대역으로 연 것은 위반 | `test_private_range_breaks_admin_access_and_opens_vpc` · `test_db_opened_to_vpc_is_caught_even_though_api_still_works` |
| 설계도에 있는데 막힘 (필수 통신) | 서비스 경로 · 관리자 접속이 끊기면 FAIL (broken) | `test_removed_rule_breaks_service_path` · `test_single_admin_ip_breaks_other_admins` |
| 설계도에 없는 리소스 | 들어오는 허용이 있으면 FAIL, 없으면 기록만 | `test_undesigned_resource_open_to_internet` · `test_undesigned_resource_without_inbound_is_only_a_note` |
| 설계도 구성요소가 코드에 없음 | 기록 (`test_design_component_missing_in_code`) | |
| 보지 않는 것 | **egress**, NACL, 라우팅, 공인 IP, 서비스가 포트를 실제로 여는지 — ⑥ '확인하지 않은 것' 에 적는다 (`web/problems.unchecked`) | `test_result_screen` (unchecked 문장) |

### 2.3 자체 보안 그룹 검사 (`verify/sg_scan.py`, 설계도 없이)

종류: `mgmt_public`(22 · 3389 인터넷 전체) · `highrisk_public`(EC2.19 목록 포트) · `all_ports_public` · `split_any`(분할 대역 합치면 인터넷 전체) · `ipv6_any`(::/0) · `vpc_wide`(VPC 대역 → 고위험 포트, 주의) · `undecidable`(출처 미확정 → 판정 불가). 443 같은 목록 밖 포트는 세지 않는다 — 공개 입구인지는 V6 가 판단. 시험: `test_sg_scan`.

### 2.4 Trivy(0.74.0 내장 체크)가 보지 못하고 이 프로그램만 보는 것 — 구체적으로

④ 화면의 'Trivy 는 못 봄' 은 **같은 코드의 Trivy 보고서와 대조해** 프로젝트마다 계산한 값이다 (추정이 아님). 지금까지 실측한 종류:

| 이 프로그램이 찾는 것 | Trivy 가 못 보는 이유 (실측) |
|---|---|
| 분할 대역 합치면 인터넷 전체 (`split_any`) | Trivy 는 `0.0.0.0/0` 만 본다 — 0.0.0.0/1 + 128.0.0.0/1 은 지적 없음. 실측: 수정안 `bastion-cidr-split` (2026-10-23 PC) V1 PASS · V2 PASS(Trivy 새 지적 없음) · **V6 FAIL** (`RESULTS_2026-10-23_pc.md` 기록 20261023-133512-8c9485); A 의 probe 사례 `01-cidr-split` 도 Trivy `not_triggered` |
| VPC 대역 전체 → DB 포트 (`vpc_wide`, 설계 위반) | 사설 대역은 Trivy 규칙 대상이 아님. 실측: 주문 서비스 예제(E2E proj) 10.20.0.0/16 → 5432 가 ④ 'Trivy 는 못 봄' 1건 |
| 설계도에 없는 통신 · 설계도에 있는데 막힌 통신 (V6) | 고객 설계라는 입력이 Trivy 에 없음. 실측: 3계층 예제 ④ 'Trivy 는 못 봄' 1건 = 웹 서버 → MySQL :3306 (설계에 없는 통신); 2계층 예제는 0건 |
| (참고) IPv6 `::/0` 로 SSH · RDP 를 연 것 | **Trivy 가 잡는다** (AVD-AWS-0107 은 IPv6 포함 — `bastion-ipv6-open` V1 FAIL). 이 프로그램만의 발견이 아니다 |
| IAM `"Action": "*"` 또는 `s3:Get*` 류 과다 권한 | AVD-AWS-0057 이 0.74.0 에서 deprecated(규칙 본문 없음). Trivy 는 `s3:*`(AVD-AWS-0345) · `iam:PassRole`(AVD-AWS-0342) 만 잡음 (`verify/iam_oracle.py` docstring, 실측 09-22) |

반대로 Trivy 가 보고 이 프로그램이 안 보는 것도 많다 (S3 · RDS 암호화 · 로그 등 175개 체크 중 대부분). ④ 는 그것을 '탐지만' 으로 표시한다 (`web/product.coverage`).

## 3. IAM — 지원 · 미지원 요소 (`verify/iam_oracle.py` Tier 1, docs/IAM_SCOPE.md)

| 지원 (판정함) | 미지원 (→ UNKNOWN, 자동 승인 금지) |
|---|---|
| 대상 정책 `aws_iam_policy` · `aws_iam_role_policy` · `aws_iam_user_policy` · `aws_iam_group_policy` 의 **Allow** 문 | Deny 문 |
| 대상 역할에 붙는 정책 (role_policy · policy_attachment(단일 참조) · managed_policy_arns 의 승인 목록) | NotAction / NotResource · Condition · Principal(리소스 정책) · 정책 변수 `${…}` · `?` 와일드카드 |
| Action × Resource 집합 ⊆ 승인 집합 (`*` 포함 판정: "s3:GetObject" ⊆ "s3:Get*", "s3:*" ⊄ "s3:Get*") · 필수 권한 유지 | plan 시점 미확정 policy · inline_policy · managed_policy_arns |
| Action 대소문자 무시 · Resource(ARN) 대소문자 구분 | AWS 관리형 정책의 **내용** (승인 ARN 목록에 있으면 허용, 내용은 읽지 않음) |
| 신뢰 정책: Principal `*`(또는 AWS:`*`) + Condition 없음 → FAIL | `aws_iam_policy_attachment` 의 roles 목록 · `*_exclusive` 류 · policy_arn 참조가 둘 이상 · JSON 중복 키 · 비ASCII 액션 |

시험: `test_iam_slice`, 교차검증 기록 `docs/CROSS_VERIFICATION_2026-09-22.md` (false PASS 8건을 막은 변경). 정책 범위(V5): `aws_iam_policy` 의 policy · description · tags, `aws_iam_role_policy` 의 policy, `aws_iam_role` 의 description · tags · max_session_duration 만 변경 허용 — assume_role_policy · inline_policy · managed_policy_arns 변경, 새 IAM 리소스 생성은 정책 위반.

## 4. 검증기가 실제로 잡는지 — 변이 시험 (실측 2026-11-02)

검토 문서 8항 "검증기 자체를 변이 시험으로 증명". 검증 코드를 일부러 망가뜨리고 단위 시험이 그것을 잡는지 봤다.

| 변이 (일부러 넣은 결함) | 결과 | 되돌림 |
|---|---|---|
| `verify/netset.NetSet` 의 대역 합치기(`ipaddress.collapse_addresses`)를 정렬만 하는 것으로 바꿈 → 분할 대역이 합쳐지지 않음 | 단위 시험 **14건 실패** — `test_netset` 5 · `test_fuzz` 2(무작위 입력 대조 포함) · `test_topology_oracle` 1 · `test_sg_scan` 1 · `test_intent` 1 · `test_postdeploy` 1(prefix list 전개) 등 | 원복 (511 OK) |
| 토폴로지 오라클의 '설계도에 있는데 막힘(필수 통신)' 판정 두 곳을 `if False` 로 막음 | 단위 시험 **9건 실패** — `test_topology_oracle` 5 (`test_removed_rule_breaks_service_path` · `test_single_admin_ip_breaks_other_admins` · `test_private_range_breaks_admin_access_and_opens_vpc` · `test_design_component_missing_in_code` · `test_unresolved_source_means_undecided_not_broken`) · `test_structure` 3 · `test_result_screen` 1 | 원복 (511 OK) |

재현: 해당 함수 본문을 바꾼 뒤 `python3 -m unittest discover -s tests/unit` (저장소 루트에서 `PYTHONPATH=src`). 실패 수가 0 이면 그 결함은 시험이 못 잡는 것이다.

## 5. 지원 밖 입력이 PASS 로 새지 않는지 (시험으로 확인한 것)

- 미확정 출처 · 외부 prefix list · 자식 모듈 참조 → UNKNOWN (`test_unknown_source_is_not_pass`, `test_unresolved_source_means_undecided_not_broken`)
- 설계도 없음 → V6 판정 불가, 승인 불가 (`test_projects`, E2E proj J-시리즈 '설계도 확정 전')
- 설계도 초안(확정 전) → 검사 통과여도 '고객 요구 충족' 아님 · 승인 불가 (`test_designs` 확정 시험, E2E proj L-시리즈, D-38)
- AWS 를 조회하는 `data` 소스가 있는 폴더 → plan 을 돌리지 않고 '지원 범위 밖' 으로 (E2E proj K1 · K2)
- 지원 밖 Trivy 규칙 → UNSUPPORTED_RULE 로 종료 (탐지만)

## 6. 아직 없는 것 (이 표에 넣지 않은 것)

- 토폴로지 오라클의 IPv6 출발지 분기(§2.2)의 단위 시험 — 실측 기록(10-23)만 있음. 추가하려면 `test_topology_oracle` 에 `::/0` 규칙 사례를 넣는다.
- 프로토콜 번호(예: 47 GRE)를 쓴 규칙의 시험 — 문자열 비교로 처리되며 시험 없음.
- egress · NACL · 라우팅 — 범위 밖 (설계 비교 · 자체 검사 모두 인바운드만).
