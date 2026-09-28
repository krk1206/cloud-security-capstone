# 패치 화이트리스트 (허용되는 Terraform 변경 유형)

버전: v0.2 (2026-09-28, 결정 1~4 반영). 4주차 말에 v1.0으로 고정하고, 이후 실험 결과를 보고 바꾸지 않는다. 바꿔야 하면 버전을 올리고 사유를 기록한다.
담당: A(정의), C(Policy Validator 구현, V5), B(Risk Rubric 입력, 패치 생성 프롬프트 제약).

---

## 1. 목적

AI 또는 규칙 기반 생성기가 만든 패치가 손댈 수 있는 범위를 사전에 정한다. 이 범위를 벗어난 변경은 위험도 등급이나 AI 확신도와 관계없이 차단한다.
검사 시점은 V5(plan JSON 차이 검사)이며, 소스 diff 수준의 범위 규칙은 V3 이전에 함께 확인한다.

## 2. 원칙

1. 패치는 지목된 finding이 가리키는 리소스만 바꾼다.
2. 리소스를 만들거나 지우거나 교체하지 않는다. 기존 리소스의 속성 갱신(update)만 허용한다.
3. 허용값(승인 CIDR, 필요 권한)은 사람이 관리하는 정책 파일에서만 온다. 생성기는 값을 지어내지 못한다.
4. 화이트리스트에 없는 변경은 어떤 경우에도 통과하지 않는다. 경계선에 있으면 차단이다.

## 3. 범위 규칙 (모든 유형 공통)

| 항목 | 허용 | 금지 |
|---|---|---|
| 변경 파일 | finding이 있는 시나리오 폴더 안의 .tf | 그 외 모든 경로, variables.tf, provider.tf, backend 설정, .terraform.lock.hcl, 워크플로우 파일 |
| 변경 리소스 | Evidence Bundle의 `CauseMetadata.Resource`에 적힌 리소스 1개. 그 리소스에 속한 규칙 리소스(`aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`)는 같은 SG를 가리킬 때만 포함 | 그 외 리소스 |
| plan action | `update`만 | `create`, `delete`, `replace`(delete+create), `no-op`만 있는 빈 패치 |
| 구조 요소 | 없음 | 새 `resource`, `module`, `data`, `provider`, `terraform` 블록 추가. `count`, `for_each`, `depends_on`, `lifecycle` 변경 |
| 변수 | 없음 | 변수 추가, `default` 값 변경, 변수 참조 도입 전부 금지. 리소스 속성을 직접 바꾼다 (v1.0에서 재검토) |
| 변경 규모 | 변경 리소스 1개, 변경 속성 3개 이하, 소스 diff 30줄 이하 | 초과 시 차단 (패치를 만들지 않고 Low 등급 리포트만 생성) |

## 4. Security Group 속성 규칙

대상 리소스: `aws_security_group`(inline ingress/egress), `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, `aws_vpc_security_group_egress_rule`.

| 속성 | 허용되는 변경 | 조건 |
|---|---|---|
| `cidr_blocks` / `ipv6_cidr_blocks` (finding이 가리키는 방향의 규칙) | 값 교체 | 교체 후 모든 CIDR이 정책 파일의 승인 CIDR에 포함(부분집합)되어야 함. `0.0.0.0/0`, `::/0` 금지 |
| `from_port` / `to_port` | 범위 축소 | 새 범위가 기존 범위 안에 있어야 함. 확대 금지 |
| `protocol` | 축소 | `-1`(all) → `tcp` 또는 `udp`만 허용. 반대 방향 금지 |
| `description` | 추가 또는 수정 | 없음 |
| 규칙 블록 삭제 (해당 ingress 블록 통째로 제거) | 허용 | 등급 상한 Medium (기능 영향 가능, V8로 확인) |

금지 (finding의 방향과 무관하게):

| 변경 | 금지 이유 |
|---|---|
| `prefix_list_ids` 추가 또는 변경 | 허용 대역을 CIDR 밖으로 옮기는 우회 통로. 사전 실험 06 케이스 |
| `security_groups`(참조 SG) 추가, `self = true` 추가 | 허용 범위가 다른 리소스에 숨는 우회 통로. 사전 실험 08 케이스와 같은 구조 |
| 새 ingress/egress 블록 추가 | 리소스 추가와 같은 효과 |
| finding 방향이 아닌 규칙 변경 (ingress finding인데 egress 수정) | 범위 밖 |
| `vpc_id`, `name`, `name_prefix`, `tags`, `revoke_rules_on_delete` | 보안 개선과 무관. diff를 최소로 유지 |
| CIDR 값을 변수 참조로 바꾸기 | 변수 관련 변경은 3절에서 전부 금지. 실효 값은 plan JSON으로 확인 |

주의: `cidr_blocks` 교체는 허용 형태이므로 `0.0.0.0/1` + `128.0.0.0/1`(사전 실험 01 케이스)은 이 표만으로는 잡히지 않는다. 승인 CIDR 부분집합 검사에서 걸리거나, 최종적으로 V6(Intent Oracle)의 합집합 계산이 잡는다. 이 표는 V6를 대체하지 않는다.

## 5. 승인값 출처

`policy/approved_cidrs.yaml` (사람이 관리, PR로만 변경)

    version: 1
    approved_cidrs:
      - cidr: "10.0.0.0/16"
        purpose: "샌드박스 VPC 내부"
      - cidr: "203.0.113.10/32"
        purpose: "운영자 접속 출발지 (예시 값, 실제 IP로 교체)"
    # V8 구축 시 추가: 라즈베리파이(승인된 출발지)의 공인 IP/32
    forbidden_cidrs:
      - "0.0.0.0/0"
      - "::/0"

규칙: 패치의 각 CIDR은 `approved_cidrs` 중 하나에 부분집합으로 포함되어야 한다. 포함되는 항목이 없으면 패치를 만들지 않고 Low 등급 리포트만 낸다("승인된 출발지 정보 없음"을 사유로 기록).

## 6. IAM (초안, 7주차에 확정)

대상: `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`의 정책 문서.

| 변경 | 허용 여부 |
|---|---|
| `Action: "*"` 또는 `service:*`를 `policy/required_permissions.yaml`에 있는 목록으로 교체 | 허용 (등급 상한 Medium) |
| `Resource: "*"`를 정책 파일의 ARN 목록으로 교체 | 허용 (등급 상한 Medium) |
| `Effect`, `Principal`, 신뢰 정책(`assume_role_policy`) 변경 | 금지 |
| 새 정책 생성, 관리형 정책 연결/해제, 역할 생성 | 금지 |
| Condition 추가 | 보류 (7주차 판단) |

필요 권한 목록을 정의할 수 없는 경우 "IAM은 무조건 사람 승인"으로 대체한다(계획서 명시).
IAM 실효 판정의 초기 버전은 선행 연구(TerraProbe) 부록 B의 방식을 따른다: plan JSON의 정책 문서에서 `Resource` 또는 `Action`에 `*`가 남아 있는 Statement 수를 세고, 0이 아니면 보류.

## 7. V5가 확인하는 방법 (구현 지침, C)

입력: `terraform show -json tfplan` 결과의 `resource_changes[]`, Evidence Bundle의 대상 리소스 주소, 정책 파일.

1. `resource_changes`에서 `change.actions`가 `["no-op"]`이 아닌 항목만 모은다.
2. 그 항목이 정확히 1개이고 `address`가 대상 리소스(또는 같은 SG의 규칙 리소스)인지 확인한다. 아니면 차단.
3. `change.actions`가 `["update"]`인지 확인한다. 아니면 차단.
4. `change.before`와 `change.after`를 비교해 값이 달라진 속성 목록을 만든다. 목록의 모든 속성이 4절의 허용 속성이어야 한다. 아니면 차단.
5. ingress/egress는 집합이므로, 규칙 블록 단위로 before와 after를 짝지어 비교한다. 짝이 없는 새 블록이 after에 있으면 차단(새 규칙 추가).
6. 바뀐 `cidr_blocks`의 각 항목이 승인 CIDR의 부분집합인지 `ipaddress` 모듈로 확인한다. 아니면 차단.
7. `prefix_list_ids`, `security_groups`, `self`가 before에 없다가 after에 생겼으면 차단.
8. 결과는 `{"verdict": "PASS"|"BLOCK", "reasons": [...]}`로 출력하고 종료 코드 0/1. 입력 오류는 2.

## 8. 위험도 등급과의 관계

이 표는 통과/차단만 정한다. 통과한 패치의 등급은 Risk Rubric이 정한다. 참고용 상한:

| 통과한 변경 | 등급 상한 |
|---|---|
| SG 규칙 1개의 CIDR 교체 또는 포트 축소 | High |
| SG 규칙 블록 삭제 | Medium |
| IAM 정책 문서 변경 | Medium |

## 9. 이 표가 막는 사전 실험 케이스

| 케이스 | 어디서 막히나 |
|---|---|
| 01 cidr-split (0.0.0.0/1 + 128.0.0.0/1) | 이 표로는 안 막힘. 승인 CIDR 부분집합 검사 또는 V6 |
| 06 prefix-list | 4절 금지: `prefix_list_ids` 추가 |
| 08 second-sg | 3절 금지: 리소스 추가(create) |
| 02 var-default | 패치 형태로는 3절 금지(변수 변경)로 차단. 원 코드가 변수를 쓰는 경우 실효 값은 plan JSON으로 확인 |
| 03 string-build, 04 dynamic | 값이 plan JSON에서 확정되므로 V5의 실효 값 비교. 소스 문자열은 보지 않음 |

## 10. 결정 기록 (2026-09-28, A)

| 번호 | 결정 | 결과 | 사유 |
|---|---|---|---|
| 1 | 변경 규모 상한 | 리소스 1개, 속성 3개, diff 30줄 | 첫 버전은 작게. 실험 중 필요하면 v1.1에서 조정 |
| 2 | 규칙 블록 삭제 허용 여부 | 허용, 등급 상한 Medium | 규칙 제거도 정당한 수정. 기능 영향은 V8이 확인 |
| 3 | 승인 CIDR의 실제 값 | 샌드박스 VPC CIDR + 운영자 출발지 IP/32. 라즈베리파이 공인 IP는 V8 구축 시 추가 | 현재 확정 가능한 값만 |
| 4 | 변수 기본값 변경 허용 여부 | 금지 | 변수 경유 값은 스캐너가 `--tf-vars` 없이 못 읽는 것을 사전 실험에서 확인. 첫 버전은 직접 속성 변경만 허용해 검증을 단순하게 유지 |
