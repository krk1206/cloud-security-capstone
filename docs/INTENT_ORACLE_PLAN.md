# Intent Oracle (V6) 설계·테스트 계획 — 3~4주차 명세

> 상태 표기 규칙: **"명세"** 는 문서, **"구현"** 은 코드가 있고 단위 테스트가 통과한 것, **"실측"** 은 실제 A 의 plan/AWS 결과로 돌려본 것.
> 이번 3~4주차 필수 범위는 명세다. 코드는 지난 세션(2026-09-13)에 plan JSON fixture 기준으로 구현·테스트됐지만, **A 의 실제 plan(Terraform 1.16.1)이나 실제 AWS 상태로는 아직 돌려보지 않았다.** "계획만 있는 V6" 도 아니고 "완료" 도 아닌, "fixture 로 구현 확인" 단계다.

## 1. 입력 데이터 형식

| 입력 | 형식 | 출처 |
|---|---|---|
| 후보 plan JSON | `terraform show -json plan.bin` (format_version 1.x). `planned_values`, `resource_changes[].change.after_unknown`, `configuration.root_module.resources[].expressions` 를 쓴다 | A (또는 B 가 오프라인 plan) |
| 후보 HCL 텍스트 | `*.tf` | 실행 폴더 `candidate/` |
| Intent | JSON (아래) | 사람 |
| 외부 prefix list 전개 결과 (선택) | `{"pl-xxxx": ["cidr", ...]}` | A/V7 (`get-managed-prefix-list-entries`) |
| AWS 실측 (V7) | `describe-security-groups` + `describe-network-interfaces` + prefix list 전개 → 같은 모델(SGWorld) | A |

Intent JSON (`policy/intent/<scenario>.json`):

```json
{
  "intent_version": "1", "intent_id": "sg-baseline", "status": "active",
  "target_dir": "infrastructure/sg-baseline",
  "targets": {"security_groups": ["aws_security_group.vulnerable_ssh"], "attachment_points": []},
  "guarded_services": [
    {"label": "ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
     "approved_sources": {"cidrs_v4": ["<팀이 정한 CIDR>"], "cidrs_v6": [], "security_group_refs": [], "prefix_list_refs": []}},
    {"label": "rdp", "direction": "ingress", "protocol": "tcp", "from_port": 3389, "to_port": 3389,
     "approved_sources": {"cidrs_v4": [], "cidrs_v6": [], "security_group_refs": [], "prefix_list_refs": []}}
  ],
  "required_access": [
    {"label": "admin-ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "source_cidr": "<팀이 정한 CIDR>"}
  ]
}
```

## 2. 사람이 정하는 것

- **승인 출처**: 보호 서비스(예: tcp/22, tcp/3389)마다 허용할 IPv4 CIDR, IPv6 CIDR, 참조 SG(주소 또는 sg-ID, "self"), prefix list 참조. 코드는 절대 추측하지 않는다. 플레이스홀더(`__FILL_ME__`)가 남아 있거나 `status: draft` 면 사용 불가(INSUFFICIENT_INFO). 승인 출처가 인터넷 전체(0.0.0.0/0, ::/0)를 덮으면 intent 자체가 무효.
- **필수 접근**: 패치 후에도 반드시 열려 있어야 하는 (서비스, 출처 CIDR). "고치느라 필요한 접근까지 끊은" 패치를 잡는 기준.
- **대상 SG** 와 (선택) 부착 지점.

## 3. PASS · FAIL · UNKNOWN 의 뜻

대상 SG 마다, 부착 범위(같은 인스턴스/ENI 에 붙은 SG 들의 합집합; 없으면 SG 단독)마다, 보호 서비스마다:

| 판정 | 뜻 |
|---|---|
| **FAIL** | (a) EXCESS: 실효 허용 집합 − 승인 집합 ≠ ∅ (승인 밖 접근이 남아 있다), 또는 (b) MISSING: 필수 접근이 실효 허용 집합에 완전히 포함되지 않는다, 또는 (c) 대상 SG 가 plan 에 없다(삭제/이름 변경) |
| **UNKNOWN** | FAIL 은 아니지만 판단에 필요한 값을 모른다: plan 시점 미확정 값, 전개 불가 prefix list, plan 밖 SG 가 같은 ENI 에 붙음, 소스 HCL 없이 원소 수를 셀 수 없는 SG 목록, 자식 모듈 참조 미해석 → **자동 승인 금지** |
| **PASS** | 모든 보호 서비스가 승인 집합 안이고 필수 접근이 유지됐으며 UNKNOWN 이 없다 |

우선순위: FAIL > UNKNOWN > PASS. **"인터넷 전체를 덮지 않는다" 는 통과 기준이 아니다** — 승인 밖이면 FAIL 이다.

## 4. 지원하는 SG 규칙 범위 (명시)

| 지원 | 내용 |
|---|---|
| ✅ | `aws_security_group` inline `ingress`/`egress` (cidr_blocks, ipv6_cidr_blocks, prefix_list_ids, security_groups, self, protocol, from/to_port) |
| ✅ | `aws_vpc_security_group_ingress_rule` / `_egress_rule` (cidr_ipv4/ipv6, prefix_list_id, referenced_security_group_id, ip_protocol, ports) |
| ✅ | `aws_security_group_rule` (구형; type=ingress/egress) |
| ✅ | 같은 plan 안의 `aws_ec2_managed_prefix_list` 전개 (참조가 모호하지 않을 때) |
| ✅ | 부착 지점: `aws_instance.vpc_security_group_ids`, `aws_network_interface.security_groups`, `aws_network_interface_sg_attachment`, 그 밖에 SG 를 참조하는 managed 리소스 (launch template, RDS, Lambda 등은 참조 탐색으로만) |
| ✅ | 프로토콜 `-1`(전체), tcp/udp 포트 범위(전체·부분 겹침 구분), icmp/icmpv6 는 포트 비교 없음 |
| ⚠️ UNKNOWN | 외부 prefix list ID(전개 결과가 없을 때), plan 시점 미확정 CIDR(EIP 참조 등), 같은 ENI 의 plan 밖 sg-… , `var.x`/`concat()` 로 만든 SG 목록, 자식 모듈 참조 |
| ❌ 범위 밖 | NACL, 라우팅/IGW, 공인 IP 유무, 호스트 방화벽, 서비스 리스닝 — **SG 규칙상 허용 집합만 증명**한다. 실제 도달 가능성은 V8 |

**참조 SG 는 참조 대상 SG 의 인바운드 규칙을 상속하지 않는다.** `security_groups = [bastion]` 은 "bastion 이 붙은 ENI 에서 오는 트래픽" 이라는 별도 출처이며, 승인 목록(`security_group_refs`)에 없으면 EXCESS 다. bastion 자체의 개방 여부는 bastion 을 대상으로 따로 판정한다.

## 5. 테스트 계획 (케이스 → 기대 판정)

승인 출처 = 10.0.0.0/8, 필수 접근 = 10.0.0.0/8 → tcp/22 (테스트 값). 현재 구현 상태: ✅ = `tests/unit/test_oracle_fixtures.py` 에 fixture(OpenTofu 1.10.6 plan JSON)로 통과. **실측(A 의 Terraform 1.16.1 plan / AWS)은 전부 미완**.

| 유형 | 케이스 (tests/fixtures/src) | 기대 | 구현 |
|---|---|---|---|
| 취약 대조군 | 00-baseline (0.0.0.0/0) | FAIL | ✅ |
| 정상 수정 | 00b-baseline-fixed | PASS | ✅ |
| **CIDR 분할** | 01-cidr-split (0.0.0.0/1 + 128.0.0.0/1), 22-sg-rule-legacy(구형 리소스로 분할), 4분할(netset 단위 테스트) | FAIL (집합이 0.0.0.0/0 로 합쳐짐) | ✅ |
| 변형 | 02 변수, 03 문자열 조합, 04 dynamic, 05 별도 규칙 리소스 | FAIL | ✅ |
| **IPv6** | 07-ipv6-only (::/0), 19-ipv6-approved (승인 2001:db8::/32 정확/더 좁게) | FAIL / PASS·FAIL | ✅ |
| **다중 SG** | 08-second-sg (같은 인스턴스의 legacy 개방) → FAIL; 12-two-enis (다른 인스턴스) → app PASS, legacy FAIL; 13-external-sg-attached → UNKNOWN | ✅ |
| **prefix list** | 06-prefix-list (plan 내, 0.0.0.0/0) → FAIL; 외부 pl-ID → UNKNOWN; V7 전개(FakeCli) → 분할 entries 도 합쳐서 FAIL | ✅ |
| **SG 참조** | 11-sg-ref-source: 승인 없음 FAIL(bastion 규칙 미상속, 실효 v4 = ∅), 참조 승인 PASS, bastion 대상 FAIL; 18-self-ref | ✅ |
| 필수 접근 | 승인 밖 출처로 좁힘(172.16.0.0/12 승인 시 10.0.0.0/8 은 EXCESS+MISSING), ingress 제거(mock breaks_required) | FAIL | ✅ |
| 삭제 | 14-target-deleted | FAIL(대상 없음) | ✅ |
| 미확정 | 17-unknown-value (EIP) | UNKNOWN | ✅ |
| 포트/프로토콜 | 09 부분 범위(20-25), 10 protocol -1, 20 icmp 만 개방, 21 rdp 개방 | FAIL / FAIL / PASS / rdp FAIL | ✅ |

### 실측 계획 (이후 단계)

1. A 가 Terraform 1.16.1 로 `scripts/generate_fixtures.sh` 를 돌려 plan fixture 를 재생성 → OpenTofu 결과와 diff (판정 동일 여부).
2. `iacpatch review --candidate-plan <A 의 plan> --intent policy/intent/sg-baseline.json` 으로 V6 실측 (팀 승인 CIDR 필요).
3. 샌드박스 apply 후 `postdeploy --execute` 로 V7 — 06-prefix-list 가 실제 SG 에 반영되는지(README 부록 A) 확인.
4. 위 결과를 `docs/TEST_RECORD.md` 에 "실측" 으로 추가. 그 전까지 발표에서 V6 는 "fixture 로 구현 확인" 이라고만 말한다.
