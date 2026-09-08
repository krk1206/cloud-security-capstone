# 검증 기록 (A/B/C)

- 일시: 2026-09-08 22:18
- Trivy: Version: 0.74.0
- Terraform: Terraform v1.16.1

## 검증 C — terraform validate
```
01-cidr-split    valid
01b-control      valid
06-prefix-list   valid
```

## 검증 A - 룰이 실제로 실행됐는가

trivy config --include-non-failures 로 재스캔해 PASS 기록까지 확보.
전 케이스에서 룰 71개가 실행됨(통과+실패 합계 = 71).
Results 가 비어 있거나 통과 0인 케이스는 없음 -> 스캔 실패 가능성 배제.

| 케이스 | 통과 | 실패 | AWS-0107 | 지목 리소스 |
|---|---|---|---|---|
| 00-baseline | 70 | 1 | FAIL | aws_security_group.baseline |
| **01-cidr-split** | **71** | **0** | **PASS** | - |
| 01b-control | 70 | 1 | FAIL | aws_security_group.cidr_split |
| 02-var-default | 70 | 1 | FAIL | aws_security_group.var_default |
| 03-string-build | 70 | 1 | FAIL | aws_security_group.string_build |
| 04-dynamic | 69 | 2 | FAIL | aws_security_group.dynamic_rules |
| 05-separate | 68 | 4 | FAIL | aws_vpc_security_group_ingress_rule.ssh_open |
| **06-prefix-list** | **71** | **0** | **PASS** | - |
| 07-ipv6-only | 70 | 1 | FAIL | aws_security_group.ipv6_only |
| 08-second-sg | 68 | 3 | FAIL | aws_security_group.legacy |

01 과 06 에서 AWS-0107 이 Status=PASS 로 기록됨.
= 해당 룰이 파일을 검사했고 명시적으로 통과시켰다는 뜻.

## 검증 B - 최소 쌍 대조

01-cidr-split 을 복사해 CIDR 값 한 곳만 바꿔 01b-control 생성 (make_control.py).

변경 전 (01-cidr-split): cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"]
변경 후 (01b-control)  : cidr_blocks = ["0.0.0.0/0"]

두 CIDR 의 합집합은 0.0.0.0/0 과 수학적으로 동일하다.
python3 -c "import ipaddress as i; print(list(i.collapse_addresses([i.ip_network('0.0.0.0/1'), i.ip_network('128.0.0.0/1')])))"

| | 실패 | AWS-0107 |
|---|---|---|
| 01-cidr-split | 0 | PASS |
| 01b-control | 1 | FAIL |

파일 구조/리소스명/문법이 동일하고 CIDR 값만 다름.
-> 판정을 가른 원인이 CIDR 값임이 확정.

## 판정

| | 01-cidr-split | 06-prefix-list |
|---|---|---|
| A 룰 실행 | O | O |
| B 최소 쌍 | O | 해당 없음 |
| C 문법 유효 | O | O |
| **결론** | **우회 확정** | **정적 스캔 우회 후보** |

### 미확정 사항

- terraform validate 는 문법만 검증한다. 배포 후 실제 포트 개방 여부는 미확인.
- 06 은 prefix list 참조가 실제 SG 에 반영되는지 sandbox apply + describe-security-groups 로 확인 필요.
- LLM 이 이 패턴을 실제로 생성하는지는 측정하지 않았다. 본 실험은 탐지기 능력 측정이며, 자연 발생률 측정이 아니다.
