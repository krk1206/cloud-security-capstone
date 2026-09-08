# Trivy IaC 스캐너 — Security Group 기만적 패치 탐지 실측

- 스캐너: `trivy config` / **Trivy v0.74.0** (checks bundle: 스캔 시점 최신)
- 실행일: 2026-09-08 / 환경: WSL2 Ubuntu 24.04.3 LTS
- 스캔 방식: 디렉터리 **개별** 스캔 — `trivy config cases/<name> --format json --output results/<name>.json`
- 원본 JSON: `results/<name>.json` (FAIL 0건인 케이스 포함 전부 보존)
- 판정 기준 룰: **AWS-0107** — *Security groups should not allow unrestricted ingress to SSH or RDP from any IP address* (HIGH)

## 결과 표

| 케이스 | FAIL 개수 | 검출된 룰 ID 전체 | 22번 포트 공개개방 룰(AWS-0107) 검출 |
|---|---|---|---|
| 00-baseline | 1 | AWS-0107 | **Y** |
| 01-cidr-split | 0 | (없음) | **N** |
| 02-var-default | 1 | AWS-0107 | **Y** |
| 03-string-build | 1 | AWS-0107 | **Y** |
| 04-dynamic | 2 | AWS-0107, AWS-0124 | **Y** |
| 05-separate | 4 | AWS-0104, AWS-0107, AWS-0124 x2 | **Y** |
| 06-prefix-list | 0 | (없음) | **N** |
| 07-ipv6-only | 1 | AWS-0107 | **Y** |
| 08-second-sg | 3 | AWS-0028, AWS-0107, AWS-0131 | **Y** |

> FAIL 개수는 해당 디렉터리에서 나온 **모든** misconfiguration FAIL의 합계다. AWS-0104(무제한 egress), AWS-0124(rule description 누락), AWS-0028(IMDSv2), AWS-0131(EBS 미암호화)은 22번 포트 개방과 무관한 부수 검출이므로, 판정은 AWS-0107 컬럼만 본다.

## 케이스별 AWS-0107 검출 위치

| 케이스 | 기법 | AWS-0107 지목 리소스 | 라인 |
|---|---|---|---|
| 00-baseline | ingress cidr_blocks = ["0.0.0.0/0"] (기준선) | `aws_security_group.baseline` | 14 |
| 01-cidr-split | cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"] | — (미검출) | — |
| 02-var-default | variable "cidr" default = ["0.0.0.0/0"] → var.cidr | `aws_security_group.var_default` | 19 |
| 03-string-build | locals { open = join("/", ["0.0.0.0","0"]) } → [local.open] | `aws_security_group.string_build` | 18 |
| 04-dynamic | dynamic "ingress" (var: [{port=22, cidr="0.0.0.0/0"}]) | `aws_security_group.dynamic_rules` | 28 |
| 05-separate | SG는 inline ingress 없음 + aws_vpc_security_group_ingress_rule | `aws_vpc_security_group_ingress_rule.ssh_open` | 19 |
| 06-prefix-list | aws_ec2_managed_prefix_list(0.0.0.0/0) → prefix_list_ids | — (미검출) | — |
| 07-ipv6-only | cidr_blocks=["10.0.0.0/8"] + ipv6_cidr_blocks=["::/0"] | `aws_security_group.ipv6_only` | 15 |
| 08-second-sg | app SG는 10.0.0.0/8, legacy SG는 0.0.0.0/0, 인스턴스에 둘 다 부착 | `aws_security_group.legacy` | 27 |

## 5단계 — 결론

**00-baseline 대비 FAIL(AWS-0107)이 사라진 케이스: 01-cidr-split, 06-prefix-list**
