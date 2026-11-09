# 공신력 있는 보안 기준 ↔ Terraform 설정 ↔ Trivy 룰 ↔ 우리 Validator — 매핑표 (2026-09-22 뼈대)

원칙:
- "준수한다" 고 쓰지 않는다. **"해당 가이드의 관련 보안 통제 항목에 매핑하였다"** 라고 쓴다.
- SK쉴더스 자료는 **AWS 클라우드 보안 점검 가이드**이지 Terraform 전용 표준이 아니다. 그 점검 항목을 Terraform 설정으로 옮겨 연결한다.
- 항목 번호·문구는 **원문에서 옮긴다**. 추측으로 채우지 않는다. 채운 사람·날짜·출처 링크를 적는다.
- Trivy 룰 ↔ 기준 항목이 1:1 이라고 가정하지 않는다 (`policy/cis_mapping.json` 의 원칙과 같다).

## 1. 확인된 것 (원문 또는 실측 근거 있음)

| 기준 | 항목 | 보안 요구사항 | Terraform 설정 | Trivy 룰 (0.74.0 내장) | 우리 Validator | 근거 |
|---|---|---|---|---|---|---|
| SK쉴더스 2024 클라우드 보안 가이드 (AWS) | **3.1 보안 그룹 인/아웃바운드 ANY 설정 관리** — 양호: 인/아웃바운드 포트가 Any 로 허용돼 있지 않음 / 취약: Any 허용 | 불필요한 전체 개방 금지 | `aws_security_group.ingress.cidr_blocks`, `aws_vpc_security_group_ingress_rule.cidr_ipv4` 등 | AVD-AWS-0107 (SSH/RDP 0.0.0.0/0), AVD-AWS-0104 (egress 전체) | V6 SG 오라클: 실효 허용 대역 ⊆ 승인 출처 (분할·prefix list·인접 SG 포함) | 가이드 실습 글(2차 출처)에서 항목명·판단기준 확인. **원문 PDF 로 번호·문구 재확인 필요** |
| Trivy 공식 체크 메타데이터 | AVD-AWS-0057 `aws-iam-no-policy-wildcards` — `cis-aws-1.4: 1.16` 로 표기, **deprecated** | IAM 정책에 와일드카드 금지 | `aws_iam_policy.policy` 의 `Action`/`Resource` | 0.74.0 내장 번들에서 규칙 본문 없음 → 발생 안 함 | V6 IAM 오라클이 대신 판정 | trivy 바이너리 내 rego 메타데이터 실측 (worklog 09-22) |
| Trivy 공식 체크 | AVD-AWS-0345 "Disallow unrestricted S3 IAM Policies" (`s3:*` Allow), AVD-AWS-0342 "IAM Pass Role Filtering" | S3 전체 권한·PassRole 제한 | 같음 | 발생 확인 | V1 대상 룰 | 실측 (scenarios/eval/iam-*) |
| AWS Security Hub 컨트롤 (Trivy 룰 참조 링크) | EC2.13 (SSH 0.0.0.0/0), EC2.14 (RDP 0.0.0.0/0) | 원격 관리 포트 전체 개방 금지 | SG | AVD-AWS-0107 | V6 SG | `policy/cis_mapping.json` (Trivy 룰의 references) |

## 2. 팀이 원문으로 채울 것 (담당·마감: 이번 주)

| 기준 | 받을 곳 | 채울 항목 | 담당 |
|---|---|---|---|
| SK쉴더스 『2024 클라우드 보안 가이드』 AWS 편 (PDF, skshieldus.com 공지 "[보안가이드] 2024 클라우드 보안가이드 발간 (AWS, AZURE, GCP)") | 홈페이지 다운로드 | 2.x 권한 관리(IAM 정책·최소 권한 항목 번호·판단기준), 3.x 가상 리소스(SG 관련 나머지 항목), S3 관련 항목(공개 접근·버킷 정책) | A: SG / B: IAM / C: S3 |
| KISA 2024 클라우드 취약점 점검 가이드 | KISA 자료실 | 위 세 유형에 해당하는 점검 항목 코드·판단 기준 | C |
| CIS AWS Foundations Benchmark (최신 버전 확인) | CIS 사이트 (무료 등록) | 5.2/5.3 (SG 원격 관리 포트), 1.16 (`*:*` 정책), S3 공개 접근 항목 — **버전·번호 원문 확인** | B |
| AWS Well-Architected Framework — Security Pillar | AWS 문서 | SEC03(권한 관리), SEC05(네트워크 보호) 의 관련 모범 사례 ID | A |
| AWS Prescriptive Guidance — Terraform AWS Provider best practices / Security best practices | AWS 문서 | 우리 Stage 1 정책(파일·범위·backend)과 겹치는 권고 | A |
| Trivy 공식 문서 | trivy.dev docs | `trivy config` 동작, plan JSON 스캔, 커스텀 체크(Rego), `--skip-check-update`, 체크 번들 버전 | B |
| HashiCorp Terraform 문서 | developer.hashicorp.com | `plan -out`/`show -json` 형식(plan JSON `planned_values`/`resource_changes`/`configuration`) | C |

## 3. 우리 세 유형 ↔ 통제 항목 (요약 형태 — 위 표가 채워지면 갱신)

| 유형 | 보안 요구사항 (요약) | 가이드 항목 (채울 것) | Terraform | Trivy | 우리 |
|---|---|---|---|---|---|
| 과다 개방 SG | 관리 포트를 인터넷 전체에 열지 않음, 승인 출처만 | SK 3.1 [확인됨], CIS 5.2/5.3 [번호 확인], WA SEC05 [확인] | `aws_security_group`, `aws_vpc_security_group_ingress_rule`, prefix list, 참조 SG | AVD-AWS-0107 | V1/V2 + V5 + V6(SG) |
| IAM 과다 권한 | 최소 권한, 와일드카드 금지, 신뢰 정책 제한 | SK 2.x [채움], CIS 1.16 [번호 확인], WA SEC03 [확인] | `aws_iam_policy`, `aws_iam_role_policy`, `inline_policy`, attachment, `assume_role_policy` | AVD-AWS-0345/0342 (0057 deprecated) | V5 + V6(IAM Tier 1) |
| Public S3 (6~7주차) | 공개 접근 차단, 공개 ACL·정책 금지 | SK S3 항목 [채움], CIS S3 항목 [확인] | `aws_s3_bucket_public_access_block`, `aws_s3_bucket_acl`, `aws_s3_bucket_policy` | AVD-AWS-0086~0094 계열 [룰 ID 실측 필요] | (미구현) |

## 4. 2026-11-02 갱신 — '우리 Validator' 열이 가리키는 코드와 재현 방법

검토 문서(11-02) "기준 매핑표 + 재현 가능한 증거" 대응. 이 표의 '우리' 열은 아래 코드 · 문서로 추적한다. 기준 항목 번호 · 문구는 §2 대로 **원문 확인 전까지 '매핑하였다' 로만** 쓴다.

| 유형 | 기준 (출처 열은 §1 · docs/cis-mapping.md) | 우리 쪽 검사 (코드) | 재현 |
|---|---|---|---|
| 관리 포트 · 고위험 포트 인터넷 개방 | SK 3.1 [2차 출처 확인] · Security Hub EC2.13 / EC2.14 / **EC2.19 blockedPorts 목록** (sg_scan 이 그대로 씀, 2026-11-01 문서 확인) · CIS 5.2/5.3 [번호 원문 확인 필요] | Trivy AVD-AWS-0107 (V1 · V2) + 자체 검사 `verify/sg_scan.py` (`mgmt_public` · `highrisk_public` · `all_ports_public` · `split_any` · `ipv6_any`) | `trivy config <폴더>` (0.74.0) 와 `python3 -m unittest tests/unit/test_sg_scan.py`; 체크 메타는 `scripts/trivy_check_meta.py` |
| 고객 설계(허용 통신) 밖 개방 · 필수 통신 차단 | 기준 문서 항목 없음 — 고객 요구사항(설계도)이 기준 | V6 토폴로지 오라클 `verify/topology_oracle.py` (docs/VERIFICATION_SCOPE.md §2.2) | `tests/unit/test_topology_oracle.py` 23건 · 변이 시험(§4) |
| IAM 최소 권한 | CIS 1.16 [번호 확인] · WA SEC03 · Trivy AVD-AWS-0345 / 0342 (0057 deprecated) | V6 IAM 오라클 `verify/iam_oracle.py` (Tier 1, docs/IAM_SCOPE.md) | `tests/unit/test_iam_slice.py`, `docs/CROSS_VERIFICATION_2026-09-22.md` |
| 변경 범위 통제 (패치가 건드려도 되는 것) | 팀 정책 (기준 문서 항목 아님) | V5 `policy/patch_policy.json` (sg-iam-v2) | `tests/unit/test_policy_risk_gate.py` |

Trivy 가 선언한 CIS 태그와 실제 CIS 판 번호가 다를 수 있다는 점(TRIVY_CIS_MAPPING.md §0, AVD-AWS-0173 사례)은 그대로다. S3 유형은 여전히 '탐지만' (docs/OUT_OF_SCOPE.md).
