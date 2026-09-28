# Trivy 룰 ↔ CIS AWS Foundations Benchmark 매핑표

버전: v0.2 (2026-09-28, 2차 검수 반영). 담당: A.
목적: Trivy IaC 룰이 어떤 CIS 항목에 대응하는지 정리해 탐지 근거로 쓴다. 대응이 없는 룰도 그대로 적는다. 모든 Trivy 룰이 CIS 항목과 1:1 대응한다고 가정하지 않는다.

## 1. 출처와 범위

| 출처 | 내용 | 시점 |
|---|---|---|
| trivy-checks 저장소 룰 메타데이터 (`checks/cloud/aws/ec2/*.rego` 21개, `checks/cloud/aws/iam/*.rego` 24개의 `custom.frameworks`) | Trivy가 스스로 적어둔 CIS 대응. AWS 전체 룰을 훑어도 키는 `cis-aws-1.2`(33회), `cis-aws-1.4`(38회) 두 가지뿐이며 v3.0.0·v5.0.0 정보는 없음 | main 커밋 3ae9f4c (2026-09-10) |
| AWS Security Hub 문서 — CIS AWS Foundations Benchmark 표준 페이지, EC2 컨트롤 페이지, IAM 컨트롤 페이지 | 같은 점검 항목의 CIS v1.2.0 / v1.4.0 / v3.0.0 / v5.0.0 번호 교차 확인 | 2026-09-28 조회 |
| CIS AWS Foundations Benchmark 원문 | 회원가입 후 무료 다운로드. 아직 대조하지 않음 | 미확인 |

표기 규칙:
- 표시 없음: Trivy 메타데이터 값
- †: Security Hub 문서에서 가져온 값 (Trivy 메타데이터에 없음)
- ‡: CIS 원문 기준으로 추정한 값. Trivy·Security Hub 어디에도 표기가 없어 원문 대조 전까지 인용하지 않음
- 없음: 해당 버전에 항목이 없음(확인된 범위에서)
- 확인 필요: 출처 간 불일치 또는 출처 없음

대응 수준 정의:
- 직접: Trivy 룰이 검사하는 조건이 CIS 항목의 조건과 같다.
- 부분: 검사 대상은 같지만 범위가 다르다(더 넓거나 좁다).
- 문구 대응: Trivy 메타데이터에는 없지만 내용상 같은 항목이 CIS에 있다.
- 없음: CIS에 해당 항목이 없다.

룰 ID 표기: Trivy 0.74.0의 JSON 출력과 trivy-checks 메타데이터 모두 `AWS-0107` 형식이다(접두어 `AVD-`는 2025-12-20 trivy-checks #510에서 별칭으로 내려감). 문서와 코드에서 이 형식으로 통일한다.
범위: 우리 시나리오(Security Group 과다 개방, IAM 과다 권한)와 관련된 Trivy AWS ec2·iam 룰 45개 전부. S3 등 다른 서비스 룰은 선택 확장 시 추가.

## 2. 우리 시나리오 관련 룰 (표 A)

| Trivy 룰 | 검사 내용 | Trivy 심각도 | CIS v1.2.0 | v1.4.0 | v3.0.0 | v5.0.0 | 대응 수준 | 근거 | 우리 시나리오 |
|---|---|---|---|---|---|---|---|---|---|
| AWS-0107 | SG 인바운드 규칙 중 SSH(22)·RDP(3389)를 포함한 포트 범위 또는 전체 프로토콜(-1)에 0.0.0.0/0·::/0 허용 | HIGH | 4.1 (SSH), 4.2 (RDP) | 5.2‡ | 5.2† (IPv4), 5.3† (IPv6) | 5.3†, 5.4† — 컨트롤 페이지에는 5.6으로 표기되어 AWS 문서 간 불일치, 원문 확인 필요 | 직접 | Trivy 메타 `cis-aws-1.2: 4.1, 4.2`; Security Hub EC2.13/EC2.14(v1.2.0), EC2.53/EC2.54(v3.0.0, v5.0.0). 2024-09-26 trivy-checks #257에서 CIS 항목에 맞춰 22/3389로 한정됨 | SG 필수 시나리오. 00-baseline 탐지, 01·06 우회 |
| AWS-0104 | SG 아웃바운드 규칙에 0.0.0.0/0·::/0 허용 (포트 무관) | CRITICAL | 없음 | 없음 | 없음 | 없음 | 없음 | CIS는 아웃바운드 무제한을 항목화하지 않음(기본 SG 항목 제외). 심각도 CRITICAL은 Aqua 자체 기준 | baseline에서 함께 탐지됨. 게이트 기준 결정 필요(5절) |
| AWS-0173 | 기본(default) SG가 트래픽을 허용 | LOW | 4.3† | 5.3 | 5.4† | 5.5† | 직접 | Trivy 메타 `cis-aws-1.4: 5.3`; Security Hub EC2.2 | 기본 VPC를 쓰는 동안 해당 가능. 선택 |
| AWS-0105 | Network ACL 인바운드 0.0.0.0/0 → 22/3389 | MEDIUM | 없음 | 5.1 | 5.1† | 5.2† | 직접 | Trivy 메타 `cis-aws-1.4: 5.1`; Security Hub EC2.21 | 범위 밖(NACL) |
| AWS-0099 | SG에 description 없음 | LOW | 없음 | 없음 | 없음 | 없음 | 없음 | 위생 규칙 | 패치 시 description 추가 허용(화이트리스트 4절) |
| AWS-0124 | SG 규칙에 description 없음 | LOW | 없음 | 없음 | 없음 | 없음 | 없음 | 위생 규칙 | 위와 같음 |
| AWS-0057 | IAM 정책 문서의 Action·Resource 와일드카드 | HIGH | 1.22† | 1.16 | 확인 필요 (Security Hub 표에 항목 없음. 원문 기준 1.16‡) | 확인 필요 | 부분 | Trivy 메타 `cis-aws-1.4: 1.16`; Security Hub IAM.1. CIS 항목은 `*:*` 전체 관리자 권한만 다루고, Trivy는 부분 와일드카드(`s3:*`, `Resource: *`)도 탐지 → Trivy가 더 넓음 | IAM 필수 시나리오 |
| AWS-0143 | 사용자에게 정책 직접 연결 | LOW | 1.16 | 1.15 | 1.15† | 1.14† | 직접 | Trivy 메타 `cis-aws-1.2: 1.16, cis-aws-1.4: 1.15`; Security Hub IAM.2 | IAM 선택 |
| AWS-0345 | S3 전체 권한(`s3:*`) 정책 | HIGH | 없음 | 없음 | 없음 | 없음 | 없음 | Security Hub IAM.21(서비스 와일드카드)도 CIS 대응 없음 | IAM 선택(와일드카드 하위 유형) |
| AWS-0346 | S3 버킷에 불필요한 접근을 허용하는 IAM 정책 | HIGH | 없음 | 없음 | 없음 | 없음 | 없음 | - | 범위 밖 |
| AWS-0342 | iam:PassRole 무제한 | MEDIUM | 없음 | 없음 | 없음 | 없음 | 없음 | - | 범위 밖 |

## 3. Trivy IAM 계정 위생 룰 (표 B, 참고)

Terraform의 `aws_iam_account_password_policy`, 루트 계정 설정 등에 적용된다. 우리 시나리오(정책 문서의 과다 권한)와는 다른 범주지만 Trivy IAM 룰의 CIS 대응을 완성하기 위해 기록한다.

| Trivy 룰 | 검사 내용 | 심각도 | v1.2.0 | v1.4.0 | v3.0.0 | v5.0.0 | 비고 |
|---|---|---|---|---|---|---|---|
| AWS-0140 | 루트 계정 사용 자제 | LOW | 1.1 | 1.7 | - | - | Security Hub 대응 컨트롤 없음 |
| AWS-0141 | 루트 액세스 키 존재 | CRITICAL | 1.12 | 1.4 | 1.4† | 1.3† | Security Hub IAM.4 |
| AWS-0142 | 루트 MFA 미설정 | CRITICAL | 1.13 | 1.5 | 1.5† | 1.4† | Security Hub IAM.9 |
| AWS-0165 | 루트 하드웨어 MFA 미설정 | MEDIUM | 1.14† | 1.6 | 1.6† | 1.5† | Security Hub IAM.6 |
| AWS-0145 | 콘솔 사용자 MFA 미설정 | MEDIUM | 1.2 | 1.10† (Trivy 메타: 1.4) | 1.10† | 1.9† | Trivy 메타데이터는 `cis-aws-1.4: 1.4`로 표기하나, v1.4.0의 1.4는 루트 액세스 키 항목(AWS-0141과 동일 번호). Security Hub IAM.5 기준 1.10이 맞아 보임 → Trivy 메타데이터 오류 가능성, 원문 확인 필요 |
| AWS-0123 | IAM 그룹 MFA 강제 | MEDIUM | 없음 | 없음 | 없음 | 없음 | - |
| AWS-0144 | 90일 미사용 자격증명 비활성화 | MEDIUM | 1.3 | - | - | - | Security Hub IAM.8 |
| AWS-0166 | 45일 미사용 자격증명 제거 | LOW | - | 1.12 | 1.12† | 1.11† | Security Hub IAM.22 |
| AWS-0146 | 액세스 키 90일 교체 | LOW | 1.4 | 1.14 | 1.14† | 1.13† | Security Hub IAM.3 |
| AWS-0167 | 사용자당 활성 액세스 키 1개 | LOW | - | 1.13 | - | - | Security Hub 대응 없음 |
| AWS-0168 | 만료 TLS 인증서 제거 | LOW | - | 1.19 | 1.19† | 1.18† | Security Hub IAM.26 |
| AWS-0169 | AWS Support 역할 | LOW | 1.20† | 1.17 | 1.17† | 1.16† | Security Hub IAM.18 |
| AWS-0056 | 비밀번호 재사용 방지 | MEDIUM | 1.10 | 1.9 | 1.9† | 1.8† | Security Hub IAM.16 |
| AWS-0063 | 비밀번호 최소 14자 | MEDIUM | 1.9 | 1.8 | 1.8† | 1.7† | Security Hub IAM.15 |
| AWS-0061 | 대문자 요구 | MEDIUM | 1.5 | - | - | - | Security Hub IAM.11. v1.4.0 이후 CIS에서 제거 |
| AWS-0058 | 소문자 요구 | MEDIUM | 1.6 | - | - | - | Security Hub IAM.12. v1.4.0 이후 제거 |
| AWS-0060 | 기호 요구 | MEDIUM | 1.7 | - | - | - | Security Hub IAM.13. v1.4.0 이후 제거 |
| AWS-0059 | 숫자 요구 | MEDIUM | 1.8 | - | - | - | Security Hub IAM.14. v1.4.0 이후 제거 |
| AWS-0062 | 비밀번호 90일 만료 | MEDIUM | 1.11 | - | - | - | Security Hub IAM.17. v1.4.0 이후 제거 |

## 4. 그 외 Trivy EC2 룰 (표 C)

| Trivy 룰 | 검사 내용 | 심각도 | CIS 대응 |
|---|---|---|---|
| AWS-0028 | EC2 인스턴스 IMDSv2(세션 토큰) 강제 | HIGH | 문구 대응: v3.0.0 5.6†, v5.0.0 5.7† (Security Hub EC2.8). Trivy 메타데이터에는 없음 |
| AWS-0130 | 오토스케일링 launch configuration/template의 IMDSv2 강제 | HIGH | 위와 같음 |
| AWS-0026 | EBS 볼륨 암호화 | HIGH | 부분: CIS는 계정 기본 EBS 암호화(v1.4.0 2.2.1†, v3.0.0 2.2.1†, v5.0.0 5.1.1†, Security Hub EC2.7)를 다루고 Trivy는 볼륨 단위 |
| AWS-0131, AWS-0008, AWS-0122 | 인스턴스·launch configuration 블록 디바이스 암호화 | HIGH | 위와 같음(부분) |
| AWS-0027 | EBS 암호화에 고객 관리 키 사용 | LOW | 없음 |
| AWS-0178 | VPC Flow Logs 미설정 | MEDIUM | 문구 대응: v1.2.0 2.9†, v1.4.0 3.9†, v3.0.0 3.7†, v5.0.0 3.7† (Security Hub EC2.6) |
| AWS-0101 | 기본 VPC 사용 | HIGH | 없음 |
| AWS-0102 | NACL 규칙이 모든 포트 허용 | CRITICAL | 없음(5.1은 22/3389 한정) |
| AWS-0009, AWS-0164 | 퍼블릭 IP 자동 할당(launch configuration, 서브넷) | HIGH | 없음 |
| AWS-0029 | EC2 인스턴스 user data에 AWS 키 포함 | CRITICAL | 없음 |
| AWS-0129 | 오토스케일링 launch configuration user data에 AWS 키 포함 | CRITICAL | 없음 |
| AWS-0344 | AMI 데이터 소스에 owners 미지정 | LOW | 없음 |

## 5. 관찰과 결정 사항

1. **게이트 기준과 CIS 기준이 다르다.** 현재 CI 게이트는 Trivy 심각도(HIGH/CRITICAL)로 동작한다. baseline에서 함께 잡히는 AWS-0104(아웃바운드, CRITICAL)는 CIS 항목이 없고, CIS 항목이 있는 AWS-0173(기본 SG)은 LOW다. 제안: 게이트는 Trivy 심각도 기준을 유지하고, Evidence Bundle과 PR 댓글에 CIS 대응 번호를 함께 표기한다. 평가용 시나리오는 CIS 대응이 있는 룰(AWS-0107, AWS-0057)을 1차 대상으로 한다. [팀 결정 필요]
2. **Trivy 메타데이터는 오래된 CIS 버전만 담고 있다.** `cis-aws-1.2`, `cis-aws-1.4`뿐이라 v3.0.0·v5.0.0 번호는 Security Hub 문서로 보강했다(†). 발표·보고서에서는 버전을 반드시 함께 쓴다(예: "CIS v3.0.0 5.2").
3. **AWS-0057은 CIS 1.16보다 넓다.** CIS는 `*:*` 전체 관리자 권한만 금지하지만 Trivy는 부분 와일드카드도 탐지한다. IAM 시나리오에서 "CIS 위반"이라고 말할 수 있는 것은 `*:*` 사례뿐이고, `s3:*` 같은 사례는 "최소 권한 원칙 위반(Trivy 기준)"으로 구분해 말한다.
4. **Trivy 메타데이터 오류 의심 1건.** AWS-0145(콘솔 사용자 MFA)의 `cis-aws-1.4: 1.4`. 같은 번호가 AWS-0141(루트 액세스 키)에도 붙어 있어 둘 중 하나는 틀렸고, Security Hub 기준으로는 AWS-0145 쪽이 1.10이다. 원문 확인 후 필요하면 trivy-checks에 이슈 제출 가능.
5. **AWS 문서 내부 불일치 1건.** EC2.53/EC2.54의 v5.0.0 번호가 표준 페이지(5.3/5.4, 두 번 조회 일치)와 컨트롤 페이지(5.6)에서 다르다. 표준 페이지 값을 쓰되 원문 확인 전까지 v5.0.0 번호는 인용하지 않는다.
6. **v1.4.0의 SG 항목(5.2)은 Trivy에도 Security Hub에도 표기가 없다.** Trivy 메타데이터는 v1.2.0(4.1, 4.2)까지만 적었고, Security Hub는 v1.4.0 표준에 이 항목을 구현하지 않았다. 원문 기준으로만 5.2다(‡).

## 6. Trivy 룰이 "문자열 일치"로 판정한다는 근거

우회 실험(01 cidr-split, 06 prefix-list)이 왜 성공했는지는 trivy-checks 소스에서 직접 확인된다 (`lib/cloud/net.rego`, 커밋 3ae9f4c).

- `all_ips := {"0.0.0.0/0", "0000:0000:0000:0000:0000:0000:0000:0000/0", "::/0", "*"}` — 전체 인터넷 판정은 이 네 문자열과의 정확 일치다. `0.0.0.0/1`은 집합에 없으므로 통과한다. (Azure용 키워드 `internet`, `any`도 별도 집합으로 검사하지만 CIDR 계산은 없다.)
- `cidr_allows_all_ips(cidr) if cidr in all_ips` — CIDR 계산이 아니라 집합 포함 여부다.
- AWS-0107은 `rule.cidrs`만 본다. `prefix_list_ids`와 참조 SG는 검사 대상이 아니다(06·08 케이스).
- AWS-0104(아웃바운드)도 같은 `cidr_allows_all_ips`를 쓰며 포트 조건이 없다.
- 포트 판정은 `is_ssh_or_rdp_port`: 포트 범위에 22 또는 3389가 포함되거나 프로토콜이 -1이면 해당. 이 한정은 2024-09-26(#257)에 CIS 항목에 맞춰 도입됐으므로, 2026년의 Trivy 0.74.0 번들에도 적용된 상태다. 즉 80번 포트를 0.0.0.0/0에 열어도 AWS-0107은 발화하지 않는다(검증 실험 항목으로 추가).

이 사실은 "스캐너 규칙은 문법적 위치를 본다"는 선행 연구의 서술(TerraProbe 3.11절)을 Trivy에서 코드 수준으로 확인한 것이며, V6 Intent Oracle이 문자열이 아니라 대역 합집합을 계산해야 하는 이유다.

## 7. 사용처

- Evidence Bundle: finding에 `cis` 필드 추가 (버전, 항목 번호, 대응 수준, 출처 표기).
- AI 분석 리포트: "CIS 근거를 포함한 분석"(계획서 3주차 B 항목)의 입력.
- PR 댓글: 탐지 항목 옆에 CIS 번호 표기.
- 평가: 시나리오 선정 시 CIS 대응 유무를 기준 중 하나로 사용.

## 8. 확인 필요 목록

| 항목 | 방법 |
|---|---|
| Trivy 0.74.0 룰 번들이 커밋 3ae9f4c와 같은 메타데이터인지 | `trivy --version`의 Check Bundle 출력 기록. 필요 시 `trivy config --include-non-failures --format json`에서 룰 제목 대조 |
| ‡ 표시 항목: CIS v1.4.0 5.2, v3.0.0 1.16 | CIS 원문 다운로드 후 대조 |
| v5.0.0의 EC2.53/54 번호(5.3/5.4 vs 5.6) | CIS v5.0.0 원문 5절 대조 |
| AWS-0145 메타데이터 오류 여부 | CIS v1.4.0 원문 1.4·1.10 대조 |
| AWS-0107이 22/3389 외 포트에서는 발화하지 않는지 | 80번 포트를 0.0.0.0/0에 여는 SG를 Trivy 0.74.0으로 스캔 (사전 실험 케이스 09로 추가) |
