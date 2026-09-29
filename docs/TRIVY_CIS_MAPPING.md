# Trivy ↔ CIS AWS Foundations Benchmark 매핑표 — 실측 열 + 우리 계층 열 (2026-09-22, 09-28 갱신)

> **사람용 매핑표 원본은 A 가 쓴 [`docs/cis-mapping.md`](cis-mapping.md) v0.2 (2026-09-28, 45개 룰, Trivy 메타 + Security Hub 교차 확인, 출처 표기 †/‡)** 다. 이 문서는 (1) `trivy` 바이너리에서 기계로 뽑은 태그(실측, 재현 가능)와 (2) 각 룰을 우리 검증 계층 중 무엇이 잡는지만 유지한다. 두 문서의 숫자가 다르면 A 의 표가 기준이고, 기계 추출값과 다른 곳은 A 가 이미 "Trivy 메타데이터 오류 의심" 으로 적어 두었다(AWS-0145). 파이프라인이 읽는 기계용 사본은 `policy/cis_mapping.json` (A 의 v0.2 값으로 09-28 갱신, verified=false = CIS 원문 미대조).
> 룰 ID 표기: A 의 표는 Trivy 출력 그대로 `AWS-0107`, 이 브랜치의 코드·정책은 `AVD-AWS-0107` 로 정규화한다(같은 룰). 통일 여부는 팀 결정 항목 (docs/WHITELIST_VS_POLICY.md 와 함께).

지도교수 9/22: "차주: 트리비 ↔ CIS AWS 벤치마크 매핑테이블 작성." 그리고 "표준 가이드 같은 게 있는가? → SK쉴더스 테라폼 보안가이드 참고."

이 표의 원칙: **Trivy 룰이 CIS 항목과 1:1 이라고 가정하지 않는다.** Trivy 는 자기 체크 메타데이터에 프레임워크 태그(`cis-aws-1.2`, `cis-aws-1.4`)를 적어 두는데, 그건 Trivy 쪽 주장이고 **CIS 판·번호는 원문으로 확인**해야 한다. 그래서 열을 셋으로 나눈다: (1) Trivy 가 선언한 태그 [실측, 자동], (2) CIS 원문 대조 [사람], (3) 우리 계층 [코드].

## 0. 실측 열은 어떻게 만들었나 (재현 가능)

```
python3 scripts/trivy_check_meta.py            # tools/trivy 바이너리의 내장 체크 메타데이터 → experiments/trivy-check-metadata/trivy-0.74.0-aws.{json,md}
python3 scripts/trivy_check_meta.py AVD-AWS-0107
```

결과(Trivy 0.74.0 내장 번들): AWS 체크 175개, 그중 CIS 태그가 있는 것 46개, deprecated 7개. 우리가 쓰는 룰의 태그:

| Trivy 룰 | 제목 (Trivy) | 심각도 | Trivy 가 선언한 CIS 태그 | 비고 |
|---|---|---|---|---|
| AVD-AWS-0107 | Security groups should not allow unrestricted ingress to SSH or RDP from any IP address | HIGH | **cis-aws-1.2: 4.1, 4.2** | 참고 링크는 Security Hub EC2.13/EC2.14. `cis-aws-1.4` 태그는 없음 |
| AVD-AWS-0104 | A security group rule should not allow unrestricted egress to any IP address | CRITICAL | 없음 | 우리 정책은 기존 finding 이라 V2 차단 대상 아님 |
| AVD-AWS-0105 | Network ACLs should not allow unrestricted ingress to SSH or RDP | MEDIUM | cis-aws-1.4: 5.1 | NACL — 우리 범위 밖(참고) |
| AVD-AWS-0173 | Default security group should restrict all traffic | LOW | cis-aws-1.4: 5.3 | 참고: 1.4 판에서 5.3 은 **기본 SG** 항목이다 → "0107 = 5.3" 이 아닐 가능성. 원문 확인 |
| AVD-AWS-0057 | IAM policy should avoid use of wildcards (least privilege) | HIGH | cis-aws-1.4: 1.16 | **deprecated, 규칙 본문 없음** → 0.74.0 에서 발생 안 함 (D-8) |
| AVD-AWS-0345 | Disallow unrestricted S3 IAM Policies (`s3:*`) | HIGH | 없음 | IAM 시나리오의 대상 룰 (D-8) |
| AVD-AWS-0342 | IAM Pass Role Filtering | MEDIUM | 없음 | |
| AVD-AWS-0143 | IAM policies should not be granted directly to users | LOW | cis-aws-1.4: 1.15; cis-aws-1.2: 1.16 | 참고 |
| AVD-AWS-0086/0087/0091/0093 | S3 Access block: block public ACL / block public policy / ignore public ACL / restrict public bucket | HIGH | 없음 | Public S3 유형(6~7주차) 대상 후보. `aws_s3_bucket_public_access_block` 4 플래그 |
| AVD-AWS-0092 | S3 Buckets not publicly accessible through ACL | HIGH | 없음 | |
| AVD-AWS-0094 | S3 buckets should each define an aws_s3_bucket_public_access_block | LOW | 없음 | |

전체 목록: `experiments/trivy-check-metadata/trivy-0.74.0-aws.md` (팀 PC 의 trivy.exe 로 다시 뽑아 같은지 확인할 것 — 버전이 다르면 태그도 다를 수 있다).

## 1. 매핑표 본체 — A 의 `docs/cis-mapping.md` 로 대체됨 (아래 표는 '우리 계층' 열만 참고)

CIS 원문은 CIS 사이트에서 무료 등록 후 PDF 를 받는다. **판(version) 을 먼저 정하고** 그 판의 번호로만 적는다 (판마다 번호가 다르다: 1.2.0 의 4.1/4.2 가 1.4.0 이후 5.x 로 옮겨진 것으로 알려져 있으나 **원문에서 확인**).

| 우리 유형 | Trivy 룰 | Trivy 선언 태그 [실측] | CIS 판 [사람] | CIS 항목 번호 [사람] | CIS 항목 제목 (원문 그대로) [사람] | CIS 판단 기준 요약 [사람] | 우리 계층 | 확인자 / 날짜 |
|---|---|---|---|---|---|---|---|---|
| 과다 개방 SG (SSH) | AVD-AWS-0107 | cis-aws-1.2: 4.1 | | | | | V1 + V6 SG (실효 대역 ⊆ 승인) | |
| 과다 개방 SG (RDP) | AVD-AWS-0107 | cis-aws-1.2: 4.2 | | | | | V1 + V6 SG | |
| 과다 개방 SG (IPv6 ::/0) | AVD-AWS-0107 | (태그 없음 — 1.4 이후 IPv6 항목이 따로 있다는 설, 확인) | | | | | V6 SG (ipv6_cidr_blocks 합집합) | |
| IAM 과다 권한 (`*:*`) | AVD-AWS-0057 (deprecated) | cis-aws-1.4: 1.16 | | | | | **V6 IAM** (Trivy 가 못 잡음) | |
| IAM 과다 권한 (`s3:*`) | AVD-AWS-0345 | 없음 | (해당 항목 없을 수 있음 → "CIS 직접 대응 없음" 으로 적는다) | | | | V1 + V6 IAM | |
| IAM PassRole | AVD-AWS-0342 | 없음 | | | | | V1 (V6 Tier 1 밖) | |
| IAM 신뢰 정책 Principal `*` | (Trivy 룰 없음 — 실측 확인 필요) | — | | | | | V6 IAM (trust_open → FAIL) | |
| Public S3 (ACL/정책/차단 설정) | AVD-AWS-0086/0087/0091/0092/0093/0094 | 없음 | | | | | (6~7주차) | |

작성 규칙:
- 원문에 없는 번호는 **적지 않는다.** "직접 대응 없음" 도 유효한 결과다 (0345 처럼 서비스 특화 룰은 CIS 에 없을 수 있다).
- 판을 바꾸면 줄을 새로 만든다 (1.2.0 / 1.4.0 / 2.0.0 / 3.0.0 …), 이전 줄은 지우지 않는다.
- 확인자·날짜를 적는다. AI 가 채운 칸은 확인자 없이 두지 않는다 (교수 9/22: AI 가 만든 것은 공격받기 쉬운 지점).
- 완성되면 `policy/cis_mapping.json` 의 `verified` 를 true 로 바꾸고(사람이), `docs/STANDARDS_MAPPING.md` 3절과 `docs/WHY_8_LAYERS.md` 5절을 갱신한다.

## 2. "Trivy 가 결함 등급을 판단 → 높은 등급 → 실패 → 실 코드 반영 방지" 는 어디에 있나

교수 메모의 첫 줄(의도적 결함 Terraform → Trivy 스캔 → 등급 → 높은 등급이면 실패 → 반영 방지)에 대응하는 우리 위치:

| 단계 | 우리 구현 | 실측 |
|---|---|---|
| 의도적 결함 Terraform | `scenarios/`, `experiments/trivy-sg-probe/cases/`, `ground-truth/`(A 가 직접, 이번 주) | 있음 |
| Trivy 스캔 + 등급 | `trivy config --format json` → 룰 ID·Severity (`review/inputs.py list_findings`) | 있음 (0107 HIGH, 0104 CRITICAL, 0345 HIGH, 0342 MEDIUM) |
| 높은 등급 → 실패 | **배포 전 게이트**: V1(대상 finding 남아 있으면 FAIL) + V2(새 CRITICAL/HIGH 이면 FAIL) → BLOCKED → PR 불가 (`iacpatch pr --review` 가 거부) | 있음 (`policy/patch_policy.json` `v2_block_severities`) |
| 실 코드 반영 방지 (CI) | `.github/workflows/` 에 파일 3개 — **Actions 실행 0회**. C 가 첫 실행 뒤 `trivy config --severity HIGH,CRITICAL --exit-code 1` 로 PR 을 막는 required check 를 붙인다 (`docs/PROJECT_REVIEW_WEEK4.md` 11절 C-1) | **아직** |

주의: "Trivy 등급이 높으면 막는다" 만으로는 01-cidr-split/06-prefix-list 같은 **Trivy 통과 패치**를 못 막는다. 그래서 그 위에 V6 가 있다 (`docs/WHY_8_LAYERS.md`). 이 두 문장을 발표에서 한 쌍으로 말할 것.

## 3. SK쉴더스 가이드와의 관계

CIS 는 "항목 번호·감사 절차" 가 정확한 대신 AWS 계정 설정 중심이고, SK쉴더스 『2024 클라우드 보안 가이드』(AWS 편) 는 한국어 판단 기준(양호/취약)이 있어 발표·보고서에서 읽기 쉽다. 둘 다 적되 **원문 PDF 를 팀이 직접 보고** 적는다 (`docs/STANDARDS_MAPPING.md` 2절의 담당표: A SG / B IAM / C S3).
