# 아키텍처 `infrastructure/webapp-2tier` — Terraform → Trivy → 패치 → 검증 실측 (2026-10-02, 개발 환경)

지도교수 9/29 지시 흐름의 실측 기록. 환경: 개발 샌드박스(Linux), OpenTofu 1.10.6 (`tools/terraform` 이름으로 설치), Trivy 0.74.0, AWS provider 5.100.0 (오프라인 미러). **AWS 에 만든 것은 없다** (apply 는 사람이 팀 PC 에서 — `docs/AWS_ACCESS_SETUP_B.md`). 팀 PC(Windows, Terraform 1.16.1) 재실행은 아직 0회 → `[확인 필요: 팀 PC]`.

## 1. Terraform 자체 검사

| 단계 | 결과 |
|---|---|
| `terraform fmt -check` | 통과 (수정 없음) |
| `terraform init` (오프라인 미러, provider 5.100.0) | 통과 |
| `terraform validate` | 통과 |
| `terraform plan` (자격증명 없음, override) | 통과 — **17 리소스 create**, delete/replace 0 |
| plan 리소스 종류 | aws_vpc 1, aws_internet_gateway 1, aws_subnet 2, aws_route_table 1, aws_route_table_association 1, aws_security_group 2, aws_instance 2, aws_s3_bucket 1, aws_s3_bucket_public_access_block 1, aws_s3_bucket_policy 1, aws_iam_role 1, aws_iam_policy 1, aws_iam_role_policy_attachment 1, aws_iam_instance_profile 1 |

실행: `python3 scripts/arch_scan.py` (결과 폴더 `data/arch/<id>/`, 여기엔 요약만 옮김). 원문 스캔: `trivy-scan.json` (이 폴더).

## 2. Trivy 점검 — 검사 85개 실행, finding 18개 (CRITICAL 2 · HIGH 13 · MEDIUM 2 · LOW 1), 파싱 실패 0

| # | 심각도 | 룰 | 리소스 | 위치 | 내용 | 분류 |
|---:|---|---|---|---|---|---|
| 1 | CRITICAL | AVD-AWS-0104 | aws_security_group.web | security_groups.tf:31 | egress 전체 허용 | 부수 (CIS 항목 없음, 파이프라인 밖) |
| 2 | CRITICAL | AVD-AWS-0104 | aws_security_group.app | security_groups.tf:58 | egress 전체 허용 | 부수 |
| 3 | HIGH | AVD-AWS-0028 | aws_instance.web | compute.tf:6 | IMDSv2 토큰 미요구 | 부수 |
| 4 | HIGH | AVD-AWS-0131 | aws_instance.web | compute.tf:6 | 루트 볼륨 미암호화 | 부수 |
| 5 | HIGH | AVD-AWS-0028 | aws_instance.app | compute.tf:27 | IMDSv2 토큰 미요구 | 부수 |
| 6 | HIGH | AVD-AWS-0131 | aws_instance.app | compute.tf:27 | 루트 볼륨 미암호화 | 부수 |
| 7 | HIGH | AVD-AWS-0345 | aws_iam_policy.web_assets | iam.tf:22 | IAM 정책이 `s3:*` 허용 | **의도적 (IAM 과다 권한)** — 파이프라인 대상 |
| 8 | HIGH | AVD-AWS-0345 | aws_iam_policy.web_assets | iam.tf:22 | 역할이 `s3:*` 정책 사용 (같은 룰, 두 번째 메시지) | 의도적 (7과 같은 원인) |
| 9 | HIGH | AVD-AWS-0164 | aws_subnet.public | network.tf:29 | 서브넷이 퍼블릭 IP 자동 부여 | 부수 (공개 웹 서버 설계상 필요) |
| 10 | HIGH | AVD-AWS-0107 | aws_security_group.web | security_groups.tf:23 | SSH(22) 가 0.0.0.0/0 에 개방 | **의도적 (SG 과다 개방)** — 파이프라인 대상, CIS 직접 대응(v1.2 4.1·4.2, v3.0 5.2 — 팀 매핑표 기준, 원문 대조 전) |
| 11 | HIGH | AVD-AWS-0132 | aws_s3_bucket.assets | storage.tf:4 | KMS 고객 관리 키 미사용 | 부수 |
| 12 | HIGH | AVD-AWS-0086 | aws_s3_bucket_public_access_block.assets | storage.tf:17 | 퍼블릭 ACL 차단 안 함 | **의도적 (Public S3)** — 파이프라인 밖(S3 오라클 미구현, D-10 6~7주차) |
| 13 | HIGH | AVD-AWS-0087 | 〃 | storage.tf:18 | 퍼블릭 정책 차단 안 함 | 의도적 (Public S3) |
| 14 | HIGH | AVD-AWS-0091 | 〃 | storage.tf:19 | 퍼블릭 ACL 무시 안 함 | 의도적 (Public S3) |
| 15 | HIGH | AVD-AWS-0093 | 〃 | storage.tf:20 | 퍼블릭 버킷 제한 안 함 | 의도적 (Public S3) |
| 16 | MEDIUM | AVD-AWS-0178 | aws_vpc.main | network.tf:5 | VPC Flow Logs 없음 | 부수 |
| 17 | MEDIUM | AVD-AWS-0090 | aws_s3_bucket.assets | storage.tf:4 | 버전 관리 없음 | 부수 |
| 18 | LOW | AVD-AWS-0089 | aws_s3_bucket.assets | storage.tf:4 | 버킷 로깅 없음 | 부수 |

- "의도적" = 이 저장소의 연구 대상 3유형으로 일부러 넣은 설정 오류 7줄(SG 1 · S3 4 · IAM 2). "부수" = 튜토리얼 수준 기본값을 Trivy 가 추가로 잡은 것 11줄. 분류는 B 가 코드를 쓰면서 정한 것이고 Trivy 는 구분하지 않는다.
- **Trivy 가 잡지 않은 것**: `storage.tf` 의 버킷 정책 `Principal = "*"` + `s3:GetObject` (공개 읽기 정책 자체). Trivy 0.74.0 의 S3 체크는 퍼블릭 액세스 차단 설정 4개(12~15)를 보지 정책 본문의 Principal 은 보지 않았다. → AI 해석 단계의 `not_flagged_but_risky` 로 잡히는지가 볼거리.
- CIS 매핑표(`policy/cis_mapping.json`)에 있는 룰은 0107·0104·0345 뿐. 나머지 10개 룰은 "매핑표에 없음" — 사람이 채우기 전까지 CIS 대응을 주장하지 않는다.

## 3. 패치 → 검증 (다음 단계) — 두 세트, 2026-10-02

### 3.1 `arch-webapp-sg` (대상 AVD-AWS-0107 @ aws_security_group.web, 후보 = security_groups.tf 대체본) — 7/7 기대 일치, 등급 7/7 일치

| 후보 | 출처 | 기대 | 검토 수준 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 | 기록 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| rule-based | 규칙 기반 | correct | LIGHT_REVIEW | LOW(1) | PASS | PASS | PASS | PASS | PASS | PASS | 20261002-174857-625fa7 |
| correct-approved | seeded | correct | FULL_REVIEW (rationale 미기재) | LOW(1) | PASS | PASS | PASS | PASS | PASS | PASS | 20261002-174917-a1d909 |
| deceptive-cidr-split | seeded | deceptive | BLOCKED | LOW | PASS | PASS | PASS | PASS | PASS | **FAIL** | 20261002-174937-8c9f9a |
| unapproved-other-range | seeded | unapproved | BLOCKED | LOW | PASS | PASS | PASS | PASS | PASS | **FAIL** | 20261002-174957-6c3917 |
| breaks-required-delete-rule | seeded | breaks_required | BLOCKED | LOW | PASS | PASS | PASS | PASS | PASS | **FAIL** | 20261002-175019-e50d6d |
| breaks-required-http-closed | seeded | breaks_required | BLOCKED | LOW | PASS | PASS | PASS | PASS | PASS | **FAIL** (public-http MISSING) | 20261002-175040-f0f3f2 |
| unapproved-app-port-open | seeded | unapproved | BLOCKED | MEDIUM(3) | PASS | PASS | PASS | PASS | PASS | **FAIL** (app-8080 EXCESS 0.0.0.0/0) | 20261002-175100-6de18a |

- V1 만 쓰면 7건 전부 통과, V1+V6 는 2건만 통과 — 단일 파일 시나리오(seeded-sg)와 같은 모양이 **17 리소스 아키텍처의 실제 plan** 에서도 나온다.
- V6 가 참조 SG 를 해석했다: app SG 의 8080 출처 `aws_security_group.web` 이 plan 의 configuration 참조로 풀려 `effective_sg_refs=['aws_security_group.web']` (기록 625fa7 의 verification.json).
- 위험도: SG 1개 + 붙은 인스턴스 1개 = 1점 LOW (6건), 2개 SG + 인스턴스 2개 = 3점 MEDIUM (1건) — manifest 의 expected_risk 와 7/7 일치.
- **첫 실행(173214~)에서는 7건 전부 V6 FAIL** 이었다: intent 의 `required_access`(80 공개, 22 내부)가 대상 SG **둘 다**에 요구돼 app SG 가 MISSING 으로 떨어졌다. 단일 SG 시나리오에서는 드러나지 않던 V6 의 한계 → `required_access[].targets`(선택 필드) 추가로 "이 요구는 web SG 에만" 을 적을 수 있게 했다 (기존 intent 는 필드가 없으면 전과 같이 모든 대상에 적용 — 기존 테스트·20,000건 무작위 검증 결과 불변). 재실행이 위 표.

### 3.2 `arch-webapp-iam` (대상 AVD-AWS-0345 @ aws_iam_policy.web_assets, 후보 = iam.tf 대체본) — 5/6 기대 일치, 등급 5/6

| 후보 | 출처 | 기대 | 결과 | 위험도 | V5 | V6 | 기록 |
|---|---|---|---|---|---|---|---|
| rule-based | 규칙 기반 | correct | **INFO_INSUFFICIENT — 후보 없음 (NOT_SUPPORTED)** | - | - | - | 20261002-175249-eef954 |
| correct-least-privilege (`${var.bucket_name}` 보간) | seeded | correct | REVIEW_REQUIRED / FULL_REVIEW | MEDIUM | PASS | PASS | 20261002-175249-8090a5 |
| deceptive-enumerated-actions | seeded | deceptive | BLOCKED | MEDIUM | PASS | **FAIL** | 20261002-175310-752e53 |
| deceptive-resource-star | seeded | deceptive | BLOCKED | MEDIUM | PASS | **FAIL** | 20261002-175331-358c57 |
| breaks-required-wrong-bucket | seeded | breaks_required | BLOCKED | MEDIUM | PASS | **FAIL** | 20261002-175352-e34d0b |
| unapproved-trust-policy-open | seeded | unapproved | BLOCKED | **HIGH** (신뢰 정책 변경) | **FAIL** | **FAIL** | 20261002-175413-cbd0ae |

- **불일치 1건(숨기지 않음)**: 규칙 기반 생성기가 `aws_iam_policy.web_assets` 블록 안의 `name = "${var.project}-web-assets-policy"` 를 보고 "변수 경유 정책" 으로 거부했다. 정책 본문(`policy = jsonencode({...})`)은 리터럴인데 검사 범위가 블록 전체다. 기대 라벨은 실행 전 고정값이라 바꾸지 않았다(D-4). 실제 아키텍처는 이름에 변수를 쓰는 게 보통이므로 **규칙 기반 baseline 의 현실적 한계** 로 기록 — 검사 범위를 policy 속성으로 좁힐지는 팀 결정(D-16 후보). 같은 finding 에 Claude Code 후보(`scripts/cc_prompt.py arch-iam`)가 어떻게 답하는지가 E1 비교의 재료다.
- var 보간 ARN(`arn:aws:s3:::${var.bucket_name}`)은 plan 에서 값이 확정돼 IAM 오라클이 평가했다(PASS) — 규칙 기반은 못 만들고 오라클은 평가할 수 있는 형태.

## 4. AI 해석 단계 — 실제 실행 0회

`data/arch/<id>/interpret_prompt.md` → 사람이 Claude Code 새 세션에 붙여 넣기 → `scripts/arch_interpret_add.py <폴더> <응답.json>` 로 등록. 등록 스크립트의 대조(지어낸 finding·누락·CIS 불일치)는 개발 중 작성한 예제 응답으로만 검증했다(`tests/unit/test_arch.py`). **모델 응답으로 등록한 기록은 아직 0건** → B 가 팀 PC 에서 1회 실행 후 이 절에 기록 ID 를 적는다.

## 5. 아직 안 된 것

- AWS 실제 apply 0회 (계정 접근 준비 중 — `docs/AWS_ACCESS_SETUP_B.md`), 따라서 V7·V8 도 0회.
- 팀 PC(Terraform 1.16.1, Windows)에서 1~3절 재실행 0회.
- S3 유형은 탐지·해석까지만 (오라클·패치 파이프라인 없음, D-10).
- Claude Code 후보(arch-sg / arch-iam) 0건.
