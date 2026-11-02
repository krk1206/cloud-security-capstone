# 아키텍처 `scenarios/arch/webapp-2tier` — Terraform → Trivy → 패치 → 검증 실측 (2026-10-02 개발 환경, 2026-10-04 실제 AWS)

지도교수 9/29 지시 흐름의 실측 기록. 1~4절 환경: 개발 샌드박스(Linux), OpenTofu 1.10.6 (`tools/terraform` 이름으로 설치), Trivy 0.74.0, AWS provider 5.100.0 (오프라인 미러). **5절은 10-04 B 의 PC(Windows, Terraform 1.16.1, AWS CLI 2.37.9)에서 B 본인 프리 플랜 계정(서울)에 실제로 만들고 → 전 측정 → PR → 패치 apply → 후 측정 → destroy 까지 한 기록이다.** 계정 번호·키는 적지 않는다.

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

## 3. 패치 → 검증 (다음 단계) — 두 세트 (2026-10-02 첫 실행, 2026-10-04 폴더를 `scenarios/arch/` 로 옮긴 뒤 재실행 — 판정 동일, 아래 기록 ID 는 재실행 것)

### 3.1 `arch-webapp-sg` (대상 AVD-AWS-0107 @ aws_security_group.web, 후보 = security_groups.tf 대체본) — 7/7 기대 일치, 등급 7/7 일치

| 후보 | 출처 | 기대 | 검토 수준 | 위험도 | V1 | V2 | V3 | V4 | V5 | V6 | 기록 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| rule-based | 규칙 기반 | correct | LIGHT_REVIEW | LOW(1) | PASS | PASS | PASS | PASS | PASS | PASS | 20261004-031523-6de2ee |
| correct-approved | seeded | correct | FULL_REVIEW (rationale 미기재) | LOW(1) | PASS | PASS | PASS | PASS | PASS | PASS | 20261004-031539-db1e6e |
| deceptive-cidr-split | seeded | deceptive | BLOCKED | LOW | PASS | PASS | PASS | PASS | PASS | **FAIL** | 20261004-031548-fabcee |
| unapproved-other-range | seeded | unapproved | BLOCKED | LOW | PASS | PASS | PASS | PASS | PASS | **FAIL** | 20261004-031556-78a420 |
| breaks-required-delete-rule | seeded | breaks_required | BLOCKED | LOW | PASS | PASS | PASS | PASS | PASS | **FAIL** | 20261004-031604-9342d7 |
| breaks-required-http-closed | seeded | breaks_required | BLOCKED | LOW | PASS | PASS | PASS | PASS | PASS | **FAIL** (public-http MISSING) | 20261004-031613-330236 |
| unapproved-app-port-open | seeded | unapproved | BLOCKED | MEDIUM(3) | PASS | PASS | PASS | PASS | PASS | **FAIL** (app-8080 EXCESS 0.0.0.0/0) | 20261004-031621-3baac0 |

- V1 만 쓰면 7건 전부 통과, V1+V6 는 2건만 통과 — 단일 파일 시나리오(seeded-sg)와 같은 모양이 **17 리소스 아키텍처의 실제 plan** 에서도 나온다.
- V6 가 참조 SG 를 해석했다: app SG 의 8080 출처 `aws_security_group.web` 이 plan 의 configuration 참조로 풀려 `effective_sg_refs=['aws_security_group.web']` (기록 6de2ee 의 verification.json).
- 위험도: SG 1개 + 붙은 인스턴스 1개 = 1점 LOW (6건), 2개 SG + 인스턴스 2개 = 3점 MEDIUM (1건) — manifest 의 expected_risk 와 7/7 일치.
- **첫 실행(10-02 17:32, 기록 173214~173432)에서는 7건 전부 V6 FAIL** 이었다: intent 의 `required_access`(80 공개, 22 내부)가 대상 SG **둘 다**에 요구돼 app SG 가 MISSING 으로 떨어졌다. 단일 SG 시나리오에서는 드러나지 않던 V6 의 한계 → `required_access[].targets`(선택 필드) 추가로 "이 요구는 web SG 에만" 을 적을 수 있게 했다 (기존 intent 는 필드가 없으면 전과 같이 모든 대상에 적용 — 기존 테스트·20,000건 무작위 검증 결과 불변). 재실행이 위 표.

### 3.2 `arch-webapp-iam` (대상 AVD-AWS-0345 @ aws_iam_policy.web_assets, 후보 = iam.tf 대체본) — 5/6 기대 일치, 등급 5/6

| 후보 | 출처 | 기대 | 결과 | 위험도 | V5 | V6 | 기록 |
|---|---|---|---|---|---|---|---|
| rule-based | 규칙 기반 | correct | **INFO_INSUFFICIENT — 후보 없음 (NOT_SUPPORTED)** | - | - | - | 20261004-031630-31d218 |
| correct-least-privilege (`${var.bucket_name}` 보간) | seeded | correct | REVIEW_REQUIRED / FULL_REVIEW | MEDIUM | PASS | PASS | 20261004-031630-980d06 |
| deceptive-enumerated-actions | seeded | deceptive | BLOCKED | MEDIUM | PASS | **FAIL** | 20261004-031638-c80a2d |
| deceptive-resource-star | seeded | deceptive | BLOCKED | MEDIUM | PASS | **FAIL** | 20261004-031647-1bc7b9 |
| breaks-required-wrong-bucket | seeded | breaks_required | BLOCKED | MEDIUM | PASS | **FAIL** | 20261004-031655-e38d9e |
| unapproved-trust-policy-open | seeded | unapproved | BLOCKED | **HIGH** (신뢰 정책 변경) | **FAIL** | **FAIL** | 20261004-031703-3391fb |

- **불일치 1건(숨기지 않음)**: 규칙 기반 생성기가 `aws_iam_policy.web_assets` 블록 안의 `name = "${var.project}-web-assets-policy"` 를 보고 "변수 경유 정책" 으로 거부했다. 정책 본문(`policy = jsonencode({...})`)은 리터럴인데 검사 범위가 블록 전체다. 기대 라벨은 실행 전 고정값이라 바꾸지 않았다(D-4). 실제 아키텍처는 이름에 변수를 쓰는 게 보통이므로 **규칙 기반 baseline 의 현실적 한계** 로 기록 — 검사 범위를 policy 속성으로 좁힐지는 팀 결정(D-16 후보). 같은 finding 에 Claude Code 후보(`scripts/cc_prompt.py arch-iam`)가 어떻게 답하는지가 E1 비교의 재료다.
- var 보간 ARN(`arn:aws:s3:::${var.bucket_name}`)은 plan 에서 값이 확정돼 IAM 오라클이 평가했다(PASS) — 규칙 기반은 못 만들고 오라클은 평가할 수 있는 형태.

## 4. AI 해석 단계 — 실제 실행 0회

`data/arch/<id>/interpret_prompt.md` → 사람이 Claude Code 새 세션에 붙여 넣기 → `scripts/arch_interpret_add.py <폴더> <응답.json>` 로 등록. 등록 스크립트의 대조(지어낸 finding·누락·CIS 불일치)는 개발 중 작성한 예제 응답으로만 검증했다(`tests/unit/test_arch.py`). **모델 응답으로 등록한 기록은 아직 0건** → B 가 팀 PC 에서 1회 실행 후 이 절에 기록 ID 를 적는다.

## 5. 실제 AWS 실측 — 10-04, B 의 PC + B 본인 프리 플랜 계정(서울 ap-northeast-2)

전부 B 가 혼자 A·B·C 역할로 수행(`docs/SOLO_ABC_RUNBOOK.md`). 숫자는 화면 출력·캡처에서 옮긴 것이고, 안 한 것은 안 했다고 적는다.

### 5.1 팀 PC 재실행 (0단계) — 1회

`IaCPatch-console.exe --exec scripts/arch_scan.py` (빌드 `IaCPatch-ffa0cca`, Terraform 1.16.1 Windows) → `data\arch\20261004-124254` — **finding 18개, 등급 분포·대상 줄 모두 1~2절(OpenTofu 1.10.6)과 동일**. plan 도 17 create.

### 5.2 취약한 원본 apply (3-2) — 리소스 17개 생성, apply 시도 3회

| 시도 | 결과 |
|---|---|
| 1 | `terraform plan -out plan.bin` → "17 to add" → apply: 15개 생성 뒤 EC2 2대에서 **`instance type is not eligible for Free Tier`** (기본값 t2.micro) |
| 2 | tfvars 에 `instance_type` 줄을 적었지만 앞에 `#` 가 있어 주석 → 같은 오류 |
| 3 | `aws ec2 describe-instance-types --filters Name=free-tier-eligible,Values=true` 로 대상 목록 확인(t3.micro 포함, t2.micro 없음) → `instance_type = "t3.micro"` → plan "2 to add" → **apply 2 added** → 합계 17 |

- AMI: 콘솔의 Amazon Linux 2023 x86_64(서울). 인스턴스 2대 t3.micro, ap-northeast-2a.
- `terraform output`: web_public_ip 3.35.139.78 · app_private_ip 10.0.2.70 · web_security_group_id sg-0a745a68a2e0bc469 · vpc vpc-09670e9d97bc9b9e7 · bucket iacpatch-webapp-assets-demo (전부 destroy 로 사라진 값).
- 브라우저 `http://3.35.139.78/` → "iacpatch-webapp web tier" 페이지 표시 = **정상 기능 기준값**.
- 콘솔 캡처: 웹 페이지 / EC2 인스턴스 2대 / 웹 SG 인바운드(80·22 ← 0.0.0.0/0) / S3 버킷 정책 Principal `*` / IAM 정책은 콘솔 목록이 IAM 사용자 권한으로 "거부" 라 **`aws iam get-policy-version` 출력으로 대체**(s3:* on *).
- 부수적으로 배운 것: 2회째 이후 `terraform apply plan.bin` 에 `Saved plan is stale` — plan.bin 은 1회용(무해).

### 5.3 "전" 측정 (3-3) — V7 FAIL · V8 FAIL → `DEPLOY_FAILED` (정답)

- `arch_v8_checks.py --web-ip 3.35.139.78 --app-ip 10.0.2.70` → `sandbox/v8-checks.json` (5검사: web-http-open 승인 / ssh·rdp·app-8080 closed 승인 밖 PC / 핫스팟 선택).
- `iacpatch_cli.py postdeploy --intent arch-webapp-sg.json --tf-dir scenarios/arch/webapp-2tier --v8-checks … --execute` → 기록 **`data/runs/20261004-154105-143eaf`**:
  - **V7 FAIL** — describe-security-groups 로 읽은 실제 웹 SG 의 22 번이 `0.0.0.0/0` 이라 승인 대역 `10.0.0.0/8` 을 뺀 나머지가 **EXCESS** (인터페이스 eni-01bd15b6e69f702fe).
  - **V8 FAIL** — 승인 밖인 B 의 PC 에서 22 번 TCP 연결이 **열림**(닫혀야 통과). 80 은 열림(통과).
  - 해석: 코드의 설정 오류(AVD-AWS-0107)가 실제 인프라에서도 같은 상태로 재현됐다 — "스캐너 finding = 실제 노출" 의 측정값.

### 5.4 패치 기록 → PR → 사람 승인 → 병합 (4단계)

- 화면 5주차 탭 → `arch-webapp-sg` → 규칙 기반 생성 → 기록 **`20261004-154935-dc5b50`**: V1~V6 전부 PASS, 위험도 **LOW**, 검토 수준 **LIGHT_REVIEW**.
- `iacpatch_cli.py pr --review 20261004-154935-dc5b50 --base sandbox` → 브랜치 이름·제목·pr_body·commit_message 생성(실행 안 함).
- GitHub Desktop: `sandbox` 브랜치 생성(= 배포 상태 브랜치, D-17) → 패치 브랜치 → 후보 `candidate/security_groups.tf` 를 `scenarios/arch/webapp-2tier/security_groups.tf` 에 덮어쓰기.
  - **버그 발견**: 후보 파일이 CRLF 로 써져 Desktop 이 파일 전체 변경으로 표시 → PowerShell 로 LF 변환 후 **1줄 diff** 확인. 원인은 기록 쓰기의 줄바꿈(10-05 수정, `src/iacpatch/textio.py`).
- **PR #5 → base `sandbox`**, Actions 3개 통과, 승인 댓글(김보성) → Merge → 커밋 **17ba8ac**. PR 작성자는 Desktop 로그인 계정(A, krk1206)으로 표시됨 — 승인 댓글이 사람 승인 기록.

### 5.5 패치 apply + "후" 측정 (5단계) — V7 PASS · V8 PASS → `VERIFIED`

- `terraform plan -out plan.bin` → **"0 to add, 1 to change, 0 to destroy"** (웹 SG 제자리 수정, 교체 아님) → `apply` → **"0 added, 1 changed, 0 destroyed"**.
- `postdeploy --review 20261004-154935-dc5b50 … --execute` → 기록 **`data/runs/20261004-235735-b463c7`**: **V7 PASS**(22 ← 10.0.0.0/8 만) · **V8 PASS**(80 열림, 22·3389·8080 은 승인 밖 PC 에서 닫힘) → **VERIFIED**.
- 브라우저 `http://3.35.139.78/` 여전히 표시 → **정상 기능 보존**. 콘솔 캡처: 웹 SG 인바운드 22 번 소스 `10.0.0.0/8`.

### 5.6 정리 (6단계)

- `terraform destroy` → **"Destroy complete! Resources: 17 destroyed."** (S3 는 force_destroy, 의존성 오류 없음, 1회에 완료). 콘솔 EC2: 2대 "종료됨".
- IAM 액세스 키 **비활성화** 완료(콘솔 메시지 "액세스 키 비활성화됨"). 다음 시연은 새 키로.
- 요금 확인: IAM 사용자로 Billing → "권한 필요" → **미확인** `[확인 필요: 루트로 로그인해 청구서·크레딧 — 10-05 이후]`.

### 5.7 한 줄 요약 (발표용 숫자)

apply 1세트(17 리소스) · 전 측정 1회(V7 FAIL·V8 FAIL) · 패치 기록 1건(LOW·LIGHT_REVIEW·V1~V6 PASS) · PR 1건 병합(사람 승인) · 패치 apply 1회(1 changed) · 후 측정 1회(V7 PASS·V8 PASS·VERIFIED) · 정상 기능 보존 1/1 · destroy 1회(17). 비용: 청구 0원 예상, 크레딧 차감액 미확인.

## 6. 아직 안 된 것

- 요금·크레딧 차감액 확인 0회 (루트 로그인 필요).
- AI 해석 모델 응답 등록 0건 (`arch_interpret_add.py`), Claude Code 후보(arch-sg / arch-iam) 0건.
- 라벨 손 검산 0/25.
- IAM 세트(`arch-webapp-iam`)의 실제 AWS 전/후 측정 0회 (SG 만 했음; IAM 의 배포 후 검증 V7-IAM 은 미구현 — `docs/IAM_SCOPE.md`).
- S3 유형은 탐지·해석까지만 (오라클·패치 파이프라인 없음, D-10).
