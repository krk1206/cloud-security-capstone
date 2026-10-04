# webapp-2tier — VPC 2계층 웹 아키텍처 (B 김보성, 2026-10-02)

지도교수 9/29 지시 "아키텍처 하나 선정 → Terraform 으로 구성 → 실행 시연 → Trivy 점검 → AI 해석" 의 1단계. 이 폴더가 **그 아키텍처의 Terraform** 이다.
설명·선정 이유·점검 결과는 [`docs/ARCH_WEBAPP_2TIER.md`](../../../docs/ARCH_WEBAPP_2TIER.md), 문법 공부는 [`docs/TERRAFORM_STUDY_B.md`](../../../docs/TERRAFORM_STUDY_B.md),
AWS 계정·실행 시연 순서는 [`docs/AWS_ACCESS_SETUP_B.md`](../../../docs/AWS_ACCESS_SETUP_B.md).

## 무엇을 만드나 (17 리소스)

```
인터넷
  │
  ▼
[인터넷 게이트웨이] ── VPC 10.0.0.0/16 ─────────────────────────────────────────┐
  │                                                                          │
  │   public 서브넷 10.0.1.0/24                 private 서브넷 10.0.2.0/24    │
  │   ┌───────────────────────────┐            ┌───────────────────────────┐ │
  └──▶│ web EC2 (nginx, 퍼블릭 IP) │ ──8080──▶ │ app EC2 (python http)      │ │
      │  SG web: 80, 22 ◀ 인터넷   │            │  SG app: 8080 ◀ SG web 만  │ │
      │  IAM 역할 web-role         │            └───────────────────────────┘ │
      └─────────────┬─────────────┘                                          │
                    │ s3:*                                                   │
                    ▼                                                        │
      [S3 버킷 assets]  퍼블릭 액세스 차단 전부 해제 + 공개 읽기 정책            │
─────────────────────────────────────────────────────────────────────────────┘
```

| 파일 | 리소스 | 역할 |
|---|---|---|
| `versions.tf` | — | Terraform 버전·AWS provider 5.100.0 고정 (패치가 못 건드리는 보호 파일) |
| `provider.tf` | — | 리전·공통 태그 (보호 파일) |
| `variables.tf` | — | 리전·CIDR·AMI·인스턴스 크기·버킷 이름 |
| `network.tf` | VPC, IGW, 서브넷 2, 라우트 테이블, 연결 | 네트워크 층 |
| `security_groups.tf` | SG 2 (web, app) | 방화벽 층 |
| `compute.tf` | EC2 2 (web, app) | 서버 층 |
| `storage.tf` | S3 버킷, 퍼블릭 액세스 차단 설정, 버킷 정책 | 저장 층 |
| `iam.tf` | 역할, 정책, 연결, 인스턴스 프로필 | 권한 층 |
| `outputs.tf` | — | 퍼블릭 IP·URL·SG ID·버킷 이름 출력 |

AWS 공식 기본 패턴 "VPC with public and private subnets" 를 NAT 게이트웨이 없이 줄인 것이다. **프리 티어 안**: t3.micro 2대(프리 플랜 계정의 프리 티어 대상 — 10-04 실측, t2.micro 는 거부됨)·빈 S3·VPC/SG/IAM(무료) — 시연 1시간이면 청구 0원 (`docs/AWS_ACCESS_SETUP_B.md` 0절). 이 저장소의 연구 대상 3유형(Security Group · Public S3 · IAM)이 전부 들어 있는 가장 작은 구성이라 골랐다.

## 돌리는 법

**A. 자격증명 없이 — 문법·plan·Trivy 점검 (아무것도 만들지 않음)**

```
IaCPatch-console.exe --exec scripts/arch_scan.py          # 팀 PC (python 없이, tools\ 의 trivy·terraform 사용)
python3 scripts/arch_scan.py                               # 개발 환경
```
→ `data/arch/<실행 ID>/findings.md` (finding 표), `summary.json`, `plan.json`, `interpret_prompt.md` (AI 해석용).

**B. 실제 AWS 에 만들기 — 사람이 직접, 샌드박스 계정에서만** (`docs/AWS_ACCESS_SETUP_B.md` 의 순서대로)

```
cd scenarios\arch\webapp-2tier
copy terraform.tfvars.example terraform.tfvars     # ami_id 를 콘솔에서 복사해 채운다
terraform init
terraform validate
terraform plan -out plan.bin                         # "Plan: 17 to add"
terraform apply plan.bin                             # 사람이 실행. 끝나면 web_url 출력
terraform destroy                                    # 시연 끝나면 반드시
```

주의: 이 구성은 **일부러 설정 오류를 포함한 실험 재료**다(어떤 것인지는 `docs/ARCH_WEBAPP_2TIER.md`). 운영 계정에 적용하지 말고, 샌드박스에서 시연한 뒤 1시간 안에 `terraform destroy` 한다. SSH 키 페어를 붙이지 않았으므로 22번이 열려 있어도 로그인은 불가능하지만 설정 오류 자체는 그대로다.

## 이 폴더와 파이프라인의 관계

- `experiments/arch-webapp-2tier/trivy-scan.json` — 이 폴더의 Trivy 스캔 원문 (2026-10-02, Trivy 0.74.0, finding 18).
- `experiments/candidate-sets/arch-webapp-sg/`, `arch-webapp-iam/` — 이 폴더를 원본으로 한 패치 후보 세트 (V1~V6·위험도 실측은 각 `results.md`).
- `scripts/cc_prompt.py arch-sg` / `arch-iam` — Claude Code 에 붙여 넣을 패치 프롬프트.
