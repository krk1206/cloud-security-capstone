# Terraform 문법 공부 — `infrastructure/webapp-2tier/` 의 실제 줄로 (B, 2026-10-02)

지도교수: "Terraform 문법도 공부해 올 것", "본인이 한 작업은 설명이 가능해야 함". 그래서 교과서 순서가 아니라 **우리 파일에 실제로 쓰인 것만**, 파일을 열어 놓고 줄을 짚어 가며 읽는 순서로 적었다. 각 절 끝의 "직접 해 보기" 를 PC 에서 하고, 마지막 10문제를 안 보고 답할 수 있으면 된다.

## 0. Terraform 이 하는 일 한 문장

`.tf` 파일에 "이런 리소스가 있어야 한다" 를 적으면, Terraform 이 현재 상태(state)와 비교해 **만들고/바꾸고/지우는 API 호출을 대신 한다**. 사람은 콘솔을 클릭하지 않고 파일을 고치고 `plan` → `apply` 를 친다. 같은 파일이면 몇 번을 돌려도 같은 결과(멱등).

## 1. 블록 — 모든 .tf 파일은 블록의 나열이다

```hcl
<블록 종류> "<라벨1>" "<라벨2>" {
  <인자 이름> = <값>          # 인자(argument): 이름 = 값
  <중첩 블록> { ... }         # 중첩 블록: 이름 { } (= 가 없다)
}
```

우리 파일에 나오는 블록 종류 7개:

| 블록 | 어디 | 뜻 |
|---|---|---|
| `terraform { }` | versions.tf | Terraform 자체 설정 — 요구 버전, 쓸 provider 와 버전 |
| `provider "aws" { }` | provider.tf | AWS 에 어떻게 접속할지 — 리전, 공통 태그. 자격증명은 안 적는다(환경변수) |
| `variable "이름" { }` | variables.tf | 입력값 선언. 쓸 때는 `var.이름` |
| `resource "타입" "이름" { }` | network/security_groups/compute/storage/iam.tf | **만들 것**. 타입은 provider 가 정한 이름(`aws_vpc`, `aws_instance` …), 이름은 내가 붙임. 둘을 합친 `aws_vpc.main` 이 이 리소스의 주소 |
| `output "이름" { }` | outputs.tf | apply 뒤 보여 줄 값 |
| `data "타입" "이름" { }` | (이 구성엔 없음) | 이미 있는 것을 **읽기만**. 예: 최신 AMI 조회. 자격증명 없는 오프라인 plan 에서는 못 쓰기 때문에 AMI 를 변수로 받았다 (variables.tf 의 ami_id 설명) |
| `locals { }` | (이 구성엔 없음) | 파일 안 계산용 임시 이름. 쓸 때 `local.이름` |

리소스 블록 안의 중첩 블록: `ingress { }`, `egress { }`, `route { }`, `tags = { }` (tags 는 `=` 가 있으니 중첩 블록이 아니라 **맵 값**), `default_tags { tags = { } }`, `validation { }`.

**직접 해 보기**: `security_groups.tf` 를 열고 `resource "aws_security_group" "web"` 블록에서 인자(= 있음)와 중첩 블록(= 없음)을 색으로 구분해 본다. 답: 인자 name/description/vpc_id/tags, 중첩 ingress ×2 / egress ×1.

## 2. 값의 종류 — 우리 파일에 나온 것만

| 종류 | 예 (파일) | 메모 |
|---|---|---|
| 문자열 | `"ap-northeast-2"` (variables.tf) | 큰따옴표 |
| 숫자 | `from_port = 22` | 따옴표 없음 |
| 불리언 | `map_public_ip_on_launch = true` (network.tf) | |
| 리스트 | `cidr_blocks = ["0.0.0.0/0"]`, `["0.0.0.0/1", "128.0.0.0/1"]` | 대괄호. **V6 가 이 리스트들을 전부 합쳐 범위를 계산한다** |
| 맵 | `tags = { Name = "..." }` | 중괄호 안에 키 = 값 |
| 보간(interpolation) | `"${var.project}-vpc"` | 문자열 안에서 `${...}` 로 식을 끼워 넣음 |
| 참조 | `vpc_id = aws_vpc.main.id` | 다른 리소스의 속성. **이 참조가 만드는 순서를 정한다** (VPC 먼저, 그 다음 서브넷) |
| 함수 | `jsonencode({...})` (iam.tf, storage.tf), `regex(...)`, `can(...)` (variables.tf) | IAM 정책은 JSON 문자열이어야 해서 HCL 맵을 jsonencode 로 바꿈 |
| 히어독 | `<<-EOF ... EOF` (compute.tf user_data, variables.tf description) | 여러 줄 문자열. `-` 가 있으면 들여쓰기를 지워 준다 |

**직접 해 보기**: `compute.tf` 의 user_data 안에 `${var.project}` 가 있다. 이것이 bash 변수가 아니라 Terraform 보간인 이유를 말해 본다. (답: `.tf` 파일 안이므로 Terraform 이 먼저 치환하고, 치환된 평문이 EC2 에 전달된다.)

## 3. 참조와 의존 — 왜 파일이 여러 개여도 되나

Terraform 은 폴더 안의 `.tf` 를 **전부 합쳐 하나로** 읽는다. 파일 이름은 사람 편의다. 순서는 참조 그래프가 정한다:

```
aws_vpc.main ─▶ aws_subnet.public ─▶ aws_instance.web ─▶ output web_public_ip
     │                                   ▲
     └─▶ aws_security_group.web ─────────┘
              ▲
aws_security_group.app 의 ingress.security_groups = [aws_security_group.web.id]   ← SG 가 SG 를 참조
aws_iam_role.web ─▶ aws_iam_instance_profile.web ─▶ aws_instance.web (iam_instance_profile)
aws_s3_bucket.assets ─▶ aws_s3_bucket_public_access_block.assets ─▶ aws_s3_bucket_policy (depends_on 으로 명시)
```

- 암묵 의존: `aws_vpc.main.id` 를 쓰면 자동으로 VPC 뒤에 만든다.
- 명시 의존 `depends_on = [...]`: 참조가 없는데 순서가 필요할 때. storage.tf 에서 "퍼블릭 정책은 차단 해제 뒤에" 가 그것. (참조로 잡히지 않는 순서라 적어야 한다 — 안 적으면 apply 가 가끔 실패한다.)
- `plan` 에서 `(known after apply)` 로 보이는 값 = 만들어 봐야 아는 값(ID, ARN, IP). V6 오라클이 `aws_security_group.web.id` 를 값이 아니라 **참조 이름**으로 해석하는 이유가 이것이다.

**직접 해 보기**: `terraform graph` 를 치면 DOT 형식의 그래프가 나온다 (읽지 않아도 됨 — "참조가 그래프" 라는 것만 확인).

## 4. 명령 6개 — 시연 때 치는 순서와 각 줄이 하는 일

| 명령 | 하는 일 | 성공 메시지 | AWS 에 뭔가 만드나 |
|---|---|---|---|
| `terraform init` | provider 플러그인 내려받기(또는 캐시), `.terraform/` 와 `.terraform.lock.hcl` 생성 | successfully initialized | 아니오 |
| `terraform fmt` | 들여쓰기·정렬 맞춤 (`-check` 는 고치지 않고 확인만) | 출력 없음 | 아니오 |
| `terraform validate` | 문법·타입·참조 검사. 자격증명 불필요 | Success! The configuration is valid. | 아니오 |
| `terraform plan -out plan.bin` | 현재 state 와 비교해 **무엇을 만들/바꿀/지울지** 계산. 자격증명 필요(오프라인이면 override 로 우회) | Plan: 17 to add, 0 to change, 0 to destroy. | 아니오 |
| `terraform apply plan.bin` | plan 대로 실행 | Apply complete! Resources: 17 added | **예** |
| `terraform destroy` | state 에 있는 것 전부 삭제 | Destroy complete! Resources: 17 destroyed | **예(삭제)** |

보조: `terraform show -json plan.bin` (plan 을 JSON 으로 — **우리 V5·V6 가 읽는 파일**), `terraform output`, `terraform state list`, `terraform console` (식 계산기).

plan 출력의 기호: `+` 생성, `-` 삭제, `~` 제자리 수정, `-/+` **교체**(지우고 다시 만듦 — 위험도 기준표에서 hard HIGH). SG 의 `name` 을 바꾸면 `-/+` 가 된다 (`policy/risk_rubric.json` 의 replace_forcing_attributes).

**직접 해 보기(자격증명 없이)**: `IaCPatch-console.exe --exec scripts/arch_scan.py` 를 돌리고 `data\arch\<id>\plan.json` 을 메모장으로 열어 `"resource_changes"` 안에서 `"address": "aws_security_group.web"` 을 찾아 `"actions": ["create"]` 와 `ingress` 의 `cidr_blocks` 를 눈으로 확인한다. 이것이 V6 가 읽는 바로 그 값이다.

## 5. state 와 lock 파일 — 시연 때 교수가 물을 것

- `terraform.tfstate`: Terraform 이 "내가 만든 것이 무엇이고 ID 가 뭔지" 를 적어 두는 JSON. **이게 있어야 destroy 가 된다.** 비밀값이 들어갈 수 있어 git 에 안 올린다(`.gitignore`). 팀 작업이면 S3 backend 로 공유하지만 이 시연은 로컬 파일.
- `.terraform.lock.hcl`: provider 의 정확한 버전과 해시. 같은 버전을 모두가 쓰게 한다. 우리는 `versions.tf` 에서 5.100.0 으로 못 박았다 (D-15 — 안 박으면 6.x 가 받아져 V5 오탐이 났던 실측 2026-09-29).
- `.terraform/`: 내려받은 provider 바이너리 (수백 MB). git 에 안 올린다.

## 6. 변수 — 어디서 값이 오나

우선순위(뒤가 이김): `variables.tf` 의 `default` → `terraform.tfvars` 파일 → `*.auto.tfvars` → `-var`/`-var-file` 옵션 → 환경변수 `TF_VAR_이름`.
우리 구성: 평소(파이프라인·Trivy)는 default 로 돌고, 실제 apply 만 `terraform.tfvars` 에 `ami_id`·`bucket_name` 을 적는다. `validation { }` 블록은 잘못된 값(예: `ami-` 로 안 시작)을 plan 단계에서 막는다.

## 7. 보안 그룹 블록을 읽는 법 (우리 연구의 핵심 줄)

```hcl
ingress {                               # 들어오는 규칙 하나
  description = "SSH for administration"
  from_port   = 22                      # 포트 범위 시작
  to_port     = 22                      # 포트 범위 끝 (같으면 포트 하나)
  protocol    = "tcp"                   # "-1" 이면 모든 프로토콜
  cidr_blocks = ["0.0.0.0/0"]           # 출처 IP 대역 목록. /0 = 모든 주소
}
```
출처는 네 가지로 적을 수 있다: `cidr_blocks`(IPv4 대역), `ipv6_cidr_blocks`, `security_groups`(다른 SG 의 ID — app SG 가 쓴 방식), `prefix_list_ids`. **V6 Intent Oracle 은 네 가지를 전부 합쳐 "결국 어떤 범위가 들어올 수 있나" 를 계산**한다. `0.0.0.0/1` + `128.0.0.0/1` 을 합치면 `0.0.0.0/0` 이라는 것을 Trivy 는 모르고 V6 는 안다.

CIDR 읽기: `10.0.0.0/8` = 앞 8비트 고정 → 10.x.x.x 전부(약 1,677만 개). `/16` = 10.0.x.x, `/24` = 10.0.1.x (256개), `/32` = 주소 하나, `/0` = 전부.

## 8. IAM 정책 블록을 읽는 법

```hcl
policy = jsonencode({
  Version = "2012-10-17"                # 정책 문법 버전 (고정 문자열)
  Statement = [{
    Sid      = "AssetsAccess"           # 문장 이름 (선택)
    Effect   = "Allow"                  # Allow / Deny
    Action   = ["s3:*"]                 # 무엇을 — 서비스:동작. * 는 전부
    Resource = "*"                      # 어디에 — ARN. * 는 전부
  }]
})
```
최소 권한 = Action 과 Resource 를 필요한 것만: `["s3:GetObject", "s3:ListBucket"]` on `["arn:aws:s3:::버킷", "arn:aws:s3:::버킷/*"]`. 신뢰 정책(`assume_role_policy`)은 "누가 이 역할을 맡나" 이고 권한 정책(`policy`)은 "맡은 뒤 무엇을 하나" — 둘을 섞어 말하지 않는다. 신뢰 정책을 `Principal = "*"` 로 바꾸면 아무나 역할을 맡을 수 있어 기준표에서 hard HIGH.

## 9. 흔한 오류 메시지 → 뜻

| 메시지 | 뜻 |
|---|---|
| `Reference to undeclared resource` | 오타. `aws_security_group.wep` 처럼 없는 주소 |
| `Unsupported argument` | 그 리소스 타입에 없는 인자 이름 (provider 문서 확인) |
| `Missing required argument` | 꼭 필요한 인자 빠짐 (예: aws_subnet 에 vpc_id 없음) |
| `Duplicate attribute` | 같은 인자를 두 번 적음 (실습 4단계에서 Trivy 가 이 파일을 건너뛰고 '경고 없음' 이라 한 사건 — V1 ERROR 처리의 이유) |
| `Error: Inconsistent dependency lock file` | lock 과 versions.tf 가 다름 → `terraform init -upgrade` 가 아니라 **왜 다른지** 먼저 확인 |
| `Error: creating EC2 Instance: InvalidAMIID.NotFound` | AMI ID 가 이 리전에 없음 |

## 10. 안 보고 답하기 — 10문제 (답은 아래)

1. `resource "aws_subnet" "public"` 에서 `aws_subnet.public` 은 무엇이고 `public` 은 누가 정했나?
2. `vpc_id = aws_vpc.main.id` 한 줄이 만드는 순서에 미치는 영향은?
3. `plan` 과 `apply` 의 차이. 둘 중 AWS 에 리소스를 만드는 것은?
4. `cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"]` 이 사실상 무엇과 같은가? Trivy 와 V6 중 누가 아는가?
5. app SG 가 출처를 IP 대역이 아니라 `security_groups = [aws_security_group.web.id]` 로 적은 이유는?
6. `depends_on` 을 storage.tf 에서 쓴 이유는?
7. `terraform.tfstate` 를 지우면 무슨 일이 생기나?
8. provider 버전을 5.100.0 으로 못 박은 이유(실측 사건)는?
9. `jsonencode` 가 iam.tf 에 있는 이유는?
10. `-/+` 기호가 plan 에 보이면 위험도 기준표에서 무슨 일이 생기나?

답: ① 리소스 주소(타입.이름); 이름은 내가 붙임 ② VPC 가 먼저 만들어지고 서브넷은 그 ID 를 받아 뒤에 만들어진다 ③ plan 은 계산만, apply 가 실제 생성 ④ `0.0.0.0/0`(인터넷 전체); V6 만 안다(합집합 계산), Trivy 는 표기만 봄 ⑤ "웹 서버에서 온 것만" 을 IP 로 적으면 IP 가 바뀔 때 깨지지만 SG 참조는 웹 SG 가 붙은 인스턴스 전부를 자동으로 가리킨다 ⑥ 버킷 정책은 퍼블릭 차단이 풀린 뒤에 적용돼야 하는데 참조가 없어 순서가 자동으로 안 잡히므로 ⑦ Terraform 이 자기가 만든 것을 잊는다 — destroy 가 안 되고 다시 apply 하면 중복 생성 시도 ⑧ 안 박으면 그때그때 최신(6.x)이 받아져 원본 plan 과 패치 plan 의 provider 가 달라졌고 6.x 의 `region` 속성을 V5 가 변경으로 오인했다(2026-09-29 팀 PC) ⑨ IAM 정책 인자는 JSON 문자열이어야 해서 HCL 맵을 JSON 으로 바꿈 ⑩ 교체(삭제+생성)이므로 점수와 무관하게 HIGH.

## 11. 더 읽을 것 (원문 문서 — 우리 파일에 쓰인 리소스만)

- Terraform 언어: https://developer.hashicorp.com/terraform/language (블록·식·함수)
- AWS provider 리소스 문서: https://registry.terraform.io/providers/hashicorp/aws/5.100.0/docs — `aws_security_group`, `aws_instance`, `aws_s3_bucket_public_access_block`, `aws_iam_policy` 네 페이지의 "Argument Reference" 만 읽으면 우리 파일의 인자는 전부 나온다.
