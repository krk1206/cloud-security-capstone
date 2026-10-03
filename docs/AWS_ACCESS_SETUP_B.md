# AWS 계정 접근 만들기 + Terraform 실행 시연 순서 (B 용, 2026-10-02)

지도교수 9/29: "AWS 환경에서 네가 Terraform 으로 실행시키는 것까지 보여 준다 — 만들어지는지". 그러려면 B 의 손에 (1) AWS 계정 로그인, (2) Terraform 이 쓸 액세스 키가 있어야 한다. 지금 둘 다 없다(2026-10-02 B 답변 "만드는 방법좀").

**원칙**: 자격증명(액세스 키)은 파일·채팅·저장소에 절대 적지 않는다. 환경변수로만 쓰고, 시연 뒤 키를 비활성화한다. 이 저장소의 AI 세션은 AWS 에 접속하지 않고 apply 도 하지 않는다 — **apply 는 B 가 직접** 한다 (CLAUDE.md, 운영계획서 "사람 확인 없는 apply 금지").

## 0. 돈이 드나? — 안 들게 설계했다 (B 질문 2026-10-02)

이 아키텍처는 **프리 티어 안에 들어가도록 일부러** 만들었다: NAT 게이트웨이·RDS·로드밸런서 없음, EC2 는 t2.micro 2대(서울 프리 티어 대상, 월 750시간 무료), S3 는 빈 버킷(5GB 무료), VPC·서브넷·IGW·SG·IAM 은 원래 무료.

| 계정 종류 | 시연 1시간 비용 | 조건 |
|---|---|---|
| 팀 샌드박스(운영계획서 "예산 0원, 프리 티어 안") — 만든 지 12개월 안 | **0원** | `instance_type` 기본값 t2.micro 그대로. 퍼블릭 IPv4 도 12개월 750시간 무료 |
| 같은 계정인데 12개월 지남 | 퍼블릭 IPv4 1시간 ≈ 0.005달러(약 7원) + t2.micro 2시간 ≈ 0.023달러 `[확인 필요: 요금표]` | 수십 원. 예산 알림 1달러면 충분 |
| 2025-07-15 이후 새 계정(프리 플랜) | **청구 0원** — 100달러 크레딧에서 0.05달러쯤 차감 | 유료 플랜으로 올리지 않는 한 요금이 발생하지 않음. 카드 등록은 본인 확인용 |
| 학교 AWS Academy / AWS Educate 실습 계정 | 0원, 카드도 불필요 | **학과에 있는지 교수님께 확인** `[확인 필요]` |

돈이 **나가는 경우**는 딱 셋: ① destroy 를 안 해서 며칠 켜 둠(2대 × 24시간 × 30일 = 1,440시간 > 750시간 무료) ② instance_type 을 큰 것으로 바꿈 ③ NAT·RDS 같은 걸 추가. 시연 뒤 `terraform destroy` + 예산 알림이 안전장치다.

AWS 없이 하는 방법(LocalStack 같은 로컬 에뮬레이터)은 "AWS 에서 만들어지는지 보여 달라" 는 지시를 충족하지 못한다(EC2 가 가짜, Docker 설치 필요). 계정이 끝내 안 될 때의 임시 대체로만, 그때도 "에뮬레이터" 라고 밝힌다.

## 1. 계정 — 두 경로 중 하나

### 경로 A (권장): 팀 샌드박스 계정에 B 의 IAM 사용자 만들기

운영계획서상 AWS Sandbox 는 A(김윤재) 담당이다. A 에게 다음을 그대로 보내면 된다.

> 교수님 지시로 내가 Terraform apply 시연을 해야 해. 샌드박스 계정에 내 IAM 사용자 하나 만들어 줘.
> - 사용자 이름: `b-boseong` (아무거나)
> - 콘솔 로그인: 켜기 (임시 비밀번호, 첫 로그인 때 변경)
> - 권한: `AmazonEC2FullAccess`, `AmazonS3FullAccess` + 아래 IAM 인라인 정책 (역할·정책·인스턴스 프로필 만들고 지우는 것만)
> - 액세스 키: "Command Line Interface(CLI)" 용도로 하나. 키는 **채팅으로 보내지 말고** 콘솔에서 내가 직접 만들게 로그인만 넘겨 줘.
> - 계정에 예산 알림(월 5달러) 켜져 있는지, 계정 수준 S3 퍼블릭 액세스 차단이 켜져 있는지도 알려 줘.

IAM 인라인 정책 (Terraform 이 `iam.tf` 의 역할·정책·인스턴스 프로필을 만들고 지우는 데 필요한 액션. 부족하면 apply 오류 메시지에 액션 이름이 나오니 그걸 추가한다):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:PassRole", "iam:TagRole", "iam:ListRoleTags",
      "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:ListInstanceProfilesForRole",
      "iam:CreatePolicy", "iam:DeletePolicy", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions", "iam:DeletePolicyVersion",
      "iam:ListEntitiesForPolicy", "iam:TagPolicy", "iam:ListPolicyTags", "iam:UpdateAssumeRolePolicy",
      "iam:AttachRolePolicy", "iam:DetachRolePolicy",
      "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:GetInstanceProfile",
      "iam:AddRoleToInstanceProfile", "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile", "iam:ListInstanceProfileTags"
    ],
    "Resource": "*"
  }]
}
```

시간이 없으면 샌드박스 한정으로 `IAMFullAccess` 를 붙여도 되지만, 교수께 "왜 전체 권한을 줬나" 를 물으면 답이 없으니 위 목록을 권한다. (`AdministratorAccess` 는 사람에게도 주지 않는 것이 이 프로젝트의 신뢰 경계와 일관된다.)

### 경로 B: B 본인 계정 새로 만들기 (A 가 못 해 줄 때)

- https://aws.amazon.com/free 에서 가입. **신용/체크카드 등록이 필요하다** (본인 확인용 소액 승인 후 취소).
- 2025-07-15 이후 새 계정은 "프리 플랜": 가입 시 100달러 크레딧 + 활동으로 100달러 추가(최대 200달러), **6개월 또는 크레딧 소진 중 먼저 오는 때까지**, 그 안에서는 유료 플랜으로 올리지 않는 한 **청구가 발생하지 않는다** (AWS 공지 2025-07-16: https://aws.amazon.com/about-aws/whats-new/2025/07/aws-free-tier-credits-month-free-plan/). `[확인 필요: 가입 화면에서 현재 조건 그대로인지]`
- 가입 직후 할 것 (순서대로): ① 루트 계정에 MFA 켜기 (IAM → 루트 사용자 MFA) ② Billing → 예산(Budgets) → 월 5달러 알림 ③ IAM → 사용자 → `b-boseong` 만들기 (경로 A 의 권한과 동일) ④ 이후 루트로는 로그인하지 않고 IAM 사용자로만.
- 시연이 끝나면 리소스를 전부 지우고(아래 5절) Billing 에서 요금 0 인지 확인.

## 2. 액세스 키 만들기 (경로 A·B 공통, IAM 사용자로 로그인한 뒤)

IAM → 사용자 → 내 사용자 → **보안 자격 증명** 탭 → 액세스 키 만들기 → 용도 "Command Line Interface(CLI)" → 확인 → **액세스 키 ID / 비밀 액세스 키** 가 화면에 한 번만 보인다. 비밀 키는 다시 못 보니 그 자리에서 아래 3절에 쓴다. (.csv 다운로드는 해도 되지만 저장소 폴더 안에는 두지 않는다 — `.gitignore` 에 `*credentials*.csv` 가 있어도 습관적으로 밖에 둔다.)

## 3. 팀 PC 에 자격증명 넣기 — 환경변수로만 (PowerShell 창 하나에서만 유효)

```powershell
$env:AWS_ACCESS_KEY_ID     = "여기에 액세스 키 ID"
$env:AWS_SECRET_ACCESS_KEY = "여기에 비밀 액세스 키"
$env:AWS_DEFAULT_REGION    = "ap-northeast-2"
```
- 창을 닫으면 사라진다. 매번 다시 넣는다. 파일(.env, tfvars, 메모장)에는 안 적는다.
- Terraform 은 이 세 변수를 자동으로 읽는다. AWS CLI 설치는 필요 없다 (V7 의 `describe-security-groups` 를 돌릴 때는 필요 — 그건 A 담당).

## 4. 실행 시연 순서 (교수 앞에서 치는 명령 — 순서대로, 각 줄의 뜻은 `docs/TERRAFORM_STUDY_B.md` 4절)

준비 (한 번): 콘솔 EC2 → 인스턴스 시작 화면에서 "Amazon Linux 2023" 의 AMI ID(`ami-0…`, 서울 리전) 를 복사해 둔다.

```powershell
cd <저장소 폴더>\infrastructure\webapp-2tier
$env:Path = "<저장소 폴더>\tools;" + $env:Path       # tools\terraform.exe (1.16.1) 를 쓰게
$env:TF_PLUGIN_CACHE_DIR = "<저장소 폴더>\tools\plugin-cache"   # exe 가 이미 받아 둔 provider 5.100.0 재사용 (없으면 init 이 내려받음, 수십 MB)
copy terraform.tfvars.example terraform.tfvars
notepad terraform.tfvars         # ami_id 를 복사한 값으로, bucket_name 은 그대로(겹치면 뒤에 날짜 붙이기)

terraform init                   # provider 준비. "Terraform has been successfully initialized!"
terraform validate               # 문법·참조 검사. "Success! The configuration is valid."
terraform plan -out plan.bin     # 무엇을 만들지 계산. 마지막 줄 "Plan: 17 to add, 0 to change, 0 to destroy."
terraform apply plan.bin         # 실제 생성 (사람이 치는 유일한 '만드는' 명령). 2~3분. "Apply complete! Resources: 17 added"
terraform output                 # web_url 등 출력
```
→ 브라우저에서 `web_url` 열기: "iacpatch-webapp web tier" 페이지가 보이면 **정상 기능 확인(V8 의 기준)**. 부팅 직후면 1~2분 기다렸다 새로고침.

콘솔에서 보여 줄 것 (캡처해서 주간보고에):
1. EC2 → 인스턴스: `iacpatch-webapp-web`, `iacpatch-webapp-app` 실행 중.
2. EC2 → 보안 그룹 → `iacpatch-webapp-web-sg` → 인바운드 규칙: **22 가 0.0.0.0/0** (설정 오류가 실제로 만들어졌다), 80 이 0.0.0.0/0.
3. S3 → 버킷 → 권한 탭: 퍼블릭 액세스 차단 "꺼짐", 버킷 정책에 `"Principal": "*"`. (목록에 "퍼블릭" 표시.)
4. IAM → 역할 → `iacpatch-webapp-web-role` → 권한 정책 `s3:*`.
5. VPC → 리소스 맵: VPC·서브넷 2·IGW·라우트 테이블.

이 네 가지가 "Terraform 코드의 설정 오류가 실제 AWS 설정 오류가 됐다" 의 증거이고, V7(실제 상태 확인)이 읽는 대상이다.

## 5. 끝나면 반드시 — 지우기

```powershell
terraform destroy                # "yes" 입력. "Destroy complete! Resources: 17 destroyed."
```
- 안 지우면 EC2 2대 + 퍼블릭 IPv4 가 계속 돈다. 프리 티어(월 750시간) 안이면 며칠은 0원이지만 한 달 내내면 넘친다(2대 × 720시간 = 1,440시간). 크레딧 플랜이면 크레딧이 줄어든다.
- destroy 가 S3 에서 막히면: 버킷에 객체가 있어도 `force_destroy = true` 라 지워진다. 그래도 막히면 콘솔에서 버킷 비우고 다시.
- 시연이 끝난 키는 IAM → 보안 자격 증명 → 액세스 키 → **비활성화**. 다음 시연 때 다시 활성화.

## 6. 실패했을 때 — 흔한 것 네 가지

| 증상 | 뜻 | 할 일 |
|---|---|---|
| `InvalidAMIID.NotFound` / `InvalidAMIID.Malformed` | ami_id 가 자리표시자 그대로거나 다른 리전 값 | terraform.tfvars 의 ami_id 를 서울 리전 AL2023 ID 로 |
| `InvalidParameterValue ... t2.micro` 류 | 리전·AMI 가 t2.micro 를 지원하지 않음(드묾) | `instance_type = "t3.micro"` 로 (크레딧 플랜이면 비용 차이 무시 가능) |
| `BucketAlreadyExists` | 버킷 이름이 전 세계 누군가와 겹침 | bucket_name 을 `iacpatch-webapp-assets-<이니셜><날짜>` 로. (IAM intent 의 ARN 도 같이 — RESULTS.md 참고) |
| `AccessDenied` + 액션 이름 (예: `iam:CreateInstanceProfile`) | IAM 사용자 권한 부족 | 1절 인라인 정책에 그 액션 추가 (A 에게) |
| `aws_s3_bucket_policy` 에서 `AccessDenied` 인데 위 권한은 다 있음 | **계정 수준** S3 퍼블릭 액세스 차단이 켜져 있어 퍼블릭 정책이 거부됨 | 끄지 않는다. "계정 가드레일이 퍼블릭 정책을 막았다" 로 기록하고 S3 부분만 콘솔 캡처로 대체 — 이것도 결과다 |

`terraform apply` 가 중간에 실패하면 이미 만들어진 리소스는 state 에 남는다. 원인 고친 뒤 `terraform plan -out plan.bin` → `apply plan.bin` 을 다시 하면 나머지만 만든다. 포기할 때도 `terraform destroy` 로 지운다.

## 7. 시연 뒤 저장소에 남길 것 (B)

- `docs/worklog/<날짜>.md`: 명령 출력 요지(Plan 17 / Apply 17 / Destroy 17), web_url 응답 확인, 콘솔 캡처 파일 이름, 걸린 시간, 비용(Billing 화면).
- `experiments/arch-webapp-2tier/RESULTS.md` 5절의 "apply 0회" 를 "1회 (날짜)" 로.
- V7/V8 첫 기록은 A 와 같이: apply 된 상태에서 `postdeploy --review <기록 ID> --execute` (A 의 AWS CLI 필요).
