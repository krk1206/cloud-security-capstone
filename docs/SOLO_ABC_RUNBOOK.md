# 혼자 A·B·C 전부 하기 — 아키텍처 과제를 끝까지 (B, 2026-10-04)

B 요청(10-04): "일단 내가 A·B·C 다 해놓게 해주고 알려줘". 운영계획서 역할은 A(AWS·Terraform·V1~4·V7) / B(AI 후보·V6·위험도) / C(Actions·PR·승인·V5·V8·평가) 지만, 이번 아키텍처 과제는 B 혼자 끝까지 간다. 이 문서는 그 순서다. **각 단계 끝의 "보고" 를 보내 주면 다음 단계 문제를 같이 본다.**

원칙 (바뀌지 않음): 돈 0원(프리 티어 안, 끝나면 destroy) · 자격증명은 환경변수로만 · 사람 확인 없는 apply 없음 · 결과는 그대로 기록(실패도) · 유료 LLM API·자동 모델 호출 없음.

| 단계 | 원래 담당 | 네가 하는 것 | 걸리는 시간 |
|---|---|---|---|
| 0 코드 올리기·빌드 | B·C | push → CI → 새 빌드 | 15분 (대기 포함) |
| 1 AWS 계정·키·CLI | A | 본인 계정(프리 플랜) + IAM 사용자 + 키 + AWS CLI | 40분 |
| 2 점검·해석·후보 | B | arch_scan → Claude Code 해석 등록 → Claude Code 패치 후보 | 40분 |
| 3 취약 원본 apply + "전" 측정 | A·C | init/plan/apply → 캡처 → V7/V8 (FAIL 이 정답) | 40분 |
| 4 PR → 승인 → 병합 | C | `pr --review` 미리보기 → GitHub Desktop 으로 브랜치·PR → `sandbox` 브랜치에 병합 | 30분 |
| 5 패치 apply + "후" 측정 | A·C | plan(1 change) → apply → V7/V8 (PASS 가 정답) | 20분 |
| 6 정리 | A | destroy → 키 비활성화 → 요금 0 확인 → 기록 | 15분 |

AWS 계정은 1단계가 끝나야 3단계부터 가능하다. 2단계는 계정 없이 된다 — **1단계 가입 심사를 기다리는 동안 2단계를 한다.**

---

## 0단계 — 코드 올리기·빌드 (B·C)

1. 받은 `cloud-security-capstone-with-git.zip` 을 빈 새 폴더에 풀기 → GitHub Desktop → File → Add local repository → 그 폴더 → **Push origin**.
2. https://github.com/krk1206/cloud-security-capstone/pull/4 의 Checks 가 다 돌 때까지(약 10분). `build-exe` 가 초록이면 Release `dev-latest` 가 새 것으로 바뀐다.
3. 쓰던 IaCPatch 화면 → 도구 탭 → **업데이트 확인 → 새 빌드 받아서 실행** (또는 https://github.com/krk1206/cloud-security-capstone/releases/tag/dev-latest 에서 zip). 새 폴더 `IaCPatch-<7자리>` 가 생긴다. **이제부터 모든 명령은 이 폴더에서.**
4. 새 폴더 빈 곳에서 Shift+우클릭 → "여기에 PowerShell 창 열기" →
   ```powershell
   .\IaCPatch-console.exe --exec scripts/arch_scan.py
   ```
   마지막 줄에 `결과: ...\data\arch\<id>` 가 나오고, 그 위 줄에 `finding 18개` 면 정상.

**보고**: PR #4 체크 색깔, 새 폴더 이름, arch_scan 마지막 3줄.

---

## 1단계 — AWS 계정·키·CLI (A 역할) — 돈 0원

### 1-1 계정 (A 가 샌드박스 IAM 사용자를 바로 못 주면 본인 계정으로)

- https://aws.amazon.com/free → "무료 계정 생성". 이메일·비밀번호·계정 이름 → 연락처(개인) → **카드 등록**(본인 확인, 1달러 안팎 임시 승인 후 취소) → 휴대폰 인증 → 플랜 선택에서 **무료 플랜(Free plan)** → 완료. 심사·활성화에 몇 분~수십 분.
- 2025-07-15 이후 새 계정: 100달러 크레딧(활동으로 +100), 6개월, **유료 플랜으로 올리지 않는 한 청구 없음** (AWS 공지: https://aws.amazon.com/about-aws/whats-new/2025/07/aws-free-tier-credits-month-free-plan/). `[확인 필요: 가입 화면의 현재 문구]`
- 이미 A 가 샌드박스 계정을 운영 중이고 IAM 사용자를 금방 받을 수 있으면 그쪽이 더 낫다(`AWS_ACCESS_SETUP_B.md` 1절 문장). 둘 다 가능하면 **A 의 계정** — 팀 자산으로 남는다.

### 1-2 루트 보호 (가입 직후, 5분)

콘솔 오른쪽 위 계정 이름 → 보안 자격 증명 → **MFA 할당**(휴대폰 인증 앱). 루트로는 이것과 1-3 까지만 하고 다시는 루트로 로그인하지 않는다.

### 1-3 예산 알림 (3분)

콘솔 검색 → Billing and Cost Management → Budgets → 예산 생성 → 템플릿 "제로 지출 예산" 또는 월 **1달러** → 이메일. (프리 티어 안이라도 켠다 — 뭔가 새면 메일로 안다.)

### 1-4 IAM 사용자 (10분)

콘솔 검색 → IAM → 사용자 → 사용자 생성
- 이름 `b-boseong` → "AWS Management Console 에 대한 사용자 액세스 권한 제공" 체크 → "IAM 사용자를 생성하고 싶음" → 콘솔 비밀번호 자동 생성 → 다음
- 권한: "직접 정책 연결" → `AmazonEC2FullAccess`, `AmazonS3FullAccess` 체크 → 다음 → 사용자 생성
- 만든 사용자 → 권한 탭 → 권한 추가 → **인라인 정책 생성** → JSON 탭 → `docs/AWS_ACCESS_SETUP_B.md` 1절의 JSON 붙여넣기 → 이름 `terraform-iam-min` → 생성
- 콘솔 로그인 주소(`https://<계정 12자리>.signin.aws.amazon.com/console`)·비밀번호를 받아 **IAM 사용자로 다시 로그인**

### 1-5 액세스 키 (3분)

IAM → 사용자 → `b-boseong` → 보안 자격 증명 탭 → 액세스 키 만들기 → "Command Line Interface(CLI)" → 확인 체크 → 다음 → 만들기 → **액세스 키 / 비밀 액세스 키** 가 한 번만 보인다. 바로 1-7 에 쓴다. 어디에도 저장하지 않는다(.csv 받았으면 저장소 밖에).

### 1-6 AWS CLI v2 설치 (5분, V7 의 describe-security-groups 에 필요)

https://awscli.amazonaws.com/AWSCLIV2.msi 받아 설치 → PowerShell **새 창** → `aws --version` 이 `aws-cli/2.x` 면 됨.

### 1-7 자격증명 넣기 (매 PowerShell 창마다)

```powershell
$env:AWS_ACCESS_KEY_ID     = "액세스 키"
$env:AWS_SECRET_ACCESS_KEY = "비밀 액세스 키"
$env:AWS_DEFAULT_REGION    = "ap-northeast-2"
aws sts get-caller-identity
```
`Arn` 에 `user/b-boseong` 이 나오면 끝. (출력의 Account 번호는 보고에 뒷 4자리만.)

**보고**: `aws --version` 한 줄, `get-caller-identity` 의 Arn 끝부분(`user/b-boseong`), 예산 알림 캡처.

---

## 2단계 — 점검·해석·후보 (B 역할, 계정 불필요)

### 2-1 AI 해석 (교수 지시 5번째)

1. `data\arch\<id>\interpret_prompt.md` 를 메모장으로 열고 **전체 복사**.
2. Claude Code 를 **저장소 새 폴더에서 새 세션**으로 열고 붙여넣기(또는 Claude 앱). 응답이 JSON 하나로 오면 → 메모장에 붙여 `data\arch\<id>\response.json` 으로 저장(UTF-8). Claude Code 가 직접 그 경로에 저장했으면 그대로.
3. 등록:
   ```powershell
   .\IaCPatch-console.exe --exec scripts/arch_interpret_add.py data\arch\<id> data\arch\<id>\response.json --note "2026-10-xx Claude Code, 모델 표시 <화면에 보이는 대로>"
   ```
   출력의 `해석된 실제 finding N/17 · 지어낸 finding · 누락 · CIS 불일치` 숫자가 결과다. `data\arch\<id>\interpretation.md` 를 열어 "Trivy 가 잡지 않았지만 AI 가 위험하다고 본 것" 에 **버킷 정책 Principal "*"** 가 있는지 본다 — 있으면 AI 가 스캐너 사각을 찾은 것, 없으면 못 찾은 것. 둘 다 기록.

### 2-2 Claude Code 패치 후보 (운영계획서 B 항목 — 지금까지 0건)

```powershell
.\IaCPatch-console.exe --exec scripts/cc_prompt.py arch-sg      # 화면에 프롬프트 → 복사 → Claude Code 새 세션 → 응답 저장 resp-sg-1.md
.\IaCPatch-console.exe --exec scripts/cc_add.py arch-sg resp-sg-1.md --rep 1 --expected correct --note "2026-10-xx 세션1"
```
`--expected` 는 **응답 diff 를 보고 네가 적는 라벨**(correct / deceptive / unapproved / breaks_required / invalid). 등록 전 diff 가 화면에 뜨니 22 번이 `10.0.0.0/8` 로만 바뀌었으면 correct. 같은 식으로 `arch-iam` 도(규칙 기반이 거부한 케이스라 비교 가치가 크다). 각 2~3회(`--rep 2`, `3`).
검증: 화면 **5주차 탭 → 세트 `eval-claude-code` → 후보 `cc-arch-sg-r1` → 실행** → V1~V6·위험도·검토 수준.

**보고**: 해석 등록 출력 숫자, interpretation.md 의 not_flagged 절, 후보별 검토 수준(LIGHT/FULL/BLOCKED).

---

## 3단계 — 취약한 원본을 샌드박스에 apply + "전" 측정 (A·C 역할)

### 3-1 준비

- 콘솔(IAM 사용자) → EC2 → **인스턴스 시작** 화면 → "Amazon Linux 2023 AMI" 아래의 `ami-0…` 복사 → 시작하지 말고 나오기.
- PowerShell (1-7 환경변수 넣은 창):
  ```powershell
  cd <새 폴더>\scenarios\arch\webapp-2tier
  $env:Path = "<새 폴더>\tools;" + $env:Path
  $env:TF_PLUGIN_CACHE_DIR = "<새 폴더>\tools\plugin-cache"
  copy terraform.tfvars.example terraform.tfvars
  notepad terraform.tfvars          # ami_id 를 복사한 값으로. instance_type 은 건드리지 않는다(t2.micro)
  ```

### 3-2 실행 시연 (교수 지시 3번째 — 이 화면을 캡처)

```powershell
terraform init
terraform validate
terraform plan -out plan.bin        # "Plan: 17 to add, 0 to change, 0 to destroy."
terraform apply plan.bin            # 2~3분. "Apply complete! Resources: 17 added"
terraform output                    # web_url, web_public_ip, app_private_ip, web_security_group_id
```
브라우저에서 `web_url` → "iacpatch-webapp web tier" 페이지(1~2분 뒤 새로고침). **= 정상 기능의 기준값.**

콘솔 캡처 5장: EC2 인스턴스 2대 / 웹 SG 인바운드(22 가 0.0.0.0/0) / S3 버킷 권한(차단 꺼짐·정책 Principal *) / IAM 역할 정책(s3:*) / VPC 리소스 맵.

### 3-3 "전" 측정 — 설정 오류가 실제로 뚫리는지 (V7·V8, FAIL 이 정답)

저장소 새 폴더로 돌아와서(같은 창, 환경변수 유지):
```powershell
cd <새 폴더>
.\IaCPatch-console.exe --exec scripts/arch_v8_checks.py --web-ip <output web_public_ip> --app-ip <output app_private_ip>
.\IaCPatch-console.exe --exec scripts/iacpatch_cli.py postdeploy --intent experiments/candidate-sets/arch-webapp-sg/intents/arch-webapp-sg.json --tf-dir scenarios/arch/webapp-2tier --v8-checks scenarios/arch/webapp-2tier/sandbox/v8-checks.json --execute
```
기대: **V7 FAIL**(실제 AWS 의 웹 SG 에 22 ← 0.0.0.0/0 이 있어 승인 밖) + **V8 FAIL**(이 PC 는 승인 대역 10.0.0.0/8 밖인데 22 가 열림) → `DEPLOY_FAILED`. 이게 "코드의 설정 오류가 실제 인프라의 설정 오류다" 의 측정값. 기록 폴더 `data\runs\<id>` 이름을 적어 둔다.

**보고**: plan/apply 마지막 줄, web_url 화면, 캡처 5장, postdeploy 출력 전체.

---

## 4단계 — PR → 승인 → 병합 (C 역할) — `sandbox` 브랜치로

왜 `sandbox` 브랜치인가: main 과 B 브랜치의 `scenarios/arch/webapp-2tier` 는 **실험 재료(취약한 상태)로 남아야** 후보 세트가 계속 돈다. 샌드박스에 실제로 올라간 상태는 `sandbox` 브랜치가 들고 있는다(배포 브랜치).

1. 패치 기록 만들기: 화면 **5주차 탭 → `arch-webapp-sg` → 규칙 기반 생성 → 실행** → `LIGHT_REVIEW · LOW` 와 기록 id(`20261xxx-xxxxxx-xxxxxx`).
2. PR 재료 미리보기:
   ```powershell
   .\IaCPatch-console.exe --exec scripts/iacpatch_cli.py pr --review <기록 id> --base sandbox
   ```
   브랜치 이름·제목·`pr_body.md`·`commit_message.txt` 경로가 나온다(실행은 안 함).
3. GitHub Desktop 에서 (명령 대신 클릭으로):
   1. Current branch → `claude/iacpatch-sg-slice` 선택 → New branch `sandbox` → Publish branch. (처음 한 번)
   2. New branch → 이름은 2번 출력의 `branch :` 값 → 기준 `sandbox`.
   3. 탐색기에서 `data\reviews\<기록 id>\candidate\security_groups.tf` 를 복사해 `scenarios\arch\webapp-2tier\security_groups.tf` 에 덮어쓰기.
   4. Desktop 에 변경 1파일 보임 → Summary 에 `commit_message.txt` 첫 줄 → Commit → Publish branch.
   5. Desktop 의 "Create Pull Request" → 웹에서 **base 를 `sandbox` 로 바꾸고** 본문에 `pr_body.md` 내용 붙여넣기 → Create.
4. Actions 의 `iacpatch-verify` 가 PR 에 검증 표 댓글을 단다(수 분). 같은 PR 에 댓글 "승인: 김보성 — LIGHT_REVIEW, 위험도 LOW, V1~V6 PASS, 전 측정 DEPLOY_FAILED(기록 id)" 를 남기고 **Merge pull request**. (본인 PR 은 Approve 버튼을 못 누른다 — 병합 자체가 사람 승인 기록이다.)
5. Desktop → Current branch `sandbox` → Fetch/Pull. 이제 로컬 `scenarios\arch\webapp-2tier\security_groups.tf` 가 패치본이다.

**보고**: PR 링크, verify 댓글 캡처, 병합 화면.

---

## 5단계 — 패치 apply + "후" 측정 (A·C 역할)

```powershell
cd <새 폴더>\scenarios\arch\webapp-2tier       # 3-1 의 환경변수가 든 창
terraform plan -out plan.bin                   # "Plan: 0 to add, 1 to change, 0 to destroy." — SG 하나만 제자리 수정(교체 아님)
terraform apply plan.bin
cd <새 폴더>
.\IaCPatch-console.exe --exec scripts/iacpatch_cli.py postdeploy --review <4-1 의 기록 id> --intent experiments/candidate-sets/arch-webapp-sg/intents/arch-webapp-sg.json --v8-checks scenarios/arch/webapp-2tier/sandbox/v8-checks.json --execute
```
기대: **V7 PASS**(22 ← 10.0.0.0/8 만) + **V8 PASS**(80 열림, 22·3389·8080 은 이 PC 에서 막힘) → `VERIFIED`. 브라우저 `web_url` 이 여전히 뜨면 정상 기능 보존. 콘솔 SG 인바운드 캡처(22 가 10.0.0.0/8).

plan 이 `1 to change` 가 아니면 멈추고 보고(다른 게 바뀐다는 뜻).

**보고**: plan 한 줄, postdeploy 출력 전체, SG 캡처.

---

## 6단계 — 정리 (A 역할) — 시연 당일 안에

```powershell
cd <새 폴더>\scenarios\arch\webapp-2tier
terraform destroy                              # yes → "Destroy complete! Resources: 17 destroyed."
```
→ IAM → 액세스 키 **비활성화** → Billing 에서 요금 0 / 크레딧 차감액 확인 → 보고. 다음 시연 때 키를 다시 활성화하면 된다.

`terraform.tfvars`·`terraform.tfstate`·`sandbox\v8-checks.json` 은 git 에 안 올라간다(.gitignore). state 는 destroy 가 끝날 때까지 지우지 않는다.

---

## 보고 뒤 내가 하는 것

worklog(날짜)·`experiments/arch-webapp-2tier/RESULTS.md` 5절(apply 1회, V7/V8 기록 id)·주간보고 숫자 갱신·D-16 보완 → 새 zip. 발표 문장은 `docs/ARCH_WEBAPP_2TIER.md` 6절에 "전/후 측정" 한 문단을 추가한다.

## 막히면

| 어디서 | 증상 | 할 일 |
|---|---|---|
| 1-1 | 카드 없음 / 가입 심사 지연 | A 의 샌드박스 IAM 사용자로(`AWS_ACCESS_SETUP_B.md` 1절), 또는 학과 AWS Academy 여부를 교수께 |
| 1-7 | `get-caller-identity` 가 InvalidClientTokenId | 키를 잘못 붙여 넣음(앞뒤 공백). 새 창에서 다시 |
| 3-2 | `InvalidAMIID`, `BucketAlreadyExists`, `AccessDenied`, S3 정책 `AccessDenied` | `AWS_ACCESS_SETUP_B.md` 6절 표 |
| 3-2 | `Unsupported ... t2.micro ... Availability Zone` | tfvars 에 `availability_zone = "ap-northeast-2c"` 추가해 재시도 |
| 3-3 | V7 `cannot map target addresses to GroupIds` | apply 가 안 됐거나 다른 폴더에서 실행. `terraform state list` 로 확인 |
| 3-3 | V8 web-http-open FAIL | 부팅 직후. 2분 뒤 재실행. 계속이면 user_data 의 nginx 설치 실패 — 콘솔 EC2 → 인스턴스 → 모니터링/시스템 로그 |
| 4 | Desktop 에 변경이 80개 | 그 폴더가 zip 에서 푼 새 클론이 아님. zip 폴더로 |
| 5 | plan 이 1 change 가 아님 | 멈추고 plan 출력 전체 보고 |
