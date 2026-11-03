# 2차 검사 시험 환경 (축소 3계층)

`scenarios/arch/webapp-3tier` 와 **보안 그룹 파일(security_groups.tf)이 바이트 단위로 같은** 축소 환경이다.
2차 검사 V7(AWS 에서 보안 그룹 읽기)·V8(실제 접속 시험)에 쓴다. 배포·삭제는 사람이 한다 —
화면의 반영 버튼(plan 을 보고 사람이 확인해야 실행, 아래 '순서') 또는 PowerShell.
검사(plan 확인·측정)는 상태 파일 읽기 · AWS 읽기(describe, get-console-output) · 연결 시도만 한다.

## 원본 설계와 다른 점 (발표 때 그대로 말할 것)

| 원본 | 시험 환경 | 이유 |
|---|---|---|
| 웹·API 자동 확장 그룹 | EC2 1대씩 | 측정기를 한 대에 고정 |
| RDS MySQL 주·복제, ElastiCache Redis | 포트만 여는 대역 프로그램 (3306, 6379) | 생성 시간·비용. 보는 것은 "연결이 되나" 뿐 |
| ALB 443 HTTPS (ACM 인증서) | ALB 443 에 HTTP | 도메인·인증서 없음. 보안 그룹 규칙은 같다 |
| 내부 NLB, 비공개 서브넷 2곳 | 내부 NLB, 비공개 서브넷 1곳 | API 서버가 1대(가용 영역 a). NLB 는 대상이 없는 영역의 주소를 DNS 에서 뺀다 |
| NAT 게이트웨이 2개, CloudFront, WAF, Route53, S3, CloudWatch | 없음 | 보안 그룹 판정과 무관 |
| 리전 도쿄(변수 기본값) | 서울 ap-northeast-2 | 팀 샌드박스 허용 리전 |
| (없음) | 측정 지점 2대 추가: 관리자 지점, 인터넷 지점 | 바깥에서 들어오는 통신을 실제로 시험하기 위해 (아래) |
| 서버 이미지 = 변수 `ami_id` (기본값은 자리 표시용 ID) | 서울 리전 최신 AL2023 을 찾아 씀 (`data.aws_ami`, `most_recent`) + 만든 뒤에는 이미지 변경 무시 (`lifecycle { ignore_changes = [ami] }`, 서버 7대) | 원본 기본값으로는 서버를 띄울 수 없다. 만든 뒤 새 AMI 가 나와도 plan 에 서버 교체가 섞이지 않게 — plan 확인에 후보가 바꾼 것(보안 그룹)만 나오도록 (2026-10-25) |

보안 그룹 7개 · 붙는 위치(ALB·웹·NLB·API·Bastion·Redis·MySQL)·공개/비공개 서브넷 배치는 원본과 같다.
측정 지점 2대는 security_groups.tf 와 무관한 자기 보안 그룹(들어오는 규칙 없음)을 쓴다.

## 측정 지점 5곳 (V8)

| 측정 지점 | 위치 | 시험하는 것 |
|---|---|---|
| 웹 서버 | 비공개 서브넷 | → NLB 8080 (열려야), API 8080 직접·MySQL·Redis·Bastion 22 (막혀야) + NLB 경유로 API 의 결과 받기 |
| API 서버 | 비공개 서브넷 | → MySQL 3306·Redis 6379 (열려야), Bastion 22·웹 80·NLB 8080 (막혀야) |
| Bastion | 공개 서브넷, 공인 IP | → 웹 22·API 22 (열려야), MySQL·Redis·NLB 8080·웹 80·API 8080 (막혀야) |
| 관리자 지점 | VPC 보조 대역 198.51.100.0/24 안 (출발 주소 198.51.100.10) | → Bastion 22 (열려야), 웹 22·API 22·MySQL (막혀야) |
| 인터넷 지점 | 공개 서브넷, 공인 IP | → ALB 443 + 웹 첫 화면 (열려야), Bastion 공인 IP 22 (막혀야) |

- 관리자 지점: 설계도의 관리자 허용 목록(203.0.113.0/24, 198.51.100.0/24)은 문서용 예시 대역이라 인터넷에 그 주소를 가진 컴퓨터가 없다.
  그래서 198.51.100.0/24 를 VPC 보조 대역으로 붙이고 그 안에 서버를 둔다 (AWS 는 RFC 1918 밖의 대역도 VPC 대역으로 허용).
  보안 그룹은 출발 주소로 판단하므로 같은 규칙을 시험하지만, 관리자 PC 의 실제 인터넷 경로는 아니다.
- 인터넷 지점: Bastion·ALB 의 **공인** 주소로만 연결한다. 처음에는 별도 VPC 에 두었으나 계정의 인터넷 게이트웨이 한도
  (리전당 기본 5개, VPC 수 한도와 함께 늘어남 — Amazon VPC quotas)에 걸려 시험 VPC 공개 서브넷으로 옮겼다.
  같은 VPC 안에서 공인 주소로 연결할 때 상대 보안 그룹이 보는 출발 주소가 공인 IP 인지 사설 IP 인지는 AWS 문서 문장으로 아직 확인 못 함 (확인 필요).
  어느 쪽이든 관리자 허용 목록 밖이라, 원본(0.0.0.0/0)·허용 목록 2개 규칙에서는 기대값이 같다.
- 결과를 받는 길: 측정기가 목적지를 차례로 시험한 뒤 직렬 콘솔에 `IACPATCH-PROBE {json}` 한 줄을 쓰고 15초 쉰다
  (응답 없음 1건이 3초라 한 바퀴는 약 19~28초 — 2026-10-23 실측). 프로그램이
  `aws ec2 get-console-output --instance-id <id> --latest` (읽기 전용, Nitro 인스턴스)로 읽는다. 보안 그룹을 하나도 열지 않는다.
  웹·API 결과는 이 PC → ALB 443 → 웹 80 `/probe.json` 으로도 받는다 (이 PC 결과는 참고 — 학교망 영향).
- 새로 잰 값만: apply 가 끝나고 2분 뒤부터 측정하고, 측정 시작 때 본 결과 번호(seq)보다 2 이상 커진 결과만 쓴다 (최대 3분 기다림).
  seq+1 이 측정 시작 때 아직 안 보였으므로 seq+2 의 시험은 apply 가 끝나고 '135초 − 콘솔 지연' 뒤에 시작한 것이다.
  콘솔 출력은 실시간이 아니다 — 2026-10-23 실측에서 새 줄이 20~40초 늦게 보인 경우가 있었다 (AWS 문서에는 숫자가 없음).

## 생기는 것 (과금 대상)

EC2 t3.micro 7대 (vCPU 14개 — 계정의 '표준 온디맨드 인스턴스' vCPU 한도가 그보다 커야 한다), ALB 1개, 내부 NLB 1개,
공인 IPv4 (Bastion 1 + 인터넷 지점 1 + ALB 노드 2), VPC 1개(보조 대역 포함)·서브넷 5개·인터넷 게이트웨이 1개, EBS 루트 볼륨 7개.
시간당 요금 (확인한 것만):
- 공인 IPv4: 개당 0.005 USD — "all public IPv4 addresses, whether attached to a service or not", 2024-02-01 부터 (AWS News Blog, 2023-07-28). 4개 → 0.02 USD
- t3.micro 서울 온디맨드: 0.0130 USD (제3자 집계 사이트 DoiT — AWS 요금표로 다시 확인 필요). 7대 → 약 0.091 USD
- ALB·NLB 시간 요금과 사용량(LCU), EBS: 서울 요금표 확인 필요
측정이 끝나면 바로 destroy.

## 순서 — 화면 버튼으로 (2026-10-26 부터, D-19)

5단계 **진행 안내** 카드가 지금 할 작업 하나만 보여 준다: 원본 배포 → 수정 전 측정 → 후보 반영 → 수정 후 측정 → 시험 환경 삭제.
반영 버튼은 먼저 plan 을 만들어 확인 창에 보여 주고(반영 안 함), 사람이 'plan 내용을 확인함' 에 체크하고 **[실행]** 을 눌러야
그 plan 파일 그대로 반영한다 (`terraform apply <plan 파일>`). plan 뒤에 시험 환경 파일이나 상태 파일이 바뀌었으면 실행을 거절한다.
시험 환경 폴더 밖은 바꾸지 못한다. AI(Claude Code)는 이 버튼을 누르지 않는다 (CLAUDE.md 규칙).

1. **[원본 배포 시작]** — 시험 환경 파일을 원본으로 복원한 뒤 plan → 확인 창 '생성 39개' → 실행 (5~8분)
2. 3분 대기 → **[수정 전 측정]** (화면에서 실행한 apply 가 성공하면 '대기 종료 시 자동 측정' 이 켜져 대기가 끝날 때 측정만 자동 시작 — 읽기 전용, 반영 1회당 1회. 안내 카드의 [사용 안 함] 으로 끌 수 있다)
3. **[후보 반영 시작]** — 이 기록의 후보 파일을 넣고 plan 확인 → '보안 그룹 제자리 수정만 포함' 이면 확인 창 → 실행
   (교체·삭제가 나온 후보는 반영하지 않는다 — 2차 결과 '차단'(PLAN_BLOCKED)으로 기록, 진행 표시에 ✕)
4. 2분 대기 → **[수정 후 측정]**
5. **[시험 환경 삭제 (destroy)]** → 확인 창 '리소스 39개 삭제' → 실행 (몇 분 — 실행 로그에 진행 줄이 나온다). 끝나면 시험 환경 파일을 원본으로 자동 복원.
- 개별 조작(시험 환경 파일 교체 · plan 확인 · 원본 apply · 후보 apply · destroy · 측정 · PowerShell 명령)은 5단계 아래 **'수동 조작'**(기본 접힘)에 있다.
- 로그인 세션이 만료됐으면 plan 이 실패하고 화면에 그렇게 나온다 → PowerShell 에서 `aws login --profile capstone` 한 줄만 하고 다시 누른다.
- 기록: `data/testbed_ops.jsonl` (한 줄씩) + `data/testbed_ops/<시각>-<종류>/` (plan 요약 · plan 출력 · apply 출력 · 명령, 계정 번호·공인 IP 가림).
- 화면 서버는 Host 가 127.0.0.1·localhost 가 아니거나 다른 사이트(Origin)에서 온 POST 를 거절한다 — 다른 웹 페이지가 이 버튼 API 를 부르지 못하게.
- 확인한 것 (10-25): 단위 테스트 + 가짜 terraform 으로 화면 버튼 전 과정 43개 항목 (원본 apply · 낡은 plan 거절 · 후보 apply · 교체 후보 차단 · destroy 뒤 원본 복원 · 실행 로그의 계정 번호 가림).
  (10-26): 진행 안내 카드만 눌러 처음부터 끝까지 36개 항목 (apply 수 = 사람이 [실행] 을 누른 수 5/5, terraform destroy 명령 0, 자동 측정은 반영 1회당 1회·읽기 전용).
  (10-27): 아래 '실제 AWS 실행 기록 (2026-10-27)' — 사람이 화면 버튼으로 처음부터 끝까지 실행. 진행 안내 E2E 는 그날 고친 것까지 45개 항목.

### 실제 AWS 실행 기록 (2026-10-27, 사람이 화면 버튼으로 · 기록: `data/testbed_ops.jsonl` · `data/measurements/` · 각 기록의 `postdeploy/` · `plancheck/`)

| 시각 | 작업 | 결과 |
|---|---|---|
| 01:50~01:53 | 원본 배포 (apply) | 생성 39개 · 188.7초 · 상태 파일 리소스 36개 |
| 02:14 | 수정 전 측정 (원본) | 반영 확인 통과 · V7 실패 (설계 외 허용 경로 2개) · V8 25건 중 4건 기대와 다름 → 원본의 기대 결과 (10-23 측정과 같음) |
| 02:16 | sg-desc-replace plan 확인 | **차단** — Bastion 보안 그룹 교체 1개 (description 변경) → apply 안 함, V7·V8 미실행 (PLAN_BLOCKED) |
| 02:38 → 02:40 | pass-rule-desc 반영 → 수정 후 측정 | plan 확인: 제자리 수정 2개 · 교체·삭제 없음 → V7 통과 (정상 통신 경로 9개 · 설계 외 허용 경로 0개) · V8 25건 모두 일치 → **통과** (VERIFIED) |
| 02:47 → 02:49 | pass-two-blocks 반영 → 수정 후 측정 | plan 확인: 제자리 수정 1개 (pass-rule-desc 가 반영된 상태 기준 — 원본 기준 아님) → V7 통과 · V8 25건 모두 일치 → **통과** (VERIFIED) |
| 03:03~03:04 | 시험 환경 삭제 (destroy) | 39개 삭제 · 82초 · 상태 파일 리소스 0개 · 시험 환경 파일 원본 복원 |

- 그날 발견해 고친 것 (화면 동작만 — V7·V8 판정 기준은 그대로):
  1. 시험 환경 파일을 후보 → 원본으로 되돌리자 내용은 배포 상태와 같은데 수정 시각만 새로워져 '파일 변경 후 apply 미실행' 으로 판단 → 원본 재배포 plan 이 '변경 없음' 이라 진행이 막힘 (그날은 수동 조작의 [이 기록의 후보 파일 넣기]로 우회). 이제 내용 기준으로도 판단 (D-21).
  2. destroy plan 의 '준비 완료 · 리소스 39개 삭제' 를 삭제 완료로 읽음 (실제 삭제는 그 뒤 [실행]). 이제 plan 단계 문구는 '삭제 예정' · 확인 창 제목 '실행 전 확인', 실행 없이 닫으면 '취소 — 반영하지 않음' 알림.
  3. 2차 통과 뒤에도 4단계 결론에 '다음 단계: 2차 검사' 가 남아 있었음 → 2차 결과를 적도록 고침.
- 그날의 측정 3건(수정 전 1 · 수정 후 2)은 모두 apply 가 파일 교체보다 나중이라, 1번 수정 전 판단(수정 시각)으로도 측정 조건을 만족했다 — 결과는 고친 내용과 무관.

## 순서 — PowerShell 로 (버튼 대신, 사람이 한다)

```powershell
cd <저장소>\scenarios\arch\webapp-3tier-testbed
aws login --profile capstone              # 로그인 세션이 만료됐을 때만 (브라우저로 로그인)
$env:AWS_PROFILE = "capstone-tf"          # Terraform 용 프로필 (capstone 세션을 빌려 씀)
aws sts get-caller-identity               # Arn 끝이 user/<본인> 인지만 확인 (계정 번호는 공유하지 않는다)
..\..\..\tools\terraform.exe init         # 처음 한 번
..\..\..\tools\terraform.exe apply        # 원본 보안 그룹 그대로. 'Plan: 39 to add' 확인 후 yes. 5~8분
```

1. apply 가 끝나고 **3분쯤** 기다린다 (서버 부팅 + 측정기 시작).
2. 프로그램 **5단계 → [수정 전 측정]** (프로필 칸 기본값 capstone-tf).
   기대: V7 실패 (인터넷 → Bastion 22, 웹 → MySQL 3306), V8 실패 (인터넷 지점 → Bastion 22, 웹 → MySQL 3306, 웹·API → Bastion 22 열림).
3. 프로그램 3·4단계에서 후보 1차 검사 (통과한 기록만 시험 환경에 넣을 수 있다).
4. 5단계 수동 조작의 **[이 기록의 후보 파일 넣기]** → **[plan 확인]** (읽기 전용) → 결과에 따라:
   - '보안 그룹 제자리 수정만 포함' (CLEAN) → 사람이 apply:
     ```powershell
     ..\..\..\tools\terraform.exe apply      # 화면에 'aws_security_group … will be updated in-place' 만 있는지 다시 보고 yes
     ```
   - '교체·삭제 포함' (BLOCKED) → **apply 하지 않는다.** 기록의 2차 결과가 '차단'(PLAN_BLOCKED)으로 남고,
     이 후보는 측정 버튼도 거절한다. 수동 조작의 [원본 파일로 복원] 또는 다른 후보를 넣는다.
   - plan 확인은 시험 환경 폴더에서 `terraform plan -lock=false -refresh=true -out=(임시 폴더)` 와 `show -json` 만 한다 —
     AWS 에서 지금 값을 읽어 비교만 하고, 상태 파일을 잠그거나 쓰지 않는다. 결과는 기록 폴더 `plancheck/<시각>/` 에 남는다
     (plan_summary.json · plan.txt · plan_changes.json · commands.json, 계정 번호·공인 IP 는 가림).
   - 배포가 있어야 한다 (원본을 먼저 apply). 배포가 없으면 plan 이 전부 '새로 만듦' 이라 교체를 볼 수 없다.
   (버튼 대신 손으로: `copy ..\..\..\experiments\candidate-sets\arch-3tier-sg\candidates\correct-design.tf security_groups.tf` 후
   `..\..\..\tools\terraform.exe plan` — 이때는 plan 화면이 기록에 남지 않는다)
5. 5단계 **[수정 후 측정]** — 같은 시험을 다시. 상태 파일이 보안 그룹 파일보다 오래됐으면(= 바꾸고 아직 apply 안 함) 버튼이 꺼져 있고,
   apply 가 끝나고 **2분**이 지나야 켜진다 (콘솔 출력이 20~40초 늦게 보이는 것을 실측으로 확인 — 바뀌기 전 결과를 쓰지 않으려고).
6. 끝나면 바로:
   ```powershell
   ..\..\..\tools\terraform.exe destroy
   ```
   그리고 5단계 수동 조작의 **[원본 파일로 복원]** (다음 시연용). destroy 뒤 AWS 콘솔(서울)에서 EC2 인스턴스·로드밸런서·VPC(Project=iacpatch-tb 태그)가 남지 않았는지 확인.

## 측정이 하는 일 / 하지 않는 일

- 한다: `terraform show -json`(이 PC 의 상태 파일), `terraform plan`(plan 확인 — 계산만, -lock=false), `aws ec2 describe-security-groups` / `describe-network-interfaces`,
  `aws ec2 get-console-output --latest`(측정 지점 5곳), `GET http://<ALB>:443/probe.json` 과 이 PC → ALB 443 TCP 연결(참고용)
- 하지 않는다 (측정·plan 확인): apply / destroy, AWS 리소스 생성·변경·삭제, 보안 그룹 열기, 서버 로그인(키 페어 없음).
  반영(apply·destroy)은 따로 있는 반영 버튼이 사람 확인 뒤에만 한다 (위 '순서 — 화면 버튼으로').
- 필요한 권한(읽기): `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`, `ec2:GetConsoleOutput`
  (plan 확인은 사람이 PowerShell 에서 하던 `terraform plan` 과 같은 프로필·권한을 쓴다 — 배포된 39개 리소스를 읽는 권한)

## 판정 규칙 (V8)

- 열려야 함(설계도 화살표 9개) = open 만 통과. 막혀야 함(그 밖) = timeout 만 통과, open 은 실패, refused·오류는 판정 불가
  (refused 는 패킷이 서버까지 갔다는 뜻이라 보안 그룹이 막았다는 증거가 아니다).
- 웹 첫 화면 경로(인터넷 지점 → ALB → 웹)는 웹 서버의 첫 화면 글자가 와야 열림. ALB 가 만든 오류 응답(502·503)은 인정하지 않는다.
- 설계 통신 9개가 모두 시험 환경 안 측정 지점의 시험으로 확인돼야 통과. 하나라도 못 재면 판정 불가.
