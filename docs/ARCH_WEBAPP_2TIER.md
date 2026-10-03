# 아키텍처 선정·구성·점검 — VPC 2계층 웹 (B 김보성, 2026-10-02)

지도교수 9/29 지시: "**아키텍처 하나 선정 → Terraform 으로 자동화해서 구성 → Terraform 실행 시연 → Trivy 점검 결과물 → AI 에이전트가 해석**", 그리고 "Terraform 이 너무 부족하다, 많이 만들 것, 본인이 한 작업은 설명할 수 있어야 한다", "다음 단계(스캔 결과로 패치 → 검증)까지".

이 문서는 그 지시를 이 저장소에서 어디까지 했는지, 무엇이 아직 안 됐는지의 기록이다. 코드: [`infrastructure/webapp-2tier/`](../infrastructure/webapp-2tier/). 실측: [`experiments/arch-webapp-2tier/RESULTS.md`](../experiments/arch-webapp-2tier/RESULTS.md).

## 1. 왜 이 아키텍처인가

| 후보 | 판단 |
|---|---|
| **VPC 2계층 웹 (public 웹 EC2 + private 앱 EC2 + S3 + IAM 역할)** — 선택 | AWS 공식 기본 패턴 "VPC with public and private subnets" 에서 NAT 게이트웨이를 뺀 것. 연구 대상 3유형(SG·S3·IAM)이 전부 자연스럽게 들어가는 **가장 작은** 구성. EC2 t3.micro 2대라 1시간 시연 비용이 수십 원 수준(프리 플랜 크레딧 안). 정상 기능 확인(V8)의 기준이 분명하다: `http://<퍼블릭 IP>/` 가 200 으로 응답해야 한다. |
| 3계층 웹 + RDS | 더 "진짜 서비스" 같지만 RDS 생성·삭제가 10분 이상이고 시연 시간이 2배. 연구 질문(SG·S3·IAM 설정 오류 검증)에 RDS 가 더하는 것이 없다. |
| 서버리스 (API Gateway + Lambda + S3 + DynamoDB) | Security Group 이 아예 없어 1순위 슬라이스(SG)가 사라진다. |

"아키텍처" 라는 말의 뜻: 어떤 AWS 리소스들을 어떻게 연결해 하나의 서비스를 만드는지의 구성도. 여기서는 "인터넷 → 웹 서버 → 앱 서버, 웹 서버는 S3 에서 파일을 읽음" 이다.

## 2. 구성 요소 (17 리소스) 와 각각이 있는 이유

| 층 | 리소스 (Terraform 주소) | 왜 있나 |
|---|---|---|
| 네트워크 | `aws_vpc.main` 10.0.0.0/16 | 이 프로젝트만의 격리된 사설망 |
| | `aws_internet_gateway.main` | VPC 와 인터넷을 잇는 문 |
| | `aws_subnet.public` 10.0.1.0/24 | 웹 서버 자리. 퍼블릭 IP 자동 부여 |
| | `aws_subnet.private` 10.0.2.0/24 | 앱 서버 자리. 인터넷에서 직접 못 들어옴 |
| | `aws_route_table.public` + `_association.public` | "목적지 0.0.0.0/0 → 인터넷 게이트웨이" 경로를 public 서브넷에만 연결 |
| 방화벽 | `aws_security_group.web` | 80 (인터넷 전체, 설계상 필요), 22 (인터넷 전체 — **설정 오류**), egress 전체 |
| | `aws_security_group.app` | 8080 을 **web SG 가 붙은 인스턴스에서만** (IP 대역이 아니라 SG 참조) |
| 서버 | `aws_instance.web` | nginx. user_data 로 첫 부팅 때 설치. IAM 인스턴스 프로필을 입음 |
| | `aws_instance.app` | python3 http.server 8080. 퍼블릭 IP 없음 |
| 저장 | `aws_s3_bucket.assets` | 정적 자산 버킷 |
| | `aws_s3_bucket_public_access_block.assets` | 퍼블릭 액세스 차단 4항목 **전부 false — 설정 오류** |
| | `aws_s3_bucket_policy.assets_public_read` | `Principal "*"` 에 `s3:GetObject` — **설정 오류** (Trivy 는 이 정책 본문을 안 잡는다) |
| 권한 | `aws_iam_role.web` | EC2 가 맡는 역할. 신뢰 정책 = ec2.amazonaws.com 만 |
| | `aws_iam_policy.web_assets` | `s3:*` on `*` — **설정 오류** (필요한 건 assets 버킷 GetObject/ListBucket) |
| | `aws_iam_role_policy_attachment.web_assets` | 정책을 역할에 연결 |
| | `aws_iam_instance_profile.web` | 역할을 EC2 에 붙이는 포장 |

## 3. 의도적 설정 오류 답안지 (코드 주석에는 안 적었다 — AI 후보 생성 실험에 힌트가 되지 않도록)

| 유형 | 어디 | 무엇 | Trivy 가 잡나 | 파이프라인 |
|---|---|---|---|---|
| SG 과다 개방 | `security_groups.tf:23` web SG ingress 22 `cidr_blocks = ["0.0.0.0/0"]` | 관리용 SSH 를 인터넷 전체에 | 잡는다 — AVD-AWS-0107 (CIS v1.2 4.1/4.2, v3.0 5.2 직접 대응 — 팀 매핑표 기준, 원문 대조 전) | 패치→V1~V6 대상 (`arch-webapp-sg`) |
| Public S3 | `storage.tf:17-20` 차단 4항목 false | 버킷을 퍼블릭으로 만들 수 있게 | 잡는다 — AVD-AWS-0086/0087/0091/0093 | 탐지·해석까지 (S3 오라클 미구현, D-10) |
| Public S3 | `storage.tf:26-37` 버킷 정책 Principal `*` | 누구나 객체 읽기 | **못 잡는다** (0.74.0 S3 체크는 차단 설정만 본다) | AI 해석의 `not_flagged_but_risky` 로 잡히는지 확인 |
| IAM 과다 권한 | `iam.tf:22-23` `Action ["s3:*"]`, `Resource "*"` | 웹 서버가 계정의 모든 S3 에 모든 작업 | 잡는다 — AVD-AWS-0345 (2개 메시지) | 패치→V1~V6 대상 (`arch-webapp-iam`) |

Trivy 가 추가로 잡는 11건(egress 전체 허용, IMDSv2, 루트 볼륨 암호화, 퍼블릭 IP 자동 부여, KMS, Flow Logs, 버전 관리, 로깅)은 튜토리얼 수준 기본값이다. 일부러 넣은 것도, 일부러 뺀 것도 아니다 — "스캐너는 많이 잡고, 그중 무엇을 자동 패치 대상으로 삼을지는 정책(`supported_target_rules`)이 정한다" 를 보여 주는 재료.

## 4. 지시 5단계 ↔ 저장소 현황

| 교수 지시 | 저장소 | 상태 (2026-10-02) |
|---|---|---|
| ① 아키텍처 선정 | 이 문서 1~2절 | 됨 (B 선정, 이유 기록) |
| ② Terraform 으로 구성 | `infrastructure/webapp-2tier/` 9 파일 17 리소스 | 됨 — fmt/validate/오프라인 plan 통과 (개발 환경). 팀 PC 재실행 `[확인 필요]` |
| ③ Terraform 실행 시연 (AWS 에 실제로 만들어지는지) | `docs/AWS_ACCESS_SETUP_B.md` 순서 | **안 됨 — apply 0회.** 계정 접근(IAM 사용자·키)이 먼저. 이 저장소의 AI 세션은 apply 를 하지 않는다(CLAUDE.md) |
| ④ Trivy 점검 결과물 | `scripts/arch_scan.py` → `findings.md`; 실측 `experiments/arch-webapp-2tier/RESULTS.md` 2절 | 됨 — finding 18 (의도적 7 + 부수 11), CIS 대응은 매핑표에 있는 3룰만 표시 |
| ⑤ AI 에이전트가 해석 | `interpret_prompt.md` → Claude Code 새 세션(사람이 염) → `scripts/arch_interpret_add.py` 등록 + 기계 대조 | **반만 됨** — 프롬프트·등록·대조 코드와 테스트는 있음, **모델 응답 등록 0건** (B 가 PC 에서 1회) |
| 다음 단계: 스캔 결과로 패치 → 검증 | `experiments/candidate-sets/arch-webapp-sg` (7), `arch-webapp-iam` (6) | 됨 — SG 7/7 기대 일치, IAM 5/6 (규칙 기반이 변수 이름 때문에 거부, 기록) |

"AI 에이전트" 를 어떻게 구현했나 (정직한 설명): 파이프라인이 모델을 자동 호출하지 않는다(D-5: 유료 API 안 씀, CLI 자동 호출 안 함). 대신 ① 코드가 증거(Trivy 원문 + Terraform 전체 + 스키마)를 프롬프트 파일로 만들고, ② 사람이 Claude Code 새 세션에 붙여 넣고, ③ 응답 JSON 을 코드가 등록하면서 **실제 스캔 결과와 대조**한다 — 응답이 없는 finding 을 지어내면 "지어냄", 빠뜨리면 "누락", CIS 번호가 팀 매핑표와 다르면 "불일치" 로 표시한다. AI 의 해석을 그대로 믿지 않는 신뢰 경계가 등록 단계에 있다.

## 5. 이 아키텍처로 뒤에 할 것

- **apply 시연 + V7/V8 첫 기록**: apply 뒤 `terraform output web_security_group_id` 의 SG 를 `describe-security-groups` 로 읽으면 V7(실제 AWS 상태), `curl http://<web_public_ip>/` 가 200 이면 V8(정상 기능). 둘 다 이 아키텍처가 처음으로 실제 기준을 준다 (지금까지 0회).
- **Claude Code 후보**: `scripts/cc_prompt.py arch-sg` / `arch-iam` → 응답을 `scripts/cc_add.py arch-sg <응답> --rep 1 --expected <라벨>` 로 등록 → 같은 검증. 특히 IAM 은 규칙 기반이 거부한 케이스라 E1 비교의 첫 실데이터가 된다.
- **S3 유형**: 탐지·해석까지만. 오라클(퍼블릭 액세스 차단 4항목 + 정책 Principal 전개)은 6~7주차 범위(D-10).

## 6. 교수께 말할 문장 (그대로 읽어도 됨)

> 아키텍처는 AWS 기본 패턴인 VPC 안의 공개 서브넷·사설 서브넷 2계층 웹 구성으로 골랐습니다. 웹 서버, 앱 서버, 정적 자산 S3 버킷, 웹 서버가 쓰는 IAM 역할까지 17개 리소스를 Terraform 파일 9개로 작성했고, 문법 검사와 plan 까지 통과했습니다. 실제 계정에 만드는 시연은 계정 접근을 준비해서 [날짜] 에 합니다.
>
> Trivy 로 점검하면 85개 검사 중 18개가 걸립니다. 그중 7개는 제가 연구 대상으로 일부러 넣은 설정 오류 — SSH 전체 개방, S3 퍼블릭 차단 해제 4개, IAM s3:* 2개 — 이고 11개는 암호화·로그 같은 기본값입니다. Trivy 가 못 잡는 것도 하나 확인했는데, 버킷 정책의 Principal "*" 공개 읽기입니다.
>
> AI 해석은 Trivy 결과와 코드 전체를 프롬프트로 만들어 Claude Code 세션에 넣고, 응답을 등록할 때 실제 결과와 기계적으로 대조합니다. 지어낸 항목·빠진 항목·CIS 번호 불일치를 표시합니다.
>
> 다음 단계로 이 아키텍처의 SSH 설정 오류에 패치 후보 7개, IAM 에 6개를 넣어 검증 6계층을 돌렸습니다. SSH 는 7개 전부 기대대로 — 정상 패치 2개 통과, 스캐너만 속이는 패치 5개 차단 — 였고, IAM 은 6개 중 5개가 기대대로였고 1개는 규칙 기반 생성기가 이름에 변수가 있다고 거부해서 후보를 못 만들었습니다. 그 한계는 그대로 기록했습니다.
