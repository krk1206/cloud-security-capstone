# three-tier-team-iam — 팀 3계층의 시험용 사본 · 시나리오 3 (IAM 과다 권한) (2026-11-06, D-51)

팀 저장소 `main`(커밋 57b7f81)의 `infrastructure/three-tier/`(김윤재 · A 작성, 6주차) **사본**이다. 원본 폴더는 건드리지 않는다.
원본 README 의 '연구와의 연결' 표의 **시나리오 3(IAM 과다 권한)** 하나만 넣었다: 웹 서버 역할의 권한 정책(`data "aws_iam_policy_document" "web_s3_read"`)을 S3 전체 · 모든 리소스로.
시나리오 1(SSH)은 고친 상태(원본 그대로)라서 요청 1(`three-tier-team`)을 처리한 뒤의 코드에 이 문제가 새로 생긴 것으로 본다.

## 그림 (웹 서버 역할의 권한)

```
웹 서버(ASG) ──인스턴스 역할──▶ [IAM 역할 web] ──s3:*──▶ 모든 리소스 (*)      ← 이 사본 (Trivy AWS-0345)
                                            └─s3:GetObject · s3:ListBucket─▶ [assets 버킷]   ← 원본 (팀 설계 1.12절)
```

## 원본과 다른 곳 (전부)

| 파일 | 원본 | 이 사본 | 왜 |
|---|---|---|---|
| `iam.tf` | `web_s3_read` 의 statement 2개: `s3:GetObject` on `"${aws_s3_bucket.assets.arn}/*"`, `s3:ListBucket` on `aws_s3_bucket.assets.arn` | statement 1개: `s3:*` on `"*"` (sid `WebS3Access`) | **일부러 넣은 설정 오류 1개** (원본 README 시나리오 3) |
| `iam.tf` | 1~2줄 주석 "…최소 권한: 이 버킷 읽기 + SSM 접속만." · "우리 연구의 시나리오 3(IAM 과다 권한)은…" | 첫 줄 "# iam.tf - WEB 인스턴스가 쓰는 IAM 역할." 만 | AI 에게 파일이 그대로 가므로 답이 됨 (D-32 — 설정 오류는 README 에만 적는다) |
| `iam.tf` | 권한 정책 위 주석 "… -> assets 버킷 객체 읽기, 목록 조회. 리소스를 ARN으로 못 박는다." | "# 권한 정책: 무엇을 할 수 있나" 까지만 | 같은 이유 |
| `bastion.tf` · `web_asg.tf` · `variables.tf` | (팀 3계층 요청 1 사본 `three-tier-team` 과 같은 변경) AMI data 소스 · `file()` · 기본값 없는 변수 | 변수 `ami_id` · 글자(heredoc) · `terraform.tfvars.example` 의 예시 값 | 프로그램은 AWS 접속 · tfvars 없이 plan 한다 (D-32 · D-25) — `scenarios/arch/three-tier-team/README.md` 표와 같음 |

`security_groups.tf` 는 원본 그대로다 (요청 1 사본과 달리 SSH 는 `var.admin_cidr`). 나머지 파일(`provider.tf` · `network.tf` · `alb.tf` · `rds.tf` · `s3.tf` · `monitoring.tf` · `outputs.tf`)도 원본 그대로다.
`DESIGN.md` 는 팀 설계 문서에서 웹 서버 역할의 권한 문장만 옮긴 것 (③ IAM 요구사항 v1 의 원문).

## 왜 `"Action": "*"` 가 아니라 `s3:*` 인가

원본 README · 설계 문서 4.4절은 시나리오 3을 `Action "*", Resource "*"` 로 적고 Trivy 규칙을 '7주차 확정' 으로 남겼다.
Trivy 0.74.0 내장 체크로 재 보면 (2026-11-06 이 사본에서):

- `actions = ["*"]`, `resources = ["*"]` → **지적 없음** (일반 와일드카드 규칙 AWS-0057 은 사용 중지 상태)
- `actions = ["s3:*"]`, `resources = ["*"]` → **AWS-0345 HIGH** (`data.aws_iam_policy_document.web_s3_read`, `iam.tf:22`)

그래서 사본에는 Trivy 가 잡는 `s3:*` 를 넣었다. `"*"` 형태는 수정안 쪽에 넣었다: `s3:*` 를 `*` 로 바꾸는 수정안은 Trivy 지적이 없어지지만
권한은 더 넓어진다 → IaCPatch 의 요구사항 검사(V6)가 막아야 한다 (`experiments/candidate-sets/three-tier-team-iam`).

**팀장 A 의 열린 PR #8** (`feature/week7-a`, 2026-10-13, main 에 아직 병합 전)에 이 공백을 메우는 커스텀 Trivy 체크
`CAPSTONE-IAM-0001`(`policy/checks/iam_no_wildcards.rego`, HIGH — Action `"*"` · Resource `"*"`)와 웹 서버 역할의 필요한 권한 목록
(`policy/required_permissions.yaml`)이 있다. 이 사본의 요구사항 v1(assets 버킷 GetObject · ListBucket + SSM 관리형 정책)은 그 목록의
`capstone-three-tier-web-role` 과 같다. 병합 전이라 IaCPatch 의 Trivy 실행에는 그 체크가 들어 있지 않다.
2026-11-06 에 그 체크를 같이 돌려 본 결과 (`trivy config <폴더> --config-check <체크 폴더> --check-namespaces user`, Trivy 0.74.0, 읽기만):

| 대상 | AWS-0345 | CAPSTONE-IAM-0001 |
|---|---|---|
| 이 사본 (`s3:*` on `*`) | 1 | 1 (Resource `*`) |
| 수정안 `*` 로 | 0 | 2 (Action `*` · Resource `*`) |
| 수정안 나열 + `*` | 0 | 1 (Resource `*`) |
| 정답 · 읽기 지움 · 다른 버킷 · 신뢰 정책 공개 | 0 | 0 |

그 체크를 켜면 Trivy 결과에는 `*` · 나열 + `*` 수정안의 와일드카드 지적이 남아 보인다. 다만 IaCPatch 의 V1 · V2 는 지적을 (규칙 · 파일 · 리소스) 로
맞춰 보는데, 원본에 이미 같은 data 블록의 CAPSTONE-IAM-0001(Resource `*`)이 있어서 두 수정안 모두 '대상 지적(AWS-0345) 없어짐 · 새 지적 없음' 이 된다
(2026-11-06, 위 결과에 V2 코드를 그대로 돌려 계산 — 6개 모두 V2 PASS). 그러니 그 체크를 켜도 이 둘을 막는 것은 요구사항 검사(V6)다.
읽기 지움 · 다른 버킷 · 신뢰 정책 공개는 체크 결과도 0 — V6 · 정책(V5)이 잡는다.
PR #8 병합과 IaCPatch 가 그 체크를 같이 돌릴지는 팀이 정한다 (검사 기준이 바뀌는 일이라 사람이 정함).

## Trivy (0.74.0, 2026-11-06 이 사본 점검)

HIGH 1 = 시나리오 3 (`AWS-0345` · `data.aws_iam_policy_document.web_s3_read` · `iam.tf:22`).
그 밖은 원본 README 와 같다 — MEDIUM 2(AWS-0178 · AWS-0177), LOW 3(AWS-0017 · AWS-0089 · AWS-0133), 원본의 `#trivy:ignore` 는 그대로 무시됨.
결과 파일: `experiments/arch-three-tier-team-iam/trivy-scan.json`.

## plan 에서 정책 값이 비는 이유 (검사기가 코드를 읽는 이유)

버킷이 `bucket_prefix` 라 이름 · ARN 이 apply 때 정해진다. 그래서 원본처럼 Resource 가 버킷 ARN 을 참조하면 plan 의
`aws_iam_role_policy.web_s3_read.policy` 값이 비어 있다(unknown). 이 사본(`"*"`)은 참조가 없어서 plan 에 값이 있다.
IaCPatch 의 요구사항 검사(V6 IAM)는 plan 에 값이 없으면 `data "aws_iam_policy_document"` 를 코드에서 읽고, plan 이 알려 준 구조(statement 수 · 글자 값 ·
참조한 리소스)와 맞을 때만 쓴다 — 버킷은 이름 대신 참조(`${aws_s3_bucket.assets.arn}`)로 비교한다 (`src/iacpatch/verify/iam_hcl.py`, D-51).

## 프로그램에서

- ① 예제 카드 '팀 3계층 — 요청 3'. ② 맨 위 가상 고객 요청서(`scenarios/requests/three-tier-team-iam.md`).
- ③ IAM 요구사항 v1 = [`DESIGN.md`](DESIGN.md) 를 옮긴 **초안** — 담당자가 확정해야 기준이 된다.
- 수정안 4개: `experiments/candidate-sets/three-tier-team-iam/` (manifest 의 `featured` 순서로 수정안 1~4).
- 실제 AWS 시험 환경 없음 (⑦ 은 '미검증').
- 이 폴더는 실험 재료(의도적으로 취약)라서 고쳐서 커밋하지 않는다. PR 게이트(`iac-scan.yml`)는 `infrastructure/` 만 보므로 이 폴더가 있어도 막히지 않는다.
