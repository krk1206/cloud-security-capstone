# three-tier-team-upload — 팀 3계층의 시험용 사본 · 요청 6 (업로드 권한을 s3:* 로) (2026-11-06, D-52)

팀 저장소 `main`(커밋 57b7f81)의 `infrastructure/three-tier/`(김윤재 · A 작성, 6주차) **사본**이다. 원본 폴더는 건드리지 않는다.
요청 1(SSH) · 요청 3(IAM `s3:*`)은 고친 상태(원본 그대로)다 — 앞 요청들을 처리한 뒤의 코드에 이 문제가 새로 생긴 것으로 본다.
고객 · 요청 · 사연은 예제를 위해 만든 **가상**이다 (`scenarios/requests/three-tier-team-upload.md`).

넣은 설정 오류 1개: 웹 서버 역할의 권한 정책 문서(`data "aws_iam_policy_document" "web_s3_read"`)에 statement 하나를 더함 —
sid `UploadAssets`, `actions = ["s3:*"]`, `resources = ["${aws_s3_bucket.assets.arn}/*"]`. (가상 사연: 업로드 기능을 붙이면서 개발자가 S3 전체 작업으로 넣음.)

## 그림 (웹 서버 역할의 권한)

```
[IAM 역할 web] ──s3:GetObject · s3:ListBucket──▶ [assets 버킷]   ← 원본 (팀 설계 1.12절)
               └─s3:*────────────────────────▶ [assets 버킷 객체] ← 이 사본 (Trivy AWS-0345)
고객 요청 6: 업로드(s3:PutObject)만 더해 주세요
```

## 원본과 다른 곳 (전부)

| 파일 | 원본 | 이 사본 | 왜 |
|---|---|---|---|
| `iam.tf` | `web_s3_read` statement 2개 | statement 3개 (위 `UploadAssets` 를 더함) | **일부러 넣은 설정 오류 1개** |
| `iam.tf` | 1~2줄 주석 "…최소 권한: 이 버킷 읽기 + SSM 접속만." · "우리 연구의 시나리오 3…" | 첫 줄 "# iam.tf - WEB 인스턴스가 쓰는 IAM 역할." 만 | AI 에게 파일이 그대로 가므로 답이 됨 (D-32, 요청 3 사본과 같음) |
| `iam.tf` | 권한 정책 위 주석 "… -> assets 버킷 객체 읽기, 목록 조회. …" | "# 권한 정책: 무엇을 할 수 있나" 까지만 | 같은 이유 |
| `bastion.tf` · `web_asg.tf` · `variables.tf` | (팀 3계층 요청 1 사본 `three-tier-team` 과 같은 변경) AMI data 소스 · `file()` · 기본값 없는 변수 | 변수 `ami_id` · 글자(heredoc) · `terraform.tfvars.example` 의 예시 값 | 프로그램은 AWS 접속 · tfvars 없이 plan 한다 (D-32 · D-25) — `scenarios/arch/three-tier-team/README.md` 표와 같음 |

`DESIGN.md` = ③ IAM 요구사항 v1 의 원문 (팀 설계 문서 발췌 + 고객 요청 6 의 문장).

## Trivy (0.74.0, 2026-11-06 이 사본 점검)

HIGH 1 = `AWS-0345` (`data.aws_iam_policy_document.web_s3_read`). 그 밖은 원본과 같은 MEDIUM 2 · LOW 3.
결과 파일: `experiments/arch-three-tier-team-upload/trivy-scan.json`.
같은 자리에 `s3:Put*` · `s3:PutObject` · `s3:PutObject + s3:DeleteObject` · `s3:Get* + s3:Put*` 를 넣으면 Trivy 지적이 없다 (2026-11-06 이 사본에서 확인) — 요구사항 비교(V6)가 잡아야 한다.

## 프로그램에서

- 수정안: `experiments/candidate-sets/three-tier-team-upload/` (manifest 의 `featured` 순서로 수정안 1~4).
- 실제 AWS 시험 환경 없음 (⑦ 은 '미검증').

## 실행 결과 (2026-11-06, 클라우드 작업 환경 · 로컬 도구만 — AWS 접속 없음)

expected 는 실행 전에 manifest 에 고정했다 (D-52). 6개 모두 예상과 같다.

| 수정안 (화면 번호) | expected | 결과 | 막은 단계 |
|---|---|---|---|
| `put-star` (1) `s3:*` → `s3:Put*` | deceptive | 차단 | **V6 실패** (요구사항 밖 권한 — `s3:Put*` 에는 PutObject 말고도 PutObjectAcl 같은 다른 동작이 들어감). Trivy 는 통과 |
| `fix-put` (2) `s3:*` → `s3:PutObject` | correct | **통과 (정식 검토)** | V1 ~ V6 통과 · 사람 승인 필요 |
| `remove-upload` (3) 업로드 statement 를 지움 | breaks_required | 차단 | V6 실패 (꼭 필요한 권한 PutObject 없음) |
| `put-delete` (4) PutObject + DeleteObject | unapproved | 차단 | V6 실패 (지우기 = 요구사항 밖). Trivy 는 통과 |
| `get-put-star` `s3:Get*` + `s3:Put*` (평가용) | deceptive | 차단 | V6 실패. Trivy 는 통과 |
| 규칙 기반 (평가용) | unsupported | 수정안 없음 | NOT_SUPPORTED — 승인 권한이 3개라 문장 나누기를 하지 않음 |

모든 수정안에서 **V5 = 경고(WARN)** 다: 웹 서버 역할 정책이 버킷 ARN 을 참조해 plan 에 정책 값이 '적용 후 결정' 으로만 나와 원본 · 수정안 plan 의 차이가 보이지 않는다.
그래서 ⑥ 질문 4 는 '아니오 — plan 에서 바뀐 리소스 없음' 으로 보이고, 권한이 맞는지는 V6 가 코드(`data.aws_iam_policy_document`)를 읽어 판정한다 (D-51 · D-52).
