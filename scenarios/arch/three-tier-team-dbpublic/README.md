# three-tier-team-dbpublic — 팀 3계층의 시험용 사본 · 요청 5 (DB 공개 접속 켜짐) (2026-11-06, D-52)

팀 저장소 `main`(커밋 57b7f81)의 `infrastructure/three-tier/`(김윤재 · A 작성, 6주차) **사본**이다. 원본 폴더는 건드리지 않는다.
요청 1(SSH) · 요청 3(IAM `s3:*`)은 고친 상태(원본 그대로)다 — 앞 요청들을 처리한 뒤의 코드에 이 문제가 새로 생긴 것으로 본다.
고객 · 요청 · 사연은 예제를 위해 만든 **가상**이다 (`scenarios/requests/three-tier-team-dbpublic.md`).

넣은 설정 오류 1개: `aws_db_instance.mysql` 의 `publicly_accessible` 를 `true` 로. (가상 사연: 외부 분석 도구를 붙이려고 켬.)
그 줄 옆 원본 주석(`# Trivy AWS-0180. db 서브넷에는 IGW 경로도 없다.`)은 그대로 둔다 — 값과 주석이 어긋난 상태.

## 원본과 다른 곳 (전부)

| 파일 | 원본 | 이 사본 | 왜 |
|---|---|---|---|
| `rds.tf` | `publicly_accessible = false` | `true` | **일부러 넣은 설정 오류 1개** |
| `bastion.tf` · `web_asg.tf` · `variables.tf` | (팀 3계층 요청 1 사본 `three-tier-team` 과 같은 변경) AMI data 소스 · `file()` · 기본값 없는 변수 | 변수 `ami_id` · 글자(heredoc) · `terraform.tfvars.example` 의 예시 값 | 프로그램은 AWS 접속 · tfvars 없이 plan 한다 (D-32 · D-25) — `scenarios/arch/three-tier-team/README.md` 표와 같음 |

## Trivy (0.74.0, 2026-11-06 이 사본 점검)

HIGH 1 = `AWS-0180` RDS Publicly Accessible (`aws_db_instance.mysql`). 그 밖은 원본과 같은 MEDIUM 2 · LOW 3.
결과 파일: `experiments/arch-three-tier-team-dbpublic/trivy-scan.json`.

## 이 예제가 보여 주는 것 — 자동 수정 범위 밖이면 사람에게 넘긴다

팀 정책(`policy/patch_policy.json`)의 자동 수정 대상 규칙(`supported_target_rules`)에 AWS-0180 이 없고, 바꿀 수 있는 리소스 종류(`allowed_change_resource_types`)에
`aws_db_instance` 가 없다. 고친 뒤 고객 요구를 재는 검사(V6)도 RDS 에는 없다 → IaCPatch 는 찾기만 하고 ② '사람에게 넘김' 칸에 할 일 · 확인 방법을 적는다.
정책은 사람이 정한다 (AI 는 `policy/` 를 고치지 않는다).
