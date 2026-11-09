# three-tier-team-dbenc — 팀 3계층의 시험용 사본 · 요청 8 (DB 저장소 암호화 꺼짐) (2026-11-06, D-52)

팀 저장소 `main`(커밋 57b7f81)의 `infrastructure/three-tier/`(김윤재 · A 작성, 6주차) **사본**이다. 원본 폴더는 건드리지 않는다.
요청 1(SSH) · 요청 3(IAM `s3:*`)은 고친 상태(원본 그대로)다 — 앞 요청들을 처리한 뒤의 코드에 이 문제가 새로 생긴 것으로 본다.
고객 · 요청 · 사연은 예제를 위해 만든 **가상**이다 (`scenarios/requests/three-tier-team-dbenc.md`).

넣은 설정 오류 1개: `aws_db_instance.mysql` 의 `storage_encrypted` 를 `false` 로. (가상 사연: DB 를 다시 만들면서 빠뜨림.)
원본 주석 `# Trivy AWS-0080` 과 파일 첫 줄 '저장소 암호화' 는 그대로 — 값과 주석이 어긋난 상태.

## 원본과 다른 곳 (전부)

| 파일 | 원본 | 이 사본 | 왜 |
|---|---|---|---|
| `rds.tf` | `storage_encrypted = true` | `false` | **일부러 넣은 설정 오류 1개** |
| `bastion.tf` · `web_asg.tf` · `variables.tf` | (팀 3계층 요청 1 사본 `three-tier-team` 과 같은 변경) AMI data 소스 · `file()` · 기본값 없는 변수 | 변수 `ami_id` · 글자(heredoc) · `terraform.tfvars.example` 의 예시 값 | 프로그램은 AWS 접속 · tfvars 없이 plan 한다 (D-32 · D-25) — `scenarios/arch/three-tier-team/README.md` 표와 같음 |

## Trivy (0.74.0, 2026-11-06 이 사본 점검)

HIGH 1 = `AWS-0080` (`aws_db_instance.mysql`). 그 밖은 원본과 같은 MEDIUM 2 · LOW 3.
결과 파일: `experiments/arch-three-tier-team-dbenc/trivy-scan.json`.

## 이 예제가 보여 주는 것 — 자동 수정 범위 밖이면 사람에게 넘긴다

팀 정책의 자동 수정 대상 규칙에 AWS-0080 이 없고, 바꿀 수 있는 리소스 종류에 `aws_db_instance` 가 없다.
게다가 이미 만든 DB 의 `storage_encrypted` 를 바꾸면 **DB 를 새로 만드는 변경(교체)** 이 된다 — 팀 정책은 교체를 막는다(`allow_replace: false`).
데이터를 옮기는 계획(스냅샷 → 암호화한 복사본 → 복원)은 사람이 세워야 한다.
