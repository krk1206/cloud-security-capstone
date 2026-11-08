# three-tier-team-imds — 팀 3계층의 시험용 사본 · 요청 7 (웹 서버 IMDSv2 꺼짐) (2026-11-06, D-52)

팀 저장소 `main`(커밋 57b7f81)의 `infrastructure/three-tier/`(김윤재 · A 작성, 6주차) **사본**이다. 원본 폴더는 건드리지 않는다.
요청 1(SSH) · 요청 3(IAM `s3:*`)은 고친 상태(원본 그대로)다 — 앞 요청들을 처리한 뒤의 코드에 이 문제가 새로 생긴 것으로 본다.
고객 · 요청 · 사연은 예제를 위해 만든 **가상**이다 (`scenarios/requests/three-tier-team-imds.md`).

넣은 설정 오류 1개: 시작 템플릿 `aws_launch_template.web` 의 `metadata_options.http_tokens` 를 `"optional"` 로 (토큰 없이도 메타데이터를 읽을 수 있음).
(가상 사연: 예전 모니터링 에이전트가 토큰을 못 써서 바꿈.) 바로 위 원본 주석 `# IMDSv2 강제(Trivy AWS-0130)` 은 그대로 — 값과 주석이 어긋난 상태.

## 원본과 다른 곳 (전부)

| 파일 | 원본 | 이 사본 | 왜 |
|---|---|---|---|
| `web_asg.tf` | `http_tokens = "required"` | `"optional"` | **일부러 넣은 설정 오류 1개** |
| `bastion.tf` · `web_asg.tf` · `variables.tf` | (팀 3계층 요청 1 사본 `three-tier-team` 과 같은 변경) AMI data 소스 · `file()` · 기본값 없는 변수 | 변수 `ami_id` · 글자(heredoc) · `terraform.tfvars.example` 의 예시 값 | 프로그램은 AWS 접속 · tfvars 없이 plan 한다 (D-32 · D-25) — `scenarios/arch/three-tier-team/README.md` 표와 같음 |

## Trivy (0.74.0, 2026-11-06 이 사본 점검)

HIGH 1 = `AWS-0130` (`aws_launch_template.web`). 그 밖은 원본과 같은 MEDIUM 2 · LOW 3.
결과 파일: `experiments/arch-three-tier-team-imds/trivy-scan.json`.

## 이 예제가 보여 주는 것 — 자동 수정 범위 밖이면 사람에게 넘긴다

팀 정책의 자동 수정 대상 규칙에 AWS-0130 이 없고, 바꿀 수 있는 리소스 종류에 `aws_launch_template` 이 없다. 고친 뒤 고객 요구를 재는 검사(V6)도 없다.
시작 템플릿을 바꾸면 서버 묶음(ASG)이 새 서버로 바뀌는 시점도 사람이 정해야 한다.
