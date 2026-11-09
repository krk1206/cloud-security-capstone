# three-tier-team-deletion — 팀 3계층의 시험용 사본 · 요청 9 (DB 삭제 보호 꺼짐 — 팀 코드의 실제 지적) (2026-11-06, D-52)

팀 저장소 `main`(커밋 57b7f81)의 `infrastructure/three-tier/`(김윤재 · A 작성, 6주차) **사본**이다. 원본 폴더는 건드리지 않는다.
요청 1(SSH) · 요청 3(IAM `s3:*`)은 고친 상태(원본 그대로)다 — 앞 요청들을 처리한 뒤의 코드에 이 문제가 새로 생긴 것으로 본다.
고객 · 요청 · 사연은 예제를 위해 만든 **가상**이다 (`scenarios/requests/three-tier-team-deletion.md`).

**설정 오류를 넣지 않았다** — 팀 원본 코드 그대로(오프라인 plan 용 변경만)다. 원본 README 에도 적혀 있는 Trivy MEDIUM 지적 `AWS-0177` 을
(가상) 고객이 운영 전환 준비 · 감사 대응으로 조치해 달라고 요청한 예제다: `aws_db_instance.mysql` 의 `deletion_protection = false` (원본 주석: "실습용: destroy가 막히지 않게 둔다. 운영이면 deletion_protection = true").

## 원본과 다른 곳 (전부)

| 파일 | 원본 | 이 사본 | 왜 |
|---|---|---|---|
| `bastion.tf` · `web_asg.tf` · `variables.tf` | (팀 3계층 요청 1 사본 `three-tier-team` 과 같은 변경) AMI data 소스 · `file()` · 기본값 없는 변수 | 변수 `ami_id` · 글자(heredoc) · `terraform.tfvars.example` 의 예시 값 | 프로그램은 AWS 접속 · tfvars 없이 plan 한다 (D-32 · D-25) — `scenarios/arch/three-tier-team/README.md` 표와 같음 |

## Trivy (0.74.0, 2026-11-06 이 사본 점검)

원본과 같다 — MEDIUM 2(AWS-0178 · AWS-0177), LOW 3(AWS-0017 · AWS-0089 · AWS-0133). 이 요청의 대상은 `AWS-0177`.
결과 파일: `experiments/arch-three-tier-team-deletion/trivy-scan.json`.

## 이 예제가 보여 주는 것 — 자동 수정 범위 밖이면 사람에게 넘긴다

팀 정책의 자동 수정 대상 규칙에 `AWS-0177` 이 없다. 고친 뒤 고객 요구를 재는 검사(V6)도 없다 → ② '사람에게 넘김' 칸에 할 일 · 확인 방법.
