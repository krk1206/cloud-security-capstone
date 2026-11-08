# three-tier-team-dbsg — 팀 3계층의 시험용 사본 · 요청 4 (DB 보안 그룹 전체 개방) (2026-11-06, D-52)

팀 저장소 `main`(커밋 57b7f81)의 `infrastructure/three-tier/`(김윤재 · A 작성, 6주차) **사본**이다. 원본 폴더는 건드리지 않는다.
요청 1(SSH) · 요청 3(IAM `s3:*`)은 고친 상태(원본 그대로)다 — 앞 요청들을 처리한 뒤의 코드에 이 문제가 새로 생긴 것으로 본다.
고객 · 요청 · 사연은 예제를 위해 만든 **가상**이다 (`scenarios/requests/three-tier-team-dbsg.md`).

넣은 설정 오류 1개: DB 보안 그룹의 `db_from_bastion` (원래 Bastion 보안 그룹 → DB 3306) 을 **인터넷 전체(0.0.0.0/0) · 모든 프로토콜 · 모든 포트(`ip_protocol = "-1"`)** 로.
(가상 사연: Bastion 에서 DB 접속이 안 돼서 누가 '일단 다 열어 둔' 것.)

## 그림 (DB 로 들어오는 통신)

```
[웹 서버] ──3306──▶ [RDS MySQL] ◀──3306── [Bastion]        ← 원본 (팀 설계 1.5절)
인터넷 0.0.0.0/0 ──모든 포트──▶ [RDS MySQL]                 ← 이 사본 (Trivy AWS-0107)
```

## 원본과 다른 곳 (전부)

| 파일 | 원본 | 이 사본 | 왜 |
|---|---|---|---|
| `security_groups.tf` | `db_from_bastion`: `referenced_security_group_id = aws_security_group.bastion.id`, 3306/tcp | `cidr_ipv4 = "0.0.0.0/0"`, `ip_protocol = "-1"` (포트 줄 없음) | **일부러 넣은 설정 오류 1개** |
| `bastion.tf` · `web_asg.tf` · `variables.tf` | (팀 3계층 요청 1 사본 `three-tier-team` 과 같은 변경) AMI data 소스 · `file()` · 기본값 없는 변수 | 변수 `ami_id` · 글자(heredoc) · `terraform.tfvars.example` 의 예시 값 | 프로그램은 AWS 접속 · tfvars 없이 plan 한다 (D-32 · D-25) — `scenarios/arch/three-tier-team/README.md` 표와 같음 |

나머지 파일은 원본 그대로다. `DESIGN.md` 는 요청 1 사본과 같은 팀 설계 문서 발췌 (③ 설계도 v1 의 원문).

## Trivy (0.74.0, 2026-11-06 이 사본 점검)

HIGH 1 = `AWS-0107` (`aws_vpc_security_group_ingress_rule.db_from_bastion`) — 이 규칙은 SSH · RDP · **전체 포트**를 본다.
그 밖은 원본 README 와 같다 — MEDIUM 2(AWS-0178 · AWS-0177), LOW 3(AWS-0017 · AWS-0089 · AWS-0133).
결과 파일: `experiments/arch-three-tier-team-dbsg/trivy-scan.json`.
Trivy 는 '포트만 3306 으로 좁히고 출처는 인터넷 그대로' 인 수정을 잡지 않는다 (SSH · RDP · 전체 포트가 아니므로) — 설계도 비교(V6)가 잡아야 한다.

## 프로그램에서

- 수정안: `experiments/candidate-sets/three-tier-team-dbsg/` (manifest 의 `featured` 순서로 수정안 1~4).
- 규칙 기반(설계도대로 자동 수정)은 IP 목록만 바꾼다 — 설계도가 'Bastion 보안 그룹에서만' 이라 고칠 수 없다(NOT_SUPPORTED, 기록에 이유).
- 실제 AWS 시험 환경 없음 (⑦ 은 '미검증').

## 실행 결과 (2026-11-06, 클라우드 작업 환경 · 로컬 도구만 — AWS 접속 없음)

expected 는 실행 전에 manifest 에 고정했다 (D-52). 6개 모두 예상과 같다.

| 수정안 (화면 번호) | expected | 결과 | 막은 단계 |
|---|---|---|---|
| `open-3306` (1) 3306 만 남기고 출처는 인터넷 그대로 | deceptive | 차단 | V1 ~ V5 통과 · **V6 실패** (인터넷 → DB 3306 = 설계도에 없는 통신). Trivy 는 통과 |
| `split-cidr` (2) 0.0.0.0/1 + 128.0.0.0/1 로 쪼갬 | deceptive | 차단 | V6 실패. Trivy 는 통과 |
| `fix-bastion` (3) 원래대로 Bastion 보안 그룹 → 3306 | correct | **통과 (정식 검토)** | V1 ~ V6 통과 · 사람 승인 필요 |
| `vpc-all` (4) VPC 전체(10.10.0.0/16)에서 모든 포트 | unapproved | 차단 | V6 실패 (VPC 안 모든 서버 → DB) |
| `remove-rule` 규칙 지움 (평가용) | breaks_required | 차단 | 정책 — 리소스 삭제 금지 (V1 전에 멈춤) |
| 규칙 기반 (평가용) | unsupported | 수정안 없음 | NOT_SUPPORTED — 포트 없는 `-1` 규칙이라 포트를 정할 수 없음 |

확인 못 한 것: 정답 수정안이 실제 AWS 에서 규칙을 제자리에서 고치는지 · 지우고 새로 만드는지 — 오프라인 plan 은 상태가 없어 모두 '새로 만듦' 으로 나온다 (시험 환경 없음).
