# three-tier-team — 팀 저장소 3계층(팀장 코드)의 시험용 사본 (2026-11-04, D-49)

팀 저장소 `main`(커밋 57b7f81)의 `infrastructure/three-tier/`(김윤재 · A 작성, 6주차) **사본**이다. 원본 폴더는 건드리지 않는다.
원본 README 의 '연구와의 연결' 표대로 **시나리오 1(과다 개방 SG)** 하나만 넣었다: `bastion_ssh_in` 의 `cidr_ipv4` 를 `0.0.0.0/0` 으로.

## 그림 (보안 그룹이 허용하는 통신)

```
사용자(인터넷) ──80──▶ [ALB] ──80──▶ [웹 서버 ASG] ──3306──▶ [RDS MySQL]
운영자 203.0.113.10/32 ──22──▶ [Bastion] ──3306──────────────────▲
                         ▲ 코드는 0.0.0.0/0 (시나리오 1, Trivy AWS-0107)
```

## 원본과 다른 곳 (전부)

| 파일 | 원본 | 이 사본 | 왜 |
|---|---|---|---|
| `security_groups.tf` | `bastion_ssh_in` 의 `cidr_ipv4 = var.admin_cidr` | `"0.0.0.0/0"` | **일부러 넣은 설정 오류 1개** (원본 README 시나리오 1) |
| `security_groups.tf` | 그 규칙 위 주석 "…0.0.0.0/0이면 AWS-0107(HIGH)이고 우리 연구의 시나리오 1이 된다." | 지움 | AI 에게 파일이 그대로 가므로 답이 됨 (D-32 — 설정 오류는 README 에만 적는다) |
| `bastion.tf` · `web_asg.tf` | `data "aws_ami" "al2023"` 로 최신 AMI 를 AWS 에서 찾음 | 변수 `ami_id` (기본값 `ami-0c9c942bd7bf113a2`) | 프로그램은 AWS 접속 없이 plan 한다 (AWS 를 조회하는 data 소스는 plan 이 멈춤 — D-32) |
| `bastion.tf` · `web_asg.tf` | `user_data = file("…_user_data.sh")` | 같은 스크립트를 글자(heredoc)로 넣음, `${IID}` 는 `$${IID}` | 실행 전 안전 점검이 `file()` 을 막는다 (D-25). 스크립트 내용은 같다 |
| `variables.tf` | `admin_cidr` · `ssh_public_key` · `db_password` 기본값 없음 (terraform.tfvars 에서) | `terraform.tfvars.example` 의 예시 값을 기본값으로 | 프로그램은 tfvars 없이 plan 한다. 값은 예시 전용 (실제 값 아님) |

`.terraform.lock.hcl` · `terraform.tfvars.example` · `*_user_data.sh` 는 복사하지 않았다. 나머지 파일(`provider.tf` · `network.tf` · `alb.tf` · `rds.tf` · `s3.tf` · `iam.tf` · `monitoring.tf` · `outputs.tf`)은 원본 그대로다.

## Trivy (0.74.0, 2026-11-04 이 사본 점검)

HIGH 1 = 시나리오 1 (`AWS-0107` · `aws_vpc_security_group_ingress_rule.bastion_ssh_in` · `security_groups.tf:94`).
그 밖은 원본 README 와 같다 — MEDIUM 2(AWS-0178 · AWS-0177), LOW 3(AWS-0017 · AWS-0089 · AWS-0133), 원본의 `#trivy:ignore` 5건은 그대로 무시됨.
결과 파일: `experiments/arch-three-tier-team/trivy-scan.json`.

## 프로그램에서

- ① 첫 예제 카드 '팀 3계층 — 깃허브 main'. ③ 설계도 v1 = [`DESIGN.md`](DESIGN.md)(팀 설계 문서의 문장을 그대로 옮긴 것)의 통신 5개를 옮긴 **초안** — 담당자가 확정해야 기준이 된다.
- 수정안 4개: `experiments/candidate-sets/three-tier-team-sg/` (manifest 의 `featured` 순서로 수정안 1~4).
- 실제 AWS 시험 환경 없음 (⑦ 은 '미검증'). 실제 AWS 측정 기록은 예제 '3계층 웹 서비스 (AWS 시험 환경 실측)' 에 있다.
- 이 폴더는 실험 재료(의도적으로 취약)라서 고쳐서 커밋하지 않는다. PR 게이트(`iac-scan.yml`)는 `infrastructure/` 만 보므로 이 폴더가 있어도 막히지 않는다.
