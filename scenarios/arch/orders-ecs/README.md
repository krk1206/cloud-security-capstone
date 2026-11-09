# 주문 API (컨테이너) — 3계층이 아닌 예제 (2026-11-01)

구조: 사용자(인터넷) → ALB(:80) → 주문 API(ECS Fargate, :8080) → PostgreSQL(:5432). 운영 서버(EC2)로 관리자가 SSH 접속.
'내 Terraform 폴더 연결' 로 이 폴더를 연결해서 ②~⑧ 을 시연 · 시험한다 (예제 목록의 고정 후보 세트 없음 — AI 수정 · 직접 수정만).

시험 재료 (일부러 넣은 설정 오류 — 고치지 말 것):

| 위치 | 무엇 | 누가 찾나 |
|---|---|---|
| `security_groups.tf` `aws_security_group.ops` | SSH 22 를 인터넷 전체(0.0.0.0/0)에 엶 | Trivy AVD-AWS-0107 + 자체 검사 |
| `security_groups.tf` `aws_security_group.db` | PostgreSQL 5432 를 VPC 대역 전체(10.20.0.0/16)에 엶 | 자체 검사(VPC 전체 → 고위험 포트) · 고객 설계 비교 — Trivy 는 못 찾음 |
| `iam.tf` `aws_iam_policy.reports` | s3:* 를 모든 리소스에 | Trivy AVD-AWS-0345 |
| `storage.tf` · `lb.tf` 등 | 버킷 암호화 · 로그 · HTTP 리스너 등 | Trivy (탐지만) |

AWS 를 조회하는 data 소스 · 모듈 없음 — 자격증명 없이 오프라인 plan 이 된다. 실제 AWS 시험 환경은 없다 (⑦ 미검증).

`.tf` 파일 주석에는 어디가 잘못됐는지 적지 않는다 — AI 수정 요청에 파일 내용이 그대로 들어가므로 정답 힌트가 되면 안 된다 (위 표는 이 README 에만).
