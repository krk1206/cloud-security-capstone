# board-saas — 고객 제안서 예제 (가상 고객 "모두의 게시판", 2026-11-03, D-46)

"실제 고객 제안서가 들어왔다" 는 가정으로 ①~⑧ 을 한 번에 보여 주는 예제다. 고객 조건은 [`PROPOSAL.md`](PROPOSAL.md) 에 있고,
③ 의 설계도 v1 은 그 제안서의 '2. 보안 조건' 을 그대로 옮긴 **초안**이다 — 담당자가 제안서와 맞는지 확인하고 **확정**해야 기준이 된다
(실험 세트의 '팀 작성 평가 기준' 과 다르게, 사람 확정 단계를 거친다).

## 무엇을 만드나 (16 리소스 · 의도적 설정 오류 1개)

```
인터넷 ──80 · 443──▶ [web EC2]  ──3306──▶ [MySQL RDS]
                       ▲ 22 (점프 서버에서만)
본사 사무실 203.0.113.0/24 ──22──▶ [bastion EC2]          ← 코드는 0.0.0.0/0 (제안서 조건 2 위반, Trivy AVD-AWS-0107)
```

| 파일 | 내용 |
|---|---|
| `versions.tf` · `provider.tf` | Terraform · AWS provider 5.100.0 고정, 서울 리전 (보호 파일 — 수정안이 못 건드림) |
| `network.tf` | VPC 10.30.0.0/16, 공개 서브넷 2 · 비공개 서브넷 2, 인터넷 게이트웨이, 공개 라우팅 표 + 연결 2 |
| `security_groups.tf` | bastion(SSH 22 ← **0.0.0.0/0**: 고칠 곳) · web(80 · 443 ← 인터넷, 22 ← bastion SG) · db(3306 ← web SG) |
| `compute.tf` | bastion(공개 서브넷) · web(비공개 서브넷) EC2 |
| `db.tf` | MySQL 8.0 RDS (db.t3.micro, 관리형 마스터 비밀번호) |
| `outputs.tf` | bastion 공개 IP |

제안서 기준(설계도)으로 보면 **제안서에 없는 통신 = 인터넷 → bastion :22 하나**다. 설계도대로 고치면(규칙 기반 · AI · 직접) 설계도와 같아진다.

- 평가 세트: `experiments/candidate-sets/board-saas-sg/` (팀 평가용 수정안 없음 — 이 예제는 AI 수정 · 설계도대로 자동 수정 · 직접 올리기만)
- Trivy 원본 점검 결과: `experiments/arch-board-saas/trivy-scan.json`
- 실제 AWS 시험 환경 없음 (⑦ 미검증). 이 폴더는 실험 재료라 PR 은 시연용(병합하지 않음, D-44)
