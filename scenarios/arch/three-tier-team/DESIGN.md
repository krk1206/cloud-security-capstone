# 팀 설계 문서 — 3계층 웹 서비스가 허용하는 통신 (발췌)

출처: `docs/architecture/three-tier-design.md` (김윤재 · A, 2026-10-12) 1.5절 · 1.6절 · 2.1절. 이 파일은 그 문서에서 **보안 그룹이 허용해야 하는 통신**에 관한 문장만 그대로 옮긴 것이다 (요약 · 해석 없음).
IaCPatch ③ 의 설계도 v1 은 아래 '설계도 v1 에 옮긴 것' 1~5 를 옮긴 **초안**이고, 담당자가 이 글과 맞는지 보고 이름을 적어 **확정**해야 검사 기준이 된다.

## 설계 문서의 문장 (그대로)

1.5절 Security Group: "이번 설계의 경로: 인터넷 →80→ ALB SG →80→ WEB SG →3306→ DB SG, 운영자 IP/32 →22→ Bastion SG →3306→ DB SG. 아웃바운드는 WEB·Bastion의 443만."

1.6절 Bastion Host: "운영자가 private 리소스(RDS 등)에 접근할 때 거치는 public 서브넷의 EC2. SSH 22를 운영자 공인 IP /32에만 연다."

2.1절 트래픽 흐름 4: "운영자 → Bastion(22, 공인 IP/32만) → RDS(3306)"

## 설계도 v1 에 옮긴 것 (들어오는 통신 5개)

1. 사용자(인터넷) → ALB : 80
2. ALB → 웹 서버 : 80
3. 운영자 → Bastion : 22 — 운영자 IP 는 `terraform.tfvars.example` 의 예시 값 `203.0.113.10/32` (실제로는 각자 공인 IP/32)
4. 웹 서버 → DB(MySQL) : 3306
5. Bastion → DB(MySQL) : 3306

## 옮기지 않은 것

- 아웃바운드(웹 · Bastion → 443): 이 프로그램의 설계도 비교(V6)는 들어오는 규칙만 본다 (아웃바운드 · NACL · 라우팅은 검사 범위 밖).
- 설계에는 있지만 코드에 없는 것(API ASG · NLB · Redis · Read Replica · Route 53 · CloudFront · WAF · HTTPS): 원본 README 의 '설계에는 있지만 이번 주 코드에 없는 것' 그대로.
