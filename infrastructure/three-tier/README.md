# three-tier - AWS 3-Tier 웹 서비스 Terraform

6주차(2026-10-12) 작성, 담당 A. 교수님 10-06 지시("AWS 학습 → 아키텍처 설계 → Terraform 자동화") 대응.
설계 설명과 결정 근거는 `docs/architecture/three-tier-design.md`, 그림은 `docs/architecture/three-tier.drawio`.

## 구성 (이번 주 apply 범위)

| 계층 | 리소스 | 파일 |
|---|---|---|
| 네트워크 | VPC 10.10.0.0/16, 서브넷 6개(public/app/db x AZ a,c), IGW, NAT Gateway 1개(+EIP), 라우트 테이블 2개 | network.tf |
| 접근 제어 | Security Group 4개(alb, web, bastion, db) + 규칙 11개 | security_groups.tf |
| 운영 진입 | Bastion EC2 t3.micro(public-a, 공인 IP, SSH는 admin_cidr만), 키 페어, AL2023 AMI 조회 | bastion.tf |
| 웹 계층 | ALB(HTTP 80) + 타깃 그룹 + 리스너, 시작 템플릿 + ASG(min1/max2, app 서브넷) | alb.tf, web_asg.tf |
| DB 계층 | RDS MySQL 8.0 db.t3.micro, 단일 AZ, 암호화, 비공개, 백업 7일 | rds.tf |
| 저장 | S3 버킷(퍼블릭 차단 4종, ACL 비활성, 버전, SSE-S3) | s3.tf |
| 권한 | EC2 역할(버킷 읽기 + SSM) + 인스턴스 프로파일 | iam.tf |
| 관측 | CloudWatch 경보(UnHealthyHostCount) + 로그 그룹 | monitoring.tf |

설계에는 있지만 이번 주 코드에 없는 것: API ASG + 내부 NLB, ElastiCache Redis, RDS Read Replica, AZ-c NAT Gateway, Route 53, CloudFront, WAF, HTTPS 리스너(ACM).

## 실행

    # 1회: 실제 값 작성 (커밋 금지). step6-1-setup.sh 가 만들어 준다.
    #   admin_cidr = "<내 공인 IP>/32", ssh_public_key = "<~/.ssh/capstone.pub 내용>", db_password = "<20자>"
    terraform init
    terraform fmt -check -recursive && terraform validate
    trivy config . --tf-vars terraform.tfvars.example --severity HIGH,CRITICAL --exit-code 1   # PR 게이트와 같은 조건
    terraform plan -out=three-tier.tfplan
    terraform apply three-tier.tfplan            # 약 10~15분 (RDS가 가장 오래 걸림)
    terraform output                  # alb_dns_name, bastion_public_ip, rds_endpoint
    curl -s http://<alb_dns_name>/    # 200 + 인스턴스 ID 페이지
    ssh -i ~/.ssh/capstone ec2-user@<bastion_public_ip> 'mysql -h <rds_endpoint> -u admin -p -e "SELECT VERSION();"'
    terraform destroy                 # 같은 날 반드시 실행

## 비용 규칙

시간당 요금이 붙는 자원: NAT Gateway, ALB, RDS, EC2(프리티어 초과 시). apply 당일 destroy. destroy 후 `step6-4-destroy.sh`가 남은 자원을 태그(Stack=three-tier)로 확인한다.

## Trivy 결과 (trivy-checks 기준, 2026-10-11 로컬 스캔)

HIGH/CRITICAL 0건. 아래 5건은 설계상 필요한 설정이라 inline `#trivy:ignore` 주석으로 예외 처리하고 코드 바로 위에 사유를 적었다. 주석을 제거한 대조 스캔에서는 정확히 이 5건이 다시 나타난다.

| ID | 심각도 | 리소스 | 사유 | 보상 통제 / 다음 단계 |
|---|---|---|---|---|
| AWS-0053 | HIGH | aws_lb.web (internal=false) | 사용자 트래픽을 받는 ALB는 공개가 목적 | ALB SG 80만, WEB은 ALB SG에서만 수신. 다음: WAF |
| AWS-0054 | CRITICAL | aws_lb_listener.http | HTTPS에 필요한 도메인/ACM 인증서가 범위 밖 | 다음: Route 53 + ACM + 443 리스너, 80→443 리다이렉트 |
| AWS-0104 | CRITICAL | web_https_out, bastion_https_out | 패키지 설치/SSM 통신용 아웃바운드 | 목적지 포트 443만. 다음: S3 게이트웨이 엔드포인트 + 프리픽스 리스트 |
| AWS-0132 | HIGH | S3 SSE 설정 | 고객 관리형 KMS 키는 키 요금/삭제 대기 기간 | SSE-S3(AES256) 적용 |

남은 finding: MEDIUM 2(AWS-0178 VPC Flow Logs, AWS-0177 RDS 삭제 보호), LOW 3(AWS-0017 로그 그룹 KMS, AWS-0089 S3 로깅, AWS-0133 Performance Insights). 모두 문서에 기록, 게이트 대상 아님.

## 연구와의 연결

이 스택이 V8(정상 기능 확인) 테스트베드의 기준(정상) 상태다. 시나리오는 이 기준에서 설정 하나를 망가뜨려 만든다.

| 시나리오 | 망가뜨리는 지점 | Trivy 규칙 | V8 정상 기능 확인 |
|---|---|---|---|
| 1 과다 개방 SG | bastion_ssh_in의 cidr_ipv4를 0.0.0.0/0으로 | AWS-0107 | admin_cidr에서 SSH 성공, ALB 200 유지 |
| 2 Public S3 | public_access_block 4종 false, 또는 블록 삭제 | AWS-0086/0087/0091/0093 | WEB 역할로 GetObject 성공 유지 |
| 3 IAM 과다 권한 | web_s3_read를 Action "*", Resource "*"로 | (7주차 확정, trivy-checks에서 AWS-0057은 deprecated 표기 - 확인 필요) | WEB 역할로 GetObject 성공 유지 |
