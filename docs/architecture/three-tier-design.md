# AWS 3-Tier 웹 서비스 아키텍처 설계 및 Terraform 자동화 보고

작성: 김윤재(A, 클라우드 인프라) / 6주차 / 작성일 2026-10-12 / 대상: 지도교수 주간 미팅
대응 지시(2026-10-06): "AWS에 대해 학습 → 아키텍처 설계 → Terraform으로 자동화까지 만들어올 것, 토폴로지는 제시한 형태로 그려올 것, 미팅 전 보고 준비"

## 0. 요약

교수님이 제시한 3-Tier 토폴로지(Route 53 / WAF / CloudFront / ALB / WEB ASG / NLB / API ASG / Redis / MySQL Master-Slave / S3 / IAM / CloudWatch, AZ 2개)를 기준으로 Seoul 리전용 설계를 그리고, 그중 네트워크·웹 계층·DB 계층·S3·IAM·CloudWatch를 Terraform 12개 파일(주석 포함 약 700줄)로 작성해 샌드박스 계정에 apply → 동작 확인 → destroy 했다. API 계층(내부 NLB + API ASG), Redis, Read Replica, Route 53/CloudFront/WAF, HTTPS는 설계와 그림에 포함하고 코드는 다음 주로 넘겼다. Trivy 스캔은 HIGH/CRITICAL 0건이며, 설계상 필요한 5개 예외는 코드 안에 사유를 적었다.

| 지시 | 결과물 | 상태 |
|---|---|---|
| 토폴로지를 제시한 형태로 그릴 것 | docs/architecture/three-tier.drawio, three-tier.png | 완료 |
| AWS 학습 | 2절 구성 요소별 역할 정리 | 완료 |
| 아키텍처 설계(DB 선택 포함) | 3절 설계 결정 12개, DB 비교표 | 완료 |
| Terraform 자동화 | infrastructure/three-tier (12 파일), apply/destroy 기록 4절 | 코어 완료, API 계층 등은 다음 주 |
| 즉석 작성 테스트 대비 | docs/architecture/terraform-live-practice.md, 연습 기록 7절 | 진행 |

## 1. AWS 학습 정리 - 구성 요소별 역할

표기: 역할 / 왜 그 위치인가 / 이번 설계의 값 / Terraform 리소스

### 1.1 Region, Availability Zone
- 리전은 독립된 지리적 영역, AZ는 리전 안의 물리적으로 분리된 데이터센터 묶음이다. AZ 하나가 죽어도 다른 AZ는 산다.
- 교수님 그림은 Tokyo(ap-northeast-1), 우리는 샌드박스 계정이 있는 Seoul(ap-northeast-2). AZ는 2a, 2c.
- 2개 AZ에 같은 계층을 배치하면 가용성이 생기고, ALB·RDS 서브넷 그룹은 AZ 2개 이상을 요구한다.

### 1.2 VPC와 서브넷
- VPC는 계정 안의 격리된 사설 네트워크(10.10.0.0/16). 서브넷은 VPC를 AZ 단위로 자른 주소 범위(/24).
- public/private는 서브넷의 속성이 아니라 라우트 테이블로 정해진다. 0.0.0.0/0 → IGW 경로가 있는 라우트 테이블에 연결된 서브넷이 public이다.
- 3계층 분리: public(ALB, Bastion, NAT) / app(WEB, 다음 주 API) / db(RDS). DB 서브넷은 IGW 경로도 NAT 경로도 쓰지 않아도 되지만 라우트 테이블은 app과 공유한다(이번 주 단순화).
- `aws_vpc`, `aws_subnet`(count = 2로 AZ마다 하나), `aws_route_table`, `aws_route`, `aws_route_table_association`

### 1.3 Internet Gateway
- VPC와 인터넷 사이의 양방향 출입구. VPC당 1개. 공인 IP를 가진 리소스의 패킷을 인터넷으로 내보내고 응답을 받는다.
- `aws_internet_gateway`

### 1.4 NAT Gateway
- private 서브넷 인스턴스가 밖으로 나가는(패키지 설치, SSM Agent 통신) 단방향 출구. 밖에서 시작하는 접속은 들어오지 못한다.
- public 서브넷에 두는 이유: NAT 자신이 IGW 경로를 타야 하기 때문. 고정 공인 IP(EIP)를 가진다.
- 교수님 그림은 AZ당 1개(한 AZ의 NAT가 죽어도 다른 AZ는 나감). 비용 때문에 이번 주는 AZ-a에 1개. AZ-c의 app 서브넷도 이 NAT를 쓴다(AZ-a 장애 시 AZ-c의 아웃바운드가 끊기는 단일 장애점 - 알고 있는 제한).
- `aws_eip`, `aws_nat_gateway`

### 1.5 Security Group
- 인스턴스(정확히는 ENI)에 붙는 상태 기반 방화벽. 허용 규칙만 있고, 들어온 연결의 응답은 자동으로 나간다.
- 출발지를 IP 대신 다른 SG로 지정할 수 있다(참조 SG). "ALB SG를 가진 ENI에서 오는 80"처럼 쓰면 인스턴스 IP가 바뀌어도 규칙이 유지된다.
- 이번 설계의 경로: 인터넷 →80→ ALB SG →80→ WEB SG →3306→ DB SG, 운영자 IP/32 →22→ Bastion SG →3306→ DB SG. 아웃바운드는 WEB·Bastion의 443만.
- 규칙을 `aws_security_group` 안의 ingress/egress 블록이 아니라 `aws_vpc_security_group_ingress_rule` / `egress_rule` 리소스로 뺀 이유: ALB SG가 WEB SG를, WEB SG가 ALB SG를 서로 가리키면 인라인 방식은 순환 참조 오류가 난다.
- 우리 연구의 시나리오 1(과다 개방 SG)이 바로 이 규칙에서 0.0.0.0/0이 들어간 상태다.

### 1.6 Bastion Host
- 운영자가 private 리소스(RDS 등)에 접근할 때 거치는 public 서브넷의 EC2. SSH 22를 운영자 공인 IP /32에만 연다.
- 대안: SSM Session Manager. 포트를 전혀 열지 않고 IAM 권한으로 셸을 연다. WEB 인스턴스에는 이미 SSM 권한을 붙였다. 교수님 그림대로 Bastion을 두고, SSM은 대안으로 설명한다.
- `aws_instance`, `aws_key_pair`, `data.aws_ami`

### 1.7 Application Load Balancer / Network Load Balancer
- ALB: L7(HTTP/HTTPS). 경로·호스트·헤더로 라우팅, 헬스체크, 여러 AZ의 인스턴스로 분산. 웹 계층 앞에 둔다.
- NLB: L4(TCP/UDP). 고정 IP, 매우 높은 처리량, 지연 작음. 교수님 그림에서 WEB → API 사이에 있는 이유: 내부 서비스 간 TCP 호출을 받는 내부(internal) 로드밸런서로 쓰기 위해서다. 다음 주 코드.
- ALB는 public 서브넷 2개에 놓이고 자체 SG를 가진다. 타깃 그룹(어디로 보낼지) + 리스너(어느 포트로 받을지)로 구성된다.
- `aws_lb`, `aws_lb_target_group`, `aws_lb_listener`

### 1.8 Launch Template과 Auto Scaling Group
- 시작 템플릿: 인스턴스 설정(AMI, 타입, SG, IAM 역할, user_data, IMDS, 디스크)의 묶음. ASG: 그 템플릿으로 인스턴스를 min~max 사이에서 유지한다. 헬스체크(ELB) 실패 인스턴스는 교체한다.
- WEB 인스턴스는 app 서브넷(private)에 뜨고 공인 IP가 없다. 들어오는 길은 ALB뿐, 나가는 길은 NAT뿐이다.
- user_data가 nginx를 설치하고 인스턴스 ID를 보여주는 페이지를 만든다. 메타데이터는 IMDSv2 토큰으로만 읽는다.
- `aws_launch_template`, `aws_autoscaling_group`

### 1.9 RDS MySQL (DB 계층)
- 관리형 관계형 DB. 패치, 백업, 장애조치를 AWS가 한다. db 서브넷 2개에 걸친 서브넷 그룹 위에 놓이고 외부 비공개(publicly_accessible = false), 저장소 암호화.
- 교수님 그림의 "MySQL Master/Slave": RDS 용어로는 Primary + Read Replica다. Read Replica는 비동기 복제로 읽기 부하를 나누고, Primary 장애 시 수동 승격할 수 있다.
- 혼동 주의: Multi-AZ는 동기 복제되는 대기(standby) 인스턴스로 장애조치 전용이며 읽기 요청을 받지 않는다. Read Replica와 다른 기능이다.
- 이번 주는 Primary 1개(단일 AZ). Read Replica는 `aws_db_instance`에 `replicate_source_db`를 지정하면 된다(다음 주).
- `aws_db_subnet_group`, `aws_db_instance`

### 1.10 ElastiCache Redis (설명만)
- 메모리 캐시. 세션 저장, 자주 읽는 조회 결과 캐시로 DB 부하를 줄인다. app 서브넷에 두고 WEB/API SG에서만 6379를 받는다.
- 다음 주 코드: `aws_elasticache_subnet_group`, `aws_elasticache_replication_group`(전송·저장 암호화 켬: Trivy AWS-0045/0051 HIGH)

### 1.11 S3
- 객체 저장소. 정적 파일, 백업, 로그. VPC 밖의 리전 서비스라서 그림에서도 VPC 바깥에 그린다.
- 이번 설계: 퍼블릭 접근 차단 4종 켬, ACL 비활성화(BucketOwnerEnforced), 버전 관리, SSE-S3 암호화. 우리 연구의 시나리오 2(Public S3)는 이 차단이 빠진 상태다.
- `aws_s3_bucket`, `aws_s3_bucket_public_access_block`, `aws_s3_bucket_ownership_controls`, `aws_s3_bucket_versioning`, `aws_s3_bucket_server_side_encryption_configuration`

### 1.12 IAM
- WEB 인스턴스에 액세스 키를 두지 않고 역할(role)을 붙인다. 인스턴스는 IMDS에서 임시 자격증명을 받는다.
- 신뢰 정책(누가 쓰나: ec2.amazonaws.com) + 권한 정책(무엇을: assets 버킷 GetObject/ListBucket, SSM 관리형 정책). 리소스를 버킷 ARN으로 못 박았다.
- 우리 연구의 시나리오 3(IAM 과다 권한)은 이 정책이 Action "*", Resource "*"인 상태다.
- `aws_iam_role`, `aws_iam_role_policy`, `aws_iam_role_policy_attachment`, `aws_iam_instance_profile`, `data.aws_iam_policy_document`

### 1.13 CloudWatch
- 지표·로그·경보. 이번 주: ALB 타깃 그룹의 UnHealthyHostCount >= 1이 2분 지속되면 ALARM 상태가 되는 경보 1개, 웹 로그 그룹 1개(에이전트 연동은 다음 단계).
- `aws_cloudwatch_metric_alarm`, `aws_cloudwatch_log_group`

### 1.14 Route 53, CloudFront, WAF (설명만)
- Route 53: DNS. 도메인을 ALB/CloudFront로 연결. 도메인 구입 전까지 코드 없음.
- CloudFront: CDN. 정적 콘텐츠를 엣지에서 제공, HTTPS 종단. 원본을 ALB와 S3로 둔다.
- WAF: L7 방화벽. SQL 인젝션/XSS 관리형 규칙, 속도 제한. CloudFront 또는 ALB에 연결한다. Trivy AWS-0053(공개 ALB) 예외의 다음 단계 보상 통제다.

## 2. 아키텍처 설계

그림: `three-tier.png` (원본 `three-tier.drawio`). 진한 요소가 이번 주 apply 범위, 흐린 요소가 설계 포함·다음 단계.

### 2.1 트래픽 흐름
1. 사용자 → (다음 단계: Route 53 → CloudFront → WAF) → IGW → ALB(80) → WEB 인스턴스 nginx(80)
2. WEB → (다음 단계: 내부 NLB → API) → RDS MySQL(3306) / Redis(6379)
3. 아웃바운드: WEB, (API) → NAT Gateway → IGW → 인터넷(443만)
4. 운영자 → Bastion(22, 공인 IP/32만) → RDS(3306)

### 2.2 설계 결정

| 번호 | 결정 | 이유 | 대안과 버린 이유 |
|---|---|---|---|
| 1 | AZ 2개(2a, 2c) | ALB·RDS 서브넷 그룹의 최소 요건이며 한 AZ 장애를 견딤 | AZ 1개: 요건 미달. AZ 3개: 비용 |
| 2 | 서브넷 3계층(public/app/db) x 2 | DB를 인터넷 경로가 전혀 없는 서브넷에 격리 | 2계층(public/private): DB와 앱이 같은 서브넷, 격리 약함 |
| 3 | NAT Gateway 1개 | 시간당 과금, 실습 범위 | AZ당 1개가 정석. NAT 인스턴스: 직접 운영 부담 |
| 4 | Bastion 유지 + SSM 권한 병행 | 교수님 그림 반영, SSM은 포트 없는 대안 | SSM만: 그림과 다름 |
| 5 | ALB HTTP 80만 | 도메인·인증서 없음 | HTTPS: ACM 인증서에 도메인 필요, 다음 단계 |
| 6 | ASG min 1 / max 2, desired 1 | 비용, 확장 동작은 desired 2로 확인 가능 | 고정 EC2: 교체·확장 불가 |
| 7 | DB = RDS MySQL 8.0 db.t3.micro | 아래 비교표 | |
| 8 | RDS 단일 AZ, Read Replica는 다음 주 | 비용(Multi-AZ는 2배) | |
| 9 | S3 퍼블릭 차단 + ACL 비활성 + SSE-S3 | 기본 보안, Trivy HIGH 4건 해소 | KMS 고객 키: 키 요금·삭제 대기, 다음 단계 |
| 10 | IAM 역할 최소 권한(버킷 ARN 지정) | 시나리오 3의 정상 기준 | 관리형 S3FullAccess: 과다 권한 |
| 11 | IMDSv2 강제, EBS/RDS 암호화 | Trivy HIGH 규칙 충족, 비용 없음 | |
| 12 | Terraform 모듈 미사용, 리소스 단위 파일 분리 | 리소스 하나하나를 설명하고 즉석 작성에 대비 | 모듈: 추상화로 설명이 어려움, 다음 단계 |

### 2.3 DB 선택 비교

| 후보 | 장점 | 단점 | 판단 |
|---|---|---|---|
| RDS MySQL | 관리형, MySQL 호환, Read Replica/Multi-AZ 제공, 프리티어 인스턴스 클래스 있음 | 인스턴스 시간당 과금 | 채택 |
| Aurora MySQL | 성능·복제 우수 | 최소 비용이 높고 실습 범위 초과 | 보류 |
| MySQL on EC2 | 가장 저렴 | 백업·패치·복제를 직접 운영, 보안 설정 부담 | 비채택 |
| DynamoDB | 서버리스, 상시 무료 범위 | 관계형 아님, 그림의 Master/Slave 구조와 다름 | 비채택 |

### 2.4 교수님 그림과 다른 점

| 항목 | 교수님 그림 | 이번 설계 | 이유 |
|---|---|---|---|
| 리전 | Tokyo | Seoul(ap-northeast-2) | 샌드박스 계정 리전 |
| NAT Gateway | AZ당 1개 | AZ-a 1개 | 비용. 그림에는 AZ-c NAT를 다음 단계로 표시 |
| API ASG + NLB | 있음 | 설계 포함, 코드 다음 주 | 하루 안에 검증 가능한 범위로 축소 |
| Redis | 있음 | 설계 포함, 코드 다음 주 | 같음 |
| MySQL Master/Slave | 있음 | Primary만, Replica 다음 주 | 비용 |
| Route 53 / CloudFront / WAF | 있음 | 설명만 | 도메인 없음, 요금 |
| 서브넷 | public/private 2계층 | public/app/db 3계층 | DB 격리 |

## 3. Terraform 자동화

### 3.1 파일 구조 (infrastructure/three-tier)

| 파일 | 내용 |
|---|---|
| provider.tf | Terraform >= 1.5, AWS provider ~> 5.0, 리전/프로파일, 공통 태그 |
| variables.tf | 리전, AZ, CIDR 6개, admin_cidr, ssh_public_key, 인스턴스 타입, DB 계정(sensitive) |
| network.tf | VPC, 서브넷 6, IGW, EIP + NAT, 라우트 테이블 2, 라우트 2, 연결 6 |
| security_groups.tf | SG 4, 규칙 11 |
| bastion.tf | AMI 조회, 키 페어, Bastion 인스턴스 |
| alb.tf | ALB, 타깃 그룹, 리스너 |
| web_asg.tf | 시작 템플릿, ASG |
| rds.tf | 서브넷 그룹, MySQL 인스턴스 |
| s3.tf | 버킷 + 설정 4개 |
| iam.tf | 역할, 정책 문서 2, 인라인 정책, 관리형 정책 연결, 인스턴스 프로파일 |
| monitoring.tf | 경보, 로그 그룹 |
| outputs.tf | ALB DNS, Bastion IP, RDS 엔드포인트, 버킷, VPC, NAT IP |
| bastion_user_data.sh, web_user_data.sh | Bastion(mysql 클라이언트), WEB(nginx + 인스턴스 ID 페이지) |
| terraform.tfvars.example | CI용 예시 값. 실제 값은 terraform.tfvars(커밋 제외) |

### 3.2 사용한 Terraform 문법과 뜻
- `count = length(var.azs)` + `count.index`: AZ 수만큼 같은 리소스를 만들고 인덱스로 CIDR·AZ를 고른다. `aws_subnet.public[0]`이 AZ-a.
- `aws_subnet.public[*].id`: count로 만든 전체의 id 리스트. ALB subnets, ASG vpc_zone_identifier, DB 서브넷 그룹에 사용.
- 리소스 참조(`aws_vpc.main.id`)가 의존 순서를 만든다. 명시적 `depends_on`은 NAT → IGW 하나만.
- `data "aws_ami"`: apply 시점의 최신 AL2023 AMI ID를 조회. `owners = ["amazon"]`으로 출처 고정.
- `file()`, `base64encode()`: user_data 스크립트를 파일로 분리. 시작 템플릿은 base64 필수.
- `sensitive = true`: db_password가 plan/apply 출력에 안 보임.
- `#trivy:ignore:<ID>`: 바로 아래 블록의 해당 finding을 예외 처리. 사유를 주석으로 함께 둔다.

### 3.3 실행 기록 (step 스크립트 출력에서 기입)

| 항목 | 값 |
|---|---|
| terraform validate | Success! The configuration is valid. |
| terraform plan | 54 to add, 0 to change, 0 to destroy |
| trivy config (HIGH,CRITICAL) | 0건 (전체: MEDIUM 2, LOW 3. 로컬 스캔과 동일) |
| terraform apply 시작~완료 | 19:01:02 ~ 19:10:12, 9분 10초 (NAT Gateway 1분 54초, ALB 2분 22초, RDS 8분 52초) |
| 리소스 수 | Apply complete! Resources: 54 added |
| ALB 응답 | HTTP 200, instance i-070d0f07353ff175e (ap-northeast-2a), 첫 시도에 성공 |
| Bastion SSH | 성공 (ip-10-10-0-219, mysql 클라이언트 10.5.29-MariaDB 설치 확인) |
| Bastion → RDS mysql SELECT VERSION() | 8.0.46 |
| S3 읽기(WEB 역할) | SSM send-command로 WEB 인스턴스에서 실행: ListBucket·GetObject 성공, PutObject는 AccessDenied(역할 정책에 없음) |
| terraform destroy 소요 | 6분 46초 (19:26:28 ~ 19:33:14), Resources: 54 destroyed |
| destroy 후 잔여 자원 확인 | EC2/NAT/EIP/ALB/RDS/VPC/S3 모두 0건. 전체 가동 시간 32분 (`docs/worklog/evidence-2026-10-12-three-tier.txt`) |

### 3.4 비용 관리
- 시간당 과금 자원: NAT Gateway, ALB, RDS, EC2(프리티어 초과분). apply 당일 destroy를 규칙으로 한다.
- destroy 후 태그(Stack=three-tier)로 잔여 자원을 조회한다. AWS Budgets 월 한도 알림 설정 여부: 미설정 (확인 필요, 7주차에 설정)
- 계정의 프리티어 방식(12개월 프리티어 / 크레딧) 확인: 확인 필요 (Billing → Free Tier). 오늘 32분 가동분 요금은 다음 날 Billing에서 확인

### 3.5 파이프라인과의 연결
- 이 폴더를 PR로 올리면 3주차에 만든 `iac-scan.yml`이 변경 폴더만 `trivy config --severity HIGH,CRITICAL --exit-code 1`로 검사하고, 5주차의 `terraform-plan.yml`이 OIDC 역할로 `terraform plan`을 돌려 plan.json을 저장한다.
- 즉, 이 코드는 게이트를 통과하는 "정상 기준" 코드다. 시나리오는 여기서 설정 하나를 망가뜨린 변형이며, 패치 후 V8(정상 기능 확인)은 "ALB 200 응답 + Bastion → RDS 접속 + WEB 역할의 S3 읽기"로 정의한다.

## 4. 보안 관점 - Trivy 결과

로컬 스캔(trivy-checks 2026-10 기준, `--tf-vars terraform.tfvars.example`): HIGH/CRITICAL 0, MEDIUM 2, LOW 3. CI 재현 결과: PR 체크 통과 - iac-scan 22초, terraform-plan 29초(OIDC 읽기 전용 역할, plan.json 아티팩트 생성)

### 4.1 코드에서 충족한 HIGH 규칙
AWS-0052(ALB 잘못된 헤더 차단), AWS-0028/0130(IMDSv2), AWS-0131/0008(EBS 암호화), AWS-0180(RDS 비공개), AWS-0080(RDS 암호화), AWS-0086/0087/0091/0093(S3 퍼블릭 차단), AWS-0088(S3 암호화), AWS-0164(서브넷 자동 공인 IP 끔)

### 4.2 예외 처리 5건 (inline ignore, 코드 위에 사유)

| ID | 심각도 | 리소스 | 왜 필요한 설정인가 | 보상 통제 | 다음 단계 |
|---|---|---|---|---|---|
| AWS-0053 | HIGH | aws_lb.web | 사용자 트래픽을 받는 ALB는 공개가 목적 | ALB SG 80만, WEB은 ALB SG에서만 | WAF 연결 |
| AWS-0054 | CRITICAL | aws_lb_listener.http | HTTPS에 도메인+ACM 인증서 필요 | 없음(실습 트래픽) | Route 53 + ACM + 443, 80→443 리다이렉트 |
| AWS-0104 | CRITICAL | web_https_out | 패키지 설치·SSM용 아웃바운드 | 목적지 포트 443만, NAT 경유 | S3 게이트웨이 엔드포인트, 프리픽스 리스트 |
| AWS-0104 | CRITICAL | bastion_https_out | 패키지 설치용 아웃바운드 | 443만 | 같음 |
| AWS-0132 | HIGH | S3 SSE 설정 | 고객 관리형 KMS 키 요금·삭제 대기 | SSE-S3 AES256 적용 | 필요 시 KMS 키 |

예외 주석을 제거한 대조 스캔에서 위 5건만 다시 나타난다(스캔 로그 보관).

### 4.3 남은 MEDIUM/LOW
AWS-0178 VPC Flow Logs 미설정(MEDIUM, 다음 단계), AWS-0177 RDS 삭제 보호 꺼짐(MEDIUM, 실습용 destroy 때문), AWS-0133 Performance Insights(LOW, db.t3.micro 미지원), AWS-0017 로그 그룹 KMS(LOW), AWS-0089 S3 액세스 로깅(LOW)

### 4.4 이 토폴로지 안에서 연구 시나리오가 들어가는 자리

| 시나리오 | 정상 기준(이 코드) | 망가진 상태 | Trivy 규칙 |
|---|---|---|---|
| 1 과다 개방 SG | bastion_ssh_in = admin_cidr/32 | 0.0.0.0/0 | AWS-0107 |
| 2 Public S3 | public_access_block 4종 true | false 또는 블록 삭제 | AWS-0086/0087/0091/0093 |
| 3 IAM 과다 권한 | GetObject/ListBucket, 버킷 ARN | Action "*", Resource "*" | 7주차 확정 |

## 5. 하지 않은 것과 다음 주

- API ASG + 내부 NLB, Redis, RDS Read Replica, AZ-c NAT, HTTPS(ACM), Route 53, CloudFront, WAF, VPC Flow Logs → 7주차에 코드 추가(우선순위: API/NLB → Read Replica → Redis → Flow Logs → HTTPS).
- 원격 state(S3 + 잠금)는 계획대로 8주차. 이번 주 apply는 A 1명만 수행(로컬 state 충돌 방지).
- 계획서의 6주차 A 항목(`tests/deceptive/` 승격)은 이번 지시 대응 때문에 7주차로 이월.

## 6. 즉석 작성 테스트 대비

연습 세트와 구두 설명 체크리스트: `terraform-live-practice.md`. 연습 기록: 1회 [기입]분, 2회 [기입]분, 3회 [기입]분.

## 참고
- VPC/NAT: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html
- Security Group: https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html
- RDS Multi-AZ: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html
- RDS Read Replica: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ReadRepl.html
- ALB: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html
- S3 Block Public Access: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- IMDSv2: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- Terraform AWS provider: https://registry.terraform.io/providers/hashicorp/aws/latest/docs
- Trivy misconfiguration 스캔: https://trivy.dev/latest/docs/scanner/misconfiguration/
- trivy-checks(규칙 소스): https://github.com/aquasecurity/trivy-checks
