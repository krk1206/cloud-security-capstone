# sg-baseline

파이프라인의 출발점이 되는 **의도적 설정 오류(Misconfiguration)** Terraform 코드.

SSH(22번) 포트가 `0.0.0.0/0`에 열려 있다. **실수가 아니라 연구용으로 일부러 만든 결함이다.**
Trivy가 이것을 탐지하고, AI가 패치를 생성하고, 검증 스택이 그 패치를 판정한다.

## 파일 구성

| 파일 | 역할 |
|---|---|
| `provider.tf` | AWS 프로바이더 설정, 버전 잠금, 공통 태그 |
| `variables.tf` | 입력 변수 정의 |
| `terraform.tfvars` | 변수 실제값. **계정별로 다르므로 커밋하지 않는다** |
| `main.tf` | 의도적 결함이 포함된 Security Group |
| `outputs.tf` | V7 실측에 사용할 SG ID |

## 파이프라인에서의 위치

    main.tf 의 0.0.0.0/0
       │
       ├─ Trivy 탐지            AVD-AWS-0107
       ├─ AI 패치 생성          6주차
       ├─ V6 Intent Oracle      6주차 — 실효 상태가 실제로 닫혔는지 독립 검증
       └─ V7 AWS 실측           8주차 — describe-security-groups

## 실행

`terraform.tfvars`를 먼저 만들어야 한다.

    # 기본 VPC ID 확인
    aws ec2 describe-vpcs --filters "Name=isDefault,Values=true" \
      --query "Vpcs[0].VpcId" --output text --profile capstone

    # terraform.tfvars 작성
    echo 'vpc_id = "vpc-xxxxxxxx"' > terraform.tfvars

그다음 순서대로 실행한다.

    terraform init
    terraform fmt
    terraform validate
    terraform plan
    terraform apply

### 배포 후 실제 상태 확인 (V7의 원형)

    aws ec2 describe-security-groups \
      --group-ids $(terraform output -raw sg_id) \
      --query "SecurityGroups[0].IpPermissions" \
      --profile capstone

`0.0.0.0/0`이 그대로 조회되면 Terraform 코드와 실제 AWS 상태가 일치한다는 뜻이다.
검증 스택 V7은 이 조회 결과를 CIDR 합집합으로 계산해 실효 개방 여부를 판정한다.

### 정리

    terraform destroy

**테스트가 끝나면 반드시 실행한다.** Security Group 자체는 과금되지 않지만,
사용하지 않는 리소스를 남겨두지 않는 것을 원칙으로 한다.

## 안전 관련

- **EC2 인스턴스를 붙이지 않는다.** 인스턴스가 없는 Security Group은 실제 공격면이 없다.
  인스턴스에 연결하는 순간 22번 포트 개방이 실제 위험이 된다
- 이 코드는 **격리된 샌드박스 계정 전용**이다. 운영 계정에 적용하지 않는다
- 프로바이더의 `default_tags`로 `Project=capstone-2026` 태그가 모든 리소스에 자동 부여된다

## 설계 의도

### 왜 버전을 잠갔는가

`required_version`과 프로바이더 `~> 5.0`으로 범위를 고정했다. 프로바이더 메이저 버전이
올라가면서 문법이 바뀌면 같은 코드가 다른 결과를 낼 수 있다. 실험 기록에 Trivy와 Terraform
버전을 남기는 것과 같은 이유다.

### 왜 액세스 키를 코드에 쓰지 않는가

`provider "aws"`에는 `profile = "capstone"`만 지정한다. 실제 자격 증명은
`~/.aws/credentials`에 있고 저장소에는 올라가지 않는다.

액세스 키가 공개 저장소에 올라가면 자동화된 스크립트가 수분 내에 찾아내 악용하는 사례가
보고되어 있다. 프로필 방식은 이 위험을 구조적으로 차단한다.

### 왜 egress를 명시했는가

`aws_security_group`에 `egress` 블록을 하나도 쓰지 않으면 Terraform이 기존 아웃바운드
규칙을 모두 제거한다. AWS 콘솔의 기본 동작(전체 허용)과 달라서, 인스턴스를 붙였을 때
외부 통신이 막힌다. 혼란을 피하기 위해 명시적으로 작성했다.

이 egress 규칙이 Trivy의 다른 룰(`AVD-AWS-0104`)에 걸릴 수 있다. 실제 탐지 여부는
스캔 결과로 확인한다. 여러 룰이 동시에 뜨는 상황은 검증 스택 V2(신규 finding 증가 확인)의
정확도를 평가할 때 참고 자료가 된다.

### 왜 SG만 만들고 EC2는 만들지 않는가

현 단계(1~7주차)에 필요한 것은 정적 스캔, `terraform plan`, `apply` 후 상태 조회뿐이며
모두 Security Group만으로 가능하다. EC2 인스턴스는 정상 기능 검증(V8, 9주차)에서 허용
트래픽이 실제로 통하는지 확인할 때 추가한다.

인스턴스를 미리 띄우면 비용이 발생하고, 22번 포트가 열린 인스턴스는 공개 인터넷에서
자동화된 접속 시도의 대상이 된다.

## 관련 문서

| 문서 | 내용 |
|---|---|
| `../../한장요약.md` | 프로젝트 전체 요약 |
| `../../README.md` | 개발 계획. 2절에 검증 스택 설계 |
| `../../experiments/trivy-sg-probe/` | Trivy가 놓치는 우회 패턴 실측 기록 |
