# scenarios/iam-overprivileged - 시나리오 3: IAM 과다 권한

7주차 A 항목("두 번째 설정 오류 유형 추가"). 2026-10-13 작성.

## 결함
`main.tf`의 `data.aws_iam_policy_document.web_overprivileged`: EC2 역할의 권한 정책이 `Action: "*"`, `Resource: "*"`.
정상 기준(`infrastructure/three-tier/iam.tf`)은 같은 역할이 assets 버킷의 `s3:GetObject`(객체 ARN)와 `s3:ListBucket`(버킷 ARN)만 가진다.

## 탐지
- Trivy 내장 규칙으로는 **안 잡힌다**. AWS-0057이 2024-12-18에 제거된 스텁이기 때문이다(`policy/checks/README.md`).
- 커스텀 체크 `CAPSTONE-IAM-0001`이 2건(Action, Resource) HIGH로 잡는다.

    trivy config scenarios/iam-overprivileged --config-check policy/checks --check-namespaces user

## 기대 패치 (policy/patch-whitelist.md 6절)
`actions`/`resources`를 `policy/required_permissions.yaml`의 `capstone-iam-baseline-web-role` 목록으로 교체. 다른 변경(역할 생성, 관리형 정책 연결, 신뢰 정책 수정)은 금지.
등급 상한 Medium (IAM 변경). 패치 후 재스캔에서 CAPSTONE-IAM-0001이 0건이어야 한다.

## 정상 기능 확인 (V8)
패치 적용 후에도 역할로 `s3:GetObject`가 성공해야 한다. three-tier에서 쓴 방법 그대로: 인스턴스 프로파일을 붙인 인스턴스에서 SSM send-command로 `aws s3 cp s3://<bucket>/test.txt -`.
이 시나리오 단독으로는 인스턴스가 없으므로, 역할 자체의 권한은 `aws iam simulate-principal-policy --policy-source-arn <role arn> --action-names s3:GetObject --resource-arns <bucket arn>/*`로 확인한다(논문 TerraProbe 3.11의 제어 2, IAM 시뮬레이터).

## 비용
IAM, S3(빈 버킷)는 요금이 없다. apply/destroy 1분 안.
