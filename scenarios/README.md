# scenarios - 의도적으로 잘못 설정한 Terraform (파이프라인 입력)

`infrastructure/`는 PR 게이트(HIGH/CRITICAL 차단)를 통과해야 하는 정상 코드다. 여기 `scenarios/`는 반대로 **일부러 틀린 코드**라서 게이트를 걸지 않고, `scenario-scan.yml`이 결과만 아티팩트로 남긴다.
기존 `infrastructure/sg-baseline`(시나리오 1)은 워크플로우와 B의 파이프라인 코드가 경로를 참조하고 있어 PR #4 검토 때 이 폴더로 옮긴다.

| 폴더 | 시나리오 | 결함 | 탐지 규칙 | 정상 기준 |
|---|---|---|---|---|
| (infrastructure/sg-baseline) | 1 과다 개방 SG | SSH 22 cidr 0.0.0.0/0 | AWS-0107 (내장) | three-tier bastion_ssh_in = admin_cidr/32 |
| iam-overprivileged | 3 IAM 과다 권한 | 역할 정책 Action "*", Resource "*" | CAPSTONE-IAM-0001 (커스텀, policy/checks) | three-tier iam.tf web_s3_read |
| (예정) s3-public | 2 Public S3 | public_access_block 해제 | AWS-0086/0087/0091/0093 (내장) | three-tier s3.tf |

실행: `trivy config scenarios/<name> --config-check policy/checks --check-namespaces user --format json`
