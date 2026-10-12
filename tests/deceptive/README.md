# tests/deceptive - V6 Intent Oracle 테스트 세트

계획서 6주차 A 항목(7주차로 이월, 2026-10-13 완료). 사전 실험 `experiments/trivy-sg-probe/cases`에서 V6 검증에 필요한 케이스만 승격했다.
기대 결과와 각 케이스가 요구하는 V6 기능은 `cases.json`에 기계가 읽을 수 있는 형태로 있다. B의 V6 테스트 하네스는 이 파일을 파라미터로 읽는다.

질문(오라클): "22/tcp가 IPv4 인터넷 전체에서 실효적으로 열려 있는가". 소스 문자열이 아니라 실효 값으로 판정한다.

| 케이스 | 종류 | Trivy AWS-0107 (재측정) | V6 기대 | V6가 필요로 하는 기능 |
|---|---|---|---|---|
| 00-baseline | 양성 대조 | FAIL | EXPOSED | 단일 CIDR |
| 00-baseline-fixed | 음성 대조 | PASS | NOT_EXPOSED | 오탐 없음 |
| 01-cidr-split | 기만 | PASS (미검출) | EXPOSED | CIDR 합집합 |
| 06-prefix-list | 기만 | PASS (미검출) | EXPOSED | prefix list 전개 |
| 08-second-sg | 기만 | FAIL (legacy SG) | EXPOSED | 다중 SG 합산 |

게이트 B 통과 조건: 01·06·08이 EXPOSED, 00-baseline-fixed가 NOT_EXPOSED.

## 입력 형식에 대한 메모
- 케이스는 Terraform 디렉터리다. V6가 HCL을 직접 읽든 `terraform show -json`의 plan JSON을 읽든 B가 정한다. plan JSON을 쓰면 06의 prefix list entry는 같은 구성 안의 리소스라 plan JSON에 들어 있다. 실제 AWS에 이미 있는 prefix list는 V7(`describe-managed-prefix-lists`)에서 전개한다.
- 08의 AMI ID는 사전 실험 당시 값이라 apply는 하지 않는다. plan/HCL 분석용이다.
- 재측정 명령: `trivy config tests/deceptive/<case> --format json`
