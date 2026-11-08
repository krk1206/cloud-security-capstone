# three-tier-team-s3 — 팀 3계층의 시험용 사본 · 시나리오 2 (Public S3) (2026-11-06, D-51)

팀 저장소 `main`(커밋 57b7f81)의 `infrastructure/three-tier/`(김윤재 · A 작성, 6주차) **사본**이다. 원본 폴더는 건드리지 않는다.
원본 README 의 '연구와의 연결' 표의 **시나리오 2(Public S3)** 하나만 넣었다: `aws_s3_bucket_public_access_block.assets` 의 공개 차단 4개를 `false` 로.
시나리오 1(SSH)은 고친 상태(원본 그대로)다.

## 이 예제가 보여 주는 것 — 자동 수정 범위 밖이면 사람에게 넘긴다

IaCPatch 는 이 문제를 **찾지만 고치지 않는다.** 팀 정책 파일(`policy/patch_policy.json`)이 정한 자동 수정 범위 밖이기 때문이다:

- `supported_target_rules` = `AVD-AWS-0107` · `AVD-AWS-0345` · `AVD-AWS-0342` — S3 공개 차단 규칙(AWS-0086 · 0087 · 0091 · 0093)이 없다
- `allowed_change_resource_types` 에 `aws_s3_bucket_public_access_block` 이 없다 — 수정안을 만들어도 V5(plan 비교)가 정책 위반으로 막는다
- 이 리소스에는 '고친 뒤 고객 요구를 지켰나' 를 재는 검사(V6)도 아직 없다

정책은 사람이 정한다(`policy/` 는 AI 가 고치지 않음). 그래서 ② ④ 에서 문제와 위치를 보여 주고, '사람에게 넘김' 칸에 할 일 · 확인 방법을 적는다.
"정책 범위를 벗어나면 확신도와 상관없이 자동으로 하지 않는다" 는 프로젝트 원칙을 그대로 보여 주는 예제다.

## 원본과 다른 곳 (전부)

| 파일 | 원본 | 이 사본 | 왜 |
|---|---|---|---|
| `s3.tf` | `block_public_acls` · `block_public_policy` · `ignore_public_acls` · `restrict_public_buckets` = `true` | 4개 모두 `false` | **일부러 넣은 설정 오류 1개** (원본 README 시나리오 2) |
| `s3.tf` | 2줄 주석 "우리 연구의 시나리오 2(Public S3)는 이 설정이 빠지거나 풀린 상태를 뜻한다." | 지움 | 설정 오류 설명은 README 에만 적는다 (D-32). 그 아래 '퍼블릭 ACL/정책을 전부 막는다' 주석은 원본 그대로 — 값과 주석이 어긋난 상태 |
| `bastion.tf` · `web_asg.tf` · `variables.tf` | (팀 3계층 요청 1 사본 `three-tier-team` 과 같은 변경) | 변수 `ami_id` · 글자(heredoc) · 예시 기본값 | 프로그램은 AWS 접속 · tfvars 없이 plan 한다 (D-32 · D-25) |

`security_groups.tf` · `iam.tf` 와 나머지 파일은 원본 그대로다.

## Trivy (0.74.0, 2026-11-06 이 사본 점검)

HIGH 4 = 시나리오 2 (`aws_s3_bucket_public_access_block.assets` · `s3.tf` 13~16줄): AWS-0086(공개 ACL 막기) · AWS-0087(공개 정책 막기) · AWS-0091(공개 ACL 무시) · AWS-0093(공개 버킷 제한).
그 밖은 원본 README 와 같다 — MEDIUM 2(AWS-0178 · AWS-0177), LOW 3(AWS-0017 · AWS-0089 · AWS-0133).
결과 파일: `experiments/arch-three-tier-team-s3/trivy-scan.json`.

## 팀이 정책을 넓히기로 하면 (사람이 정할 것)

자동 수정까지 가려면 사람이 아래 둘을 정해야 한다 — AI 는 정책 파일을 고치지 않는다.

1. `policy/patch_policy.json` 에 S3 공개 차단 규칙과 바꿀 수 있는 속성을 넣을지: `supported_target_rules` 에 `AVD-AWS-0086` · `AVD-AWS-0087` · `AVD-AWS-0091` · `AVD-AWS-0093`,
   `allowed_change_resource_types` 에 `aws_s3_bucket_public_access_block`, `allowed_attribute_changes` 에 그 4개 속성.
2. 고친 뒤 '고객 요구를 지켰나' 를 잴 검사(V6 S3: 공개 차단 4개 · 버킷 정책의 Principal `*` · ACL)를 만들지 — 지금은 없다.

## 프로그램에서

- ① 예제 카드 '팀 3계층 · 요청 2'. ② 맨 위 가상 고객 요청서(`scenarios/requests/three-tier-team-s3.md`)와 '사람에게 넘김' 칸.
- ④ 에 S3 공개 차단 4건이 '탐지만' 으로 나온다. ⑤~⑧ 로 이어지지 않는다 (수정안 없음).
- 이 폴더는 실험 재료(의도적으로 취약)라서 고쳐서 커밋하지 않는다.
