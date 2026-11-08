# 요구사항 출처 — 웹 서버 역할(IAM)의 권한 (팀 설계 문서 발췌 + 고객 요청 6)

IaCPatch ③ 의 IAM 요구사항 v1 은 아래 '요구사항 v1 에 옮긴 것' 을 옮긴 **초안**이고, 담당자가 이 글과 맞는지 보고 이름을 적어 **확정**해야 검사 기준이 된다.
팀 설계 문서의 읽기 권한에, 고객이 요청 6 에서 새로 부탁한 **업로드(PutObject) 하나**를 더한 것이다.

## 팀 설계 문서의 문장 (그대로) — `docs/architecture/three-tier-design.md` (김윤재 · A, 2026-10-12)

1.12절 IAM: "신뢰 정책(누가 쓰나: ec2.amazonaws.com) + 권한 정책(무엇을: assets 버킷 GetObject/ListBucket, SSM 관리형 정책). 리소스를 버킷 ARN으로 못 박았다."

2.2절 결정 10: "IAM 역할 최소 권한(버킷 ARN 지정) | 시나리오 3의 정상 기준 | 관리형 S3FullAccess: 과다 권한"

## 고객 요청 6 (가상)의 문장 (그대로) — `scenarios/requests/three-tier-team-upload.md`

"웹 서버가 자산 버킷에 파일을 올릴 수 있어야 합니다(업로드). 올리기 말고 지우기 · 설정 바꾸기 같은 다른 작업은 필요 없습니다."

## 요구사항 v1 에 옮긴 것 (웹 서버 역할 `aws_iam_role.web`)

허용해도 되는 권한 — 이 밖의 권한은 모두 '요구사항 밖'

1. `s3:GetObject` — assets 버킷의 객체 (`${aws_s3_bucket.assets.arn}/*`)
2. `s3:ListBucket` — assets 버킷 (`${aws_s3_bucket.assets.arn}`)
3. `s3:PutObject` — assets 버킷의 객체 (요청 6)
4. AWS 관리형 정책 `AmazonSSMManagedInstanceCore` (SSM 접속)

꼭 남아 있어야 하는 권한 — 없어지면 웹 서버가 파일을 못 읽거나 못 올림

1. `s3:GetObject` · 2. `s3:ListBucket` · 3. `s3:PutObject` (위와 같은 리소스)

## 옮기지 않은 것

- 버킷 이름: 코드가 `bucket_prefix` 로 apply 때 정하므로 이름 대신 코드의 참조(`aws_s3_bucket.assets`)로 적었다.
- 신뢰 정책(ec2.amazonaws.com): 요구사항 파일 형식에 칸이 없다. 바꾸는 수정은 팀 정책이 막고(V5), 누구나로 열면 요구사항 검사(V6)도 실패로 본다.
