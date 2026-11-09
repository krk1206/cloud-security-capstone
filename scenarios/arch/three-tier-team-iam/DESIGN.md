# 팀 설계 문서 — 웹 서버 역할(IAM)의 권한 (발췌)

출처: `docs/architecture/three-tier-design.md` (김윤재 · A, 2026-10-12) 1.12절 · 2.2절 결정 10 · 3.3절 실행 기록. 이 파일은 그 문서에서 **웹 서버 역할이 가져야 하는 권한**에 관한 문장만 그대로 옮긴 것이다 (요약 · 해석 없음).
IaCPatch ③ 의 IAM 요구사항 v1 은 아래 '요구사항 v1 에 옮긴 것' 을 옮긴 **초안**이고, 담당자가 이 글과 맞는지 보고 이름을 적어 **확정**해야 검사 기준이 된다.

## 설계 문서의 문장 (그대로)

1.12절 IAM: "WEB 인스턴스에 액세스 키를 두지 않고 역할(role)을 붙인다. 인스턴스는 IMDS에서 임시 자격증명을 받는다."

1.12절 IAM: "신뢰 정책(누가 쓰나: ec2.amazonaws.com) + 권한 정책(무엇을: assets 버킷 GetObject/ListBucket, SSM 관리형 정책). 리소스를 버킷 ARN으로 못 박았다."

2.2절 결정 10: "IAM 역할 최소 권한(버킷 ARN 지정) | 시나리오 3의 정상 기준 | 관리형 S3FullAccess: 과다 권한"

3.3절 실행 기록: "S3 읽기(WEB 역할) | SSM send-command로 WEB 인스턴스에서 실행: ListBucket·GetObject 성공, PutObject는 AccessDenied(역할 정책에 없음)"

## 요구사항 v1 에 옮긴 것 (웹 서버 역할 `aws_iam_role.web`)

허용해도 되는 권한 — 이 밖의 권한은 모두 '요구사항 밖'

1. `s3:GetObject` — assets 버킷의 객체 (`${aws_s3_bucket.assets.arn}/*`)
2. `s3:ListBucket` — assets 버킷 (`${aws_s3_bucket.assets.arn}`)
3. AWS 관리형 정책 `AmazonSSMManagedInstanceCore` (SSM 접속)

꼭 남아 있어야 하는 권한 — 없어지면 웹 서버가 파일을 못 읽음

1. `s3:GetObject` — assets 버킷의 객체
2. `s3:ListBucket` — assets 버킷

## 옮기지 않은 것

- 버킷 이름: 코드가 `bucket_prefix` 로 apply 때 정하므로 이름 대신 코드의 참조(`aws_s3_bucket.assets`)로 적었다.
- 신뢰 정책(ec2.amazonaws.com): 요구사항 파일 형식에 칸이 없다. 신뢰 정책을 바꾸는 수정은 팀 정책(`policy/patch_policy.json`)이 막고(V5), 누구나 역할을 맡을 수 있게 바꾸면 요구사항 검사(V6)도 실패로 본다.
