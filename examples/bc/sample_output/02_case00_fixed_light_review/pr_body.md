## [초안] AVD-AWS-0107 on `aws_security_group.baseline` — ex02-case00-fixed

_이 본문은 로컬에서 생성한 초안이다. 실제 PR 게시·병합·apply 는 사람이 한다._

> ✅ 필수 검증 계층 결과가 모두 있다 (결과 출처는 아래 표 참조). 최종 판단은 사람이 한다.

- 검토 수준: **LIGHT_REVIEW** — 경량 검토 — 사람 1인 확인 후 진행 (자동 반영 아님)
- 위험도: **LOW** (점수 1, risk-v1-draft (잠정 기준표, 2026-09-15 — 팀 합의 후 4주차에 고정하고 이후 결과를 보고 바꾸지 않는다) [plan basis + text basis])
- 후보 출처: **manual** — 수동 입력 (사람이 준비한 파일 — 프로그램이 생성하지 않음); 개발 중 작성한 예제 (tests/fixtures/src/00b-baseline-fixed 와 동일 내용) — LLM 출력 아님

### 수정 대상

- `main.tf:14` `aws_security_group.baseline` — Security groups should not allow unrestricted ingress to SSH or RDP from any IP address. (HIGH)
- 수정 이유: SSH ingress 를 승인 출처(예제 값 10.0.0.0/8)로 제한

### 검증 상태

| 계층 | 내용 | 상태 | 요약 | 결과 출처 |
|---|---|---|---|---|
| V1 | 대상 finding 제거 (Trivy 재스캔) | ✅ 통과 | AVD-AWS-0107 이 재스캔에서 사라짐 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V2 | 새 finding 발생 여부 (Trivy 전후 비교) | ✅ 통과 | 새 finding 없음 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V3 | terraform validate | ✅ 통과 | validate 통과 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V4 | terraform plan | ✅ 통과 | plan 생성 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V5 | plan diff within policy | ✅ 통과 | changes within policy: changed=['aws_security_group.baseline'] added=[] removed=[] | local:v5_plan_diff |
| V6 | intent oracle | ✅ 통과 | PASS: all guarded services within approved sources and all required access preserved | local:v6_intent_oracle |

### 변경 내용

```diff
--- a/scenarios/dev/case00-baseline/main.tf
+++ b/scenarios/dev/case00-baseline/main.tf
@@ -2,15 +2,16 @@
   region = "ap-northeast-2"
 }
 
+# 00-baseline 의 정상 수정본: SSH 를 승인 출처(테스트 intent 기준 10.0.0.0/8)로만 허용
 resource "aws_security_group" "baseline" {
   name        = "baseline-sg"
-  description = "Baseline: SSH open to the world"
+  description = "Baseline fixed: SSH only from approved source"
 
   ingress {
     description = "SSH"
     from_port   = 22
     to_port     = 22
     protocol    = "tcp"
-    cidr_blocks = ["0.0.0.0/0"]
+    cidr_blocks = ["10.0.0.0/8"]
   }
 }
```

### 승인 전 확인 (사람)

- [ ] diff 가 대상 finding(AVD-AWS-0107 @ aws_security_group.baseline)만 다루는지 확인
- [ ] 승인 출처(허용 CIDR 등)가 팀이 정한 값과 일치하는지 확인 (코드가 추측한 값이 아님)
- [ ] 검증 표에 '검증 대기'·'판정 불가'·'실패' 가 없는지 확인 — 있으면 A 의 결과를 받아 다시 review 실행
- [ ] 이 후보를 반영할지 결정 — 반영하더라도 terraform apply 는 사람이 실행하고, 배포 후 V7/V8 을 기록

_run: 20260915-063845-106eac · 상태: REVIEW_REQUIRED_
