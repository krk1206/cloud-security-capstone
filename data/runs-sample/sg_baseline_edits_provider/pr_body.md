## iacpatch 패치 후보 — `matrix-sg_baseline_edits_provider`

- run: `20260913-080003-df2b6b`  |  후보: `cand-49e211cb`  |  생성기: `mock:mock:mock-fixture` (origin=`mock`)
- 프롬프트 버전: `sg_v1`  |  모델: `mock-fixture`  |  시도: 1
- 도구: trivy 0.74.0, terraform opentofu 1.10.6, iacpatch 0.1.0

### 게이트 결정: **BLOCK**

- 검증(Validity): **INCOMPLETE** — verification not run: policy violation
- 정책(Policy): **VIOLATION** — file_protected:provider.tf: provider/backend/versions files may not be modified by a patch
  - policy violation: file_protected:provider.tf: provider/backend/versions files may not be modified by a patch

> 검증 축과 위험도 축은 별개다. 검증이 FAIL/INCOMPLETE 면 위험도와 무관하게 자동 승인되지 않는다.
> V6 는 SG 규칙상 허용 집합만 증명한다. 실제 인터넷 도달 가능성은 배포 후 V7/V8 로 확인한다 (그마저도 제한적).

### 검증 계층

| 계층 | 내용 | 판정 | 요약 |
|---|---|---|---|

### Intent (사람이 정의한 승인 출처)

- intent `sg-baseline-test` (v1) — 대상 ['aws_security_group.vulnerable_ssh']
- ssh: ingress/tcp/22-22 ← v4 ['203.0.113.0/24'] v6 [] sg [] pl []
- rdp: ingress/tcp/3389-3389 ← v4 [] v6 [] sg [] pl []
- required: admin-ssh 203.0.113.0/24 → tcp/22

### 생성기 설명 (검증되지 않은 주장 — 참고용)

also tidy provider

### 변경 내용 (diff)

```diff
--- a/infrastructure/sg-baseline/main.tf
+++ b/infrastructure/sg-baseline/main.tf
@@ -8,7 +8,7 @@
     from_port   = 22
     to_port     = 22
     protocol    = "tcp"
-    cidr_blocks = ["0.0.0.0/0"]
+    cidr_blocks = ["203.0.113.0/24"]
   }
 
   egress {

--- a/infrastructure/sg-baseline/provider.tf
+++ b/infrastructure/sg-baseline/provider.tf
@@ -10,7 +10,7 @@
 
 provider "aws" {
   region  = var.region
-  profile = "capstone"
+  profile = "attacker"
 
   default_tags {
     tags = {
```

---
승인 체크리스트 (사람): ① Intent 의 승인 출처가 실제 업무 요구와 맞는가 ② diff 가 대상 finding 만 다루는가 ③ 검증 표에 FAIL/UNKNOWN 이 없는가 ④ 병합 후 apply 는 사람이 실행하고, V7/V8 결과를 이 PR 에 댓글로 남긴다.
