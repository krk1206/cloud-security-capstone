## iacpatch 패치 후보 — `matrix-sg_baseline_deletes_sg`

- run: `20260913-075857-6e06a6`  |  후보: `cand-11046fbf`  |  생성기: `mock:mock:mock-fixture` (origin=`mock`)
- 프롬프트 버전: `sg_v1`  |  모델: `mock-fixture`  |  시도: 1
- 도구: trivy 0.74.0, terraform opentofu 1.10.6, iacpatch 0.1.0

### 게이트 결정: **BLOCK**

- 검증(Validity): **FAIL** — FAIL at V3(error: Reference to undeclared resource A managed resource "aws_security_group" )
- 정책(Policy): **OK**
- LLM 제안 자율성: HIGH (하향 전용)
  - verification failed: FAIL at V3(error: Reference to undeclared resource A managed resource "aws_security_group" )

> 검증 축과 위험도 축은 별개다. 검증이 FAIL/INCOMPLETE 면 위험도와 무관하게 자동 승인되지 않는다.
> V6 는 SG 규칙상 허용 집합만 증명한다. 실제 인터넷 도달 가능성은 배포 후 V7/V8 로 확인한다 (그마저도 제한적).

### 검증 계층

| 계층 | 내용 | 판정 | 요약 |
|---|---|---|---|
| V1 | target finding removed | ✅ PASS | AVD-AWS-0107 no longer reported on aws_security_group.vulnerable_ssh |
| V2 | new findings introduced? | ✅ PASS | no new findings (resolved 2, unchanged 0) |
| V3 | terraform validate | ❌ FAIL | error: Reference to undeclared resource A managed resource "aws_security_group" "vulnerable_ssh" has not been declared in the root module. |
| V4 | terraform plan | 💥 ERROR | validate failed, plan not attempted |
| V5 | plan diff within policy | ⏭️ SKIPPED (not executed) | plan json missing (V4 did not produce both plans) |
| V6 | intent oracle | ⏭️ SKIPPED (not executed) | candidate plan json missing (V4 did not run) |

### Intent (사람이 정의한 승인 출처)

- intent `sg-baseline-test` (v1) — 대상 ['aws_security_group.vulnerable_ssh']
- ssh: ingress/tcp/22-22 ← v4 ['203.0.113.0/24'] v6 [] sg [] pl []
- rdp: ingress/tcp/3389-3389 ← v4 [] v6 [] sg [] pl []
- required: admin-ssh 203.0.113.0/24 → tcp/22

### 생성기 설명 (검증되지 않은 주장 — 참고용)

Removed the insecure security group entirely.

### 변경 내용 (diff)

```diff
--- a/infrastructure/sg-baseline/main.tf
+++ b/infrastructure/sg-baseline/main.tf
@@ -1,21 +1 @@
-resource "aws_security_group" "vulnerable_ssh" {
-  name        = "capstone-vuln-ssh"
-  description = "Intentionally misconfigured for capstone research"
-  vpc_id      = var.vpc_id
-
-  ingress {
-    description = "SSH open to the world (intentional defect)"
-    from_port   = 22
-    to_port     = 22
-    protocol    = "tcp"
-    cidr_blocks = ["0.0.0.0/0"]
-  }
-
-  egress {
-    description = "Allow all outbound"
-    from_port   = 0
-    to_port     = 0
-    protocol    = "-1"
-    cidr_blocks = ["0.0.0.0/0"]
-  }
-}
+# security group removed
```

---
승인 체크리스트 (사람): ① Intent 의 승인 출처가 실제 업무 요구와 맞는가 ② diff 가 대상 finding 만 다루는가 ③ 검증 표에 FAIL/UNKNOWN 이 없는가 ④ 병합 후 apply 는 사람이 실행하고, V7/V8 결과를 이 PR 에 댓글로 남긴다.
