## iacpatch 패치 후보 — `matrix-sg_baseline_ok`

- run: `20260913-075403-d907cc`  |  후보: `cand-5ef63a64`  |  생성기: `mock:mock:mock-fixture` (origin=`mock`)
- 프롬프트 버전: `sg_v1`  |  모델: `mock-fixture`  |  시도: 1
- 도구: trivy 0.74.0, terraform opentofu 1.10.6, iacpatch 0.1.0

### 게이트 결정: **CREATE_PR_AUTO**

- 검증(Validity): **PASS** — all required layers passed
- 정책(Policy): **OK**
- 위험도(Risk): **LOW** (score 0) → 자율성 상한 **HIGH**
- 최종 자율성: **HIGH**
  - risk LOW (score 0) → autonomy cap HIGH

> 검증 축과 위험도 축은 별개다. 검증이 FAIL/INCOMPLETE 면 위험도와 무관하게 자동 승인되지 않는다.
> V6 는 SG 규칙상 허용 집합만 증명한다. 실제 인터넷 도달 가능성은 배포 후 V7/V8 로 확인한다 (그마저도 제한적).

### 검증 계층

| 계층 | 내용 | 판정 | 요약 |
|---|---|---|---|
| V1 | target finding removed | ✅ PASS | AVD-AWS-0107 no longer reported on aws_security_group.vulnerable_ssh |
| V2 | new findings introduced? | ✅ PASS | no new findings (resolved 1, unchanged 1) |
| V3 | terraform validate | ✅ PASS | valid (syntax + schema/reference consistency) |
| V4 | terraform plan | ✅ PASS | plan generated (offline mode: no state, every resource appears as create — V5 uses structural diff) |
| V5 | plan diff within policy | ✅ PASS | changes within policy: changed=['aws_security_group.vulnerable_ssh'] added=[] removed=[] |
| V6 | intent oracle | ✅ PASS | PASS: all guarded services within approved sources and all required access preserved |

<details><summary>V6 Intent Oracle 상세</summary>

- 대상 `aws_security_group.vulnerable_ssh` → PASS
  - 범위 `standalone:aws_security_group.vulnerable_ssh` (standalone; SGs: aws_security_group.vulnerable_ssh) → PASS
    - ssh: PASS | 실효 v4 ['203.0.113.0/24'] v6 [] sg [] | 승인 v4 ['203.0.113.0/24'] v6 []
    - rdp: PASS | 실효 v4 [] v6 [] sg [] | 승인 v4 [] v6 []
    - required admin-ssh (203.0.113.0/24 → ingress/tcp/22-22): PASS — required source is fully covered by declared rules
    - caveat: no attachment point found in plan; evaluated the security group alone. Other security groups attached to the same ENI at runtime are not visible here (V7 checks that).

</details>

### Intent (사람이 정의한 승인 출처)

- intent `sg-baseline-test` (v1) — 대상 ['aws_security_group.vulnerable_ssh']
- ssh: ingress/tcp/22-22 ← v4 ['203.0.113.0/24'] v6 [] sg [] pl []
- rdp: ingress/tcp/3389-3389 ← v4 [] v6 [] sg [] pl []
- required: admin-ssh 203.0.113.0/24 → tcp/22

### 생성기 설명 (검증되지 않은 주장 — 참고용)

Restrict SSH ingress to the approved admin source 203.0.113.0/24 from the intent.

가정: approved source taken from intent

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
```

<details><summary>Risk Rubric 산출 근거</summary>

rubric: risk-v1 (2026-09-13, 4주차 고정 예정 — 이후 결과를 보고 바꾸지 않는다)

| 요인 | 값 | 점수 | 비고 |
|---|---|---|---|
| non_network_resource_touched | [] | 0 |  |
| resources_touched | 1 | 0 |  |
| new_resources_created | 0 | 0 |  |
| attachment_points | 0 | 0 | no attachment in plan (standalone SG) |
| attachment_has_external_or_unknown_sg | False | 0 |  |
| egress_changed | False | 0 |  |
| non_rule_attribute_changed | False | 0 |  |
| oracle_partial_rules_or_caveats | False | 0 |  |
| patch_lines | 2 | 0 |  |
| files_changed | 1 | 0 |  |

</details>

---
승인 체크리스트 (사람): ① Intent 의 승인 출처가 실제 업무 요구와 맞는가 ② diff 가 대상 finding 만 다루는가 ③ 검증 표에 FAIL/UNKNOWN 이 없는가 ④ 병합 후 apply 는 사람이 실행하고, V7/V8 결과를 이 PR 에 댓글로 남긴다.
