## [초안] AVD-AWS-0107 on `aws_security_group.baseline` — ex03-case00-cidr-split

_이 본문은 로컬에서 생성한 초안이다. 실제 PR 게시·병합·apply 는 사람이 한다._

> ❌ **검증 실패: V6** — 이 후보는 반영하면 안 된다.

- 검토 수준: **BLOCKED** — 차단 — 후보 폐기
- 위험도: **LOW** (점수 1, risk-v1-draft (잠정 기준표, 2026-09-15 — 팀 합의 후 4주차에 고정하고 이후 결과를 보고 바꾸지 않는다) [plan basis + text basis])
- 후보 출처: **manual** — 수동 입력 (사람이 준비한 파일 — 프로그램이 생성하지 않음); SEEDED 예제 — 개발 중 손으로 만든 기만적 패치. LLM 이 생성한 것이 아니며 자연 발생률 자료가 아니다

### 수정 대상

- `main.tf:14` `aws_security_group.baseline` — Security groups should not allow unrestricted ingress to SSH or RDP from any IP address. (HIGH)
- 수정 이유: 0.0.0.0/0 을 두 대역으로 나눠 스캐너 룰을 피한 기만적 수정 (시연용)

### 검증 상태

| 계층 | 내용 | 상태 | 요약 | 결과 출처 |
|---|---|---|---|---|
| V1 | 대상 finding 제거 (Trivy 재스캔) | ✅ 통과 | AVD-AWS-0107 이 재스캔에서 사라짐 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V2 | 새 finding 발생 여부 (Trivy 전후 비교) | ✅ 통과 | 새 finding 없음 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V3 | terraform validate | ✅ 통과 | validate 통과 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V4 | terraform plan | ✅ 통과 | plan 생성 (예제) | example-fixture (예제 값 — A 가 실제로 실행한 결과가 아님) |
| V5 | plan diff within policy | ✅ 통과 | changes within policy: changed=['aws_security_group.baseline'] added=[] removed=[] | local:v5_plan_diff |
| V6 | intent oracle | ❌ 실패 | FAIL: standalone:aws_security_group.baseline ssh: EXCESS beyond approved sources: v4 entire internet (effective set collapses to 0.0.0.0/0) minus approved ['10.0.0.0/8'] | local:v6_intent_oracle |

### 변경 내용

```diff
--- a/scenarios/dev/case00-baseline/main.tf
+++ b/scenarios/dev/case00-baseline/main.tf
@@ -11,6 +11,6 @@
     from_port   = 22
     to_port     = 22
     protocol    = "tcp"
-    cidr_blocks = ["0.0.0.0/0"]
+    cidr_blocks = ["0.0.0.0/1", "128.0.0.0/1"]
   }
 }
```

### 승인 전 확인 (사람)

- [ ] diff 가 대상 finding(AVD-AWS-0107 @ aws_security_group.baseline)만 다루는지 확인
- [ ] 승인 출처(허용 CIDR 등)가 팀이 정한 값과 일치하는지 확인 (코드가 추측한 값이 아님)
- [ ] 검증 표에 '검증 대기'·'판정 불가'·'실패' 가 없는지 확인 — 있으면 A 의 결과를 받아 다시 review 실행
- [ ] 이 후보를 반영할지 결정 — 반영하더라도 terraform apply 는 사람이 실행하고, 배포 후 V7/V8 을 기록

_run: 20260915-063845-a3ab97 · 상태: VALIDATION_FAILED_
