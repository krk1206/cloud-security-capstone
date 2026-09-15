## [초안] AVD-AWS-0107 on `aws_security_group.vulnerable_ssh` — ex01-manual-pending

_이 본문은 로컬에서 생성한 초안이다. 실제 PR 게시·병합·apply 는 사람이 한다._

> ⏳ **검증 대기: V1, V2, V3, V4, V5, V6** — 아직 검증되지 않은 계층이 있다. 이 리포트가 만들어졌다는 것은 패치가 검증됐다는 뜻이 **아니다**.

- 검토 수준: **PENDING** — 검증 대기 — 검토 수준을 아직 정할 수 없음
- 위험도: **LOW** (점수 0, risk-v1-draft (잠정 기준표, 2026-09-15 — 팀 합의 후 4주차에 고정하고 이후 결과를 보고 바꾸지 않는다) [text basis])
- 후보 출처: **manual** — 수동 입력 (사람이 준비한 파일 — 프로그램이 생성하지 않음); 개발 중 작성한 예제 (Claude Cowork 세션에서 사람 검토용으로 만든 것 — LLM 자동 생성 결과가 아니며 성능 실험 자료로 쓰지 않는다)

### 수정 대상

- `main.tf:11` `aws_security_group.vulnerable_ssh` — Security groups should not allow unrestricted ingress to SSH or RDP from any IP address. (HIGH)
- 수정 이유: SSH(22) ingress 를 승인 출처(예제 값 203.0.113.0/24)로만 제한. egress 는 그대로 둠.

### 검증 상태

| 계층 | 내용 | 상태 | 요약 | 결과 출처 |
|---|---|---|---|---|
| V1 | 대상 finding 제거 (Trivy 재스캔) | ⏳ 검증 대기 | 검증 대기 — A 의 Trivy 재스캔 결과 없음 | - |
| V2 | 새 finding 발생 여부 (Trivy 전후 비교) | ⏳ 검증 대기 | 검증 대기 — A 의 Trivy 전후 비교 결과 없음 | - |
| V3 | terraform validate | ⏳ 검증 대기 | 검증 대기 — A 의 terraform validate 결과 없음 | - |
| V4 | terraform plan | ⏳ 검증 대기 | 검증 대기 — A 의 terraform plan 결과 없음 | - |
| V5 | plan 구조 비교 (허용 범위) | ⏳ 검증 대기 | 검증 대기 — 원본/후보 plan JSON 없음 | - |
| V6 | Intent Oracle (실효 허용 집합) | ⏳ 검증 대기 | 검증 대기 — 후보 plan JSON 또는 intent 없음 | - |

### 변경 내용

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

### 승인 전 확인 (사람)

- [ ] diff 가 대상 finding(AVD-AWS-0107 @ aws_security_group.vulnerable_ssh)만 다루는지 확인
- [ ] 승인 출처(허용 CIDR 등)가 팀이 정한 값과 일치하는지 확인 (코드가 추측한 값이 아님)
- [ ] 검증 표에 '검증 대기'·'판정 불가'·'실패' 가 없는지 확인 — 있으면 A 의 결과를 받아 다시 review 실행
- [ ] 위험도 미확정 항목(같은 ENI 의 다른 SG, 실제 삭제/교체 여부)은 plan JSON 을 넘겨 다시 실행하거나 사람이 확인
- [ ] 이 후보를 반영할지 결정 — 반영하더라도 terraform apply 는 사람이 실행하고, 배포 후 V7/V8 을 기록

_run: 20260915-063845-251317 · 상태: REVIEW_REQUIRED_
