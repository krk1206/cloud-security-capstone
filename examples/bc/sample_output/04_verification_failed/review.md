# 로컬 검토 리포트 — ex04-v1-fail (20260915-063845-1d04dc)

_이 문서는 입력(Trivy 결과·원본·수정 후보)과 확인된 검증 결과를 템플릿으로 정리한 것이다. 모델이 분석한 결과가 아니다._

> ❌ **검증 실패: V1** — 이 후보는 반영하면 안 된다.

- 상태: **VALIDATION_FAILED**  |  검토 수준: **BLOCKED** — 차단 — 후보 폐기
  - 검증 실패: FAIL at V1(AVD-AWS-0107 이 재스캔에서 여전히 보고됨 (예제))

## 1. 수정 대상과 이유

- 대상 finding: `AVD-AWS-0107` (HIGH) — Security groups should not allow unrestricted ingress to SSH or RDP from any IP address.
- 위치: `main.tf:11` 리소스 `aws_security_group.vulnerable_ssh`
- Trivy 메시지: Security group rule allows unrestricted ingress from any IP address.
- Trivy 권고: Set a more restrictive CIDR range
- 같은 디렉터리의 다른 finding (이번 대상 아님): `AVD-AWS-0104`@aws_security_group.vulnerable_ssh:19
- 수정 이유(후보 작성자 기재): Restrict SSH ingress to the approved admin source 203.0.113.0/24 from the intent.
- 후보 작성자의 가정: approved source taken from intent

## 2. 변경 요약과 diff 위치

- 변경 파일: `main.tf`
- diff: `candidate.diff`  (원본 사본 `original/`, 후보 `candidate/`)
- 리소스 블록 변경(텍스트 근거): 변경 {'aws_security_group.vulnerable_ssh': ['ingress', 'cidr_blocks']} / 추가 [] / 삭제 의심 [] / 타입 변경 [] / 리소스 밖 블록 []

## 3. 후보 출처

- origin: **mock** — mock fixture (사람이 미리 작성한 고정 응답 — LLM 출력 아님)
- generator: `mock:sg_baseline_ok`  |  후보 ID: `cand-9a226c85`
- 출처 설명(사람 기재): fixture note: SEEDED mock response (not produced by an LLM). Correct fix for tests/fixtures/intents/sg-baseline.test.json

## 4. 검증별 상태

| 계층 | 내용 | 상태 | 요약 | 결과 출처 |
|---|---|---|---|---|
| V1 | 대상 finding 제거 (Trivy 재스캔) | ❌ 실패 | AVD-AWS-0107 이 재스캔에서 여전히 보고됨 (예제) | example-fixture (예제 값) |
| V2 | 새 finding 발생 여부 (Trivy 전후 비교) | ⏳ 검증 대기 | 검증 대기 — A 의 Trivy 전후 비교 결과 없음 | - |
| V3 | terraform validate | ✅ 통과 | validate 통과 (예제) | example-fixture (예제 값) |
| V4 | terraform plan | ⏳ 검증 대기 | 검증 대기 — A 의 terraform plan 결과 없음 | - |
| V5 | plan 구조 비교 (허용 범위) | ⏳ 검증 대기 | 검증 대기 — 원본/후보 plan JSON 없음 | - |
| V6 | Intent Oracle (실효 허용 집합) | ⏳ 검증 대기 | 검증 대기 — 후보 plan JSON 또는 intent 없음 | - |

- 종합: **FAIL** — FAIL at V1(AVD-AWS-0107 이 재스캔에서 여전히 보고됨 (예제))
- 검증 결과 파일에 candidate_sha256 이 없어 이 후보에 대한 결과인지 대조하지 못했다 (A 가 해시를 넣어 주면 자동 대조됨)

## 5. 위험도와 판정 근거 (잠정 기준표)

- 위험도: **LOW** (점수 0) — 기준표: risk-v1-draft (잠정 기준표, 2026-09-15 — 팀 합의 후 4주차에 고정하고 이후 결과를 보고 바꾸지 않는다) [text basis]
- 위험도는 '틀렸을 때 얼마나 터지나' 이며, 검증 통과 여부와 별개다. 위험도 LOW 가 자동 반영을 뜻하지 않는다.

| 항목 | 값 | 점수 | 근거 종류 | 비고 |
|---|---|---|---|---|
| non_network_resource_touched | [] | 0 | text |  |
| resources_touched | 1 | 0 | text |  |
| new_resource_blocks | [] | 0 | text |  |
| egress_changed | False | 0 | text |  |
| replace_forcing_attribute_changed | [] | 0 | text |  |
| non_rule_attribute_changed | False | 0 | text |  |
| non_resource_block_changed | [] | 0 | text |  |
| patch_lines | 2 | 0 | text |  |
| files_changed | 1 | 0 | text |  |
| undetermined | attachment_points (같은 인스턴스/ENI 에 붙은 다른 SG — plan 또는 AWS 조회 필요) | 0 | text | 미확정 — plan/AWS 정보 필요 |
| undetermined | plan_actions_delete_replace (실제 삭제/교체 여부 — terraform plan 필요; 텍스트에서는 블록 삭제·교체 유발 속성 변경을 '의심'으로만 표시) | 0 | text | 미확정 — plan/AWS 정보 필요 |
| undetermined | provider_config_equivalence (provider 설정 변경 여부는 파일 단위 블록 비교로만 확인) | 0 | text | 미확정 — plan/AWS 정보 필요 |

## 6. 사람이 확인할 항목

1. [ ] diff 가 대상 finding(AVD-AWS-0107 @ aws_security_group.vulnerable_ssh)만 다루는지 확인
2. [ ] 승인 출처(허용 CIDR 등)가 팀이 정한 값과 일치하는지 확인 (코드가 추측한 값이 아님)
3. [ ] 검증 표에 '검증 대기'·'판정 불가'·'실패' 가 없는지 확인 — 있으면 A 의 결과를 받아 다시 review 실행
4. [ ] 위험도 미확정 항목(같은 ENI 의 다른 SG, 실제 삭제/교체 여부)은 plan JSON 을 넘겨 다시 실행하거나 사람이 확인
5. [ ] 이 후보를 반영할지 결정 — 반영하더라도 terraform apply 는 사람이 실행하고, 배포 후 V7/V8 을 기록

## 7. 미확인 사항

- V2 새 finding 발생 여부 (Trivy 전후 비교): 검증 대기 — A 의 Trivy 전후 비교 결과 없음
- V4 terraform plan: 검증 대기 — A 의 terraform plan 결과 없음
- V5 plan 구조 비교 (허용 범위): 검증 대기 — 원본/후보 plan JSON 없음
- V6 Intent Oracle (실효 허용 집합): 검증 대기 — 후보 plan JSON 또는 intent 없음
- 위험도 미확정 항목: attachment_points (같은 인스턴스/ENI 에 붙은 다른 SG — plan 또는 AWS 조회 필요)
- 위험도 미확정 항목: plan_actions_delete_replace (실제 삭제/교체 여부 — terraform plan 필요; 텍스트에서는 블록 삭제·교체 유발 속성 변경을 '의심'으로만 표시)
- 위험도 미확정 항목: provider_config_equivalence (provider 설정 변경 여부는 파일 단위 블록 비교로만 확인)
- V7(실제 AWS 상태)·V8(통신 확인)은 배포 후에만 가능하며 이번 로컬 흐름에 없다

## 부록. 입력 정합 확인

- 방법: cause-line content match (Trivy CauseMetadata.Code.Lines ↔ 원본 파일 줄)  |  결과: 일치  |  확인한 원인 줄 수: 1
- 일부 파일의 수정 시각이 스캔 시각보다 늦다 (git checkout 만으로도 생기는 현상이라 참고용). 줄 내용 비교 결과를 우선한다
- 지목된 원인 줄이 원본에 그대로 있다. 다른 줄의 변경은 이 방법으로 잡지 못한다 (A 가 source_commit 을 넘기면 완전 확인 가능)
- 도구: iacpatch 0.2.0 (review flow)
