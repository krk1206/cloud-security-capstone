# 구조 설명 (코드를 공부하고 팀원에게 설명하기 위한 문서)

> 한 줄 요약: **Trivy 가 찾고, 생성기(LLM 또는 규칙)가 고치고, 결정론적 검증 계층이 "진짜 고쳤는지" 판정하고, 위험도 기준표가 "얼마나 자동으로 진행할지" 정한다.** 사람 승인·apply·push 는 코드가 자동으로 하지 않는다.

## 1. 전체 흐름 (배포 전 = `predeploy`)

```
infrastructure/sg-baseline/*.tf  (원본, 절대 수정하지 않음)
        │
        ▼
 [1] Trivy 스캔 (trivy config --include-non-failures)  ──▶ trivy_before.json
        │  대상 finding 선택: AVD-AWS-0107 (SSH/RDP 0.0.0.0/0)
        ▼
 [2] Intent 로딩  policy/intent/<scenario>.json  (사람이 쓴 승인 출처)
        │  플레이스홀더/draft/인터넷 전체 승인 → INSUFFICIENT_INFO 로 종료 (생성기 호출 안 함)
        ▼
 [3] 원본 plan   (복사본에서 init/validate/plan/show -json)  ──▶ plan_baseline.json
        ▼
 [4] Evidence Bundle = finding + *.tf 내용 + intent + 정책 제약 + 도구 버전
        ▼
 [5] 생성기 ──▶ PatchCandidate (파일 전체 내용, 원본과 분리 저장: candidates/NN/files/)
        │      llm: mock | anthropic | openai | openai_compatible     rule_based: 리터럴 치환
        │      응답 잘림/비JSON/스키마 위반 → GENERATION_FAILED (패치 없음)
        ▼
 [6] Policy Validator  경로·보호 파일·금지 토큰·provider 블록 불변·파일 수  → 위반 시 BLOCK
        ▼
 [7] 검증 계층 (전부 결정론적, LLM 없음)
        V1 대상 finding 제거 (재스캔)      V2 finding 집합 비교 (새 CRITICAL/HIGH → FAIL, 그 외 WARN)
        V3 terraform validate               V4 terraform plan
        V5 plan 구조 비교: 삭제/교체/허용 밖 타입·속성/개수/provider 변경 → FAIL
        V6 Intent Oracle: 실효 허용 집합 계산 (아래 3절)
        → Validity = PASS / FAIL / INCOMPLETE(UNKNOWN·SKIPPED·ERROR 포함)
        │  FAIL 이고 시도 횟수 남으면: 실패 메시지를 feedback 으로 [5] 재시도 (Observe→Reason→Act→Verify)
        ▼
 [8] Risk Rubric (policy/risk_rubric.json) → 위험도 LOW/MEDIUM/HIGH → 자율성 상한 HIGH/MEDIUM/LOW
        │  LLM 이 제안한 등급은 낮추는 방향으로만 반영
        ▼
 [9] Gate
        정책 위반 → BLOCK      검증 FAIL → BLOCK (위험도 무관)      검증 INCOMPLETE → HOLD_FOR_HUMAN
        검증 PASS: 자율성 HIGH → CREATE_PR_AUTO / MEDIUM → CREATE_PR_APPROVAL / LOW → REPORT_ONLY
        ▼
 [10] pr_body.md + candidate.diff + run.json (data/runs/<id>/)
        `iacpatch pr --run <id>` 는 명령만 출력. `--execute` 를 붙여야 브랜치 push + PR 생성. 병합·apply 는 항상 사람.
```

배포 후 (`postdeploy`, 사람이 apply 한 다음):

```
 V7  aws ec2 describe-security-groups (+ describe-network-interfaces 로 같은 ENI 의 SG 합산,
     get-managed-prefix-list-entries 로 prefix list 전개) → V6 와 같은 오라클 코드로 판정
 V8  허용 출처에서 통신 성공 + 승인 밖 출처(vantage)에서 통신 실패 확인. 승인 밖 vantage 가 없으면 UNKNOWN
 복구(recover): 원본 파일 복원 → plan → apply(승인) → plan 재실행 '변경 없음' + describe 기록 → RECOVERED
```

## 2. 두 축을 섞지 않는다

| 축 | 코드 | 묻는 것 | 결과 |
|---|---|---|---|
| 검증 (Validity) | `verify/` | 이 패치가 진짜 고쳤나 | PASS / FAIL / INCOMPLETE |
| 위험도 (Risk) | `policy/risk.py` | 틀렸을 때 얼마나 터지나 | LOW / MEDIUM / HIGH → 자율성 상한 |

`policy/gate.py` 가 두 결과를 받아 동작을 정한다. **검증이 FAIL 이면 위험도가 LOW 여도 BLOCK** 이다 (`test_policy_risk_gate.py::test_verification_fail_blocks_even_low_risk`).

## 3. V6 Intent Oracle 이 하는 일 (핵심)

입력은 **plan JSON + 소스 HCL + Intent** 이고 Trivy 결과는 입력이 아니다.

1. `verify/plan_model.py` — plan JSON 을 `SGWorld` 로 정규화한다.
   - `aws_security_group` inline 규칙, `aws_vpc_security_group_ingress_rule`, `aws_security_group_rule` 을 모두 규칙(Rule)으로 모은다.
   - 규칙의 출처(Source)는 종류가 다르다: `cidr4`, `cidr6`, `prefix_list`(전개 가능하면 CIDR 목록 포함), `sg`(참조 SG), `self`, `unknown`.
   - **참조 SG 의 인바운드 규칙을 상속하지 않는다.** "bastion SG 가 붙은 ENI 에서 오는 트래픽" 이라는 별도 출처일 뿐이다.
   - prefix list 는 **같은 plan 에 선언된 것만** 전개한다. 외부 `pl-…` 은 V7 이 AWS 에서 전개한다. 못 하면 `unknown`.
   - plan 시점 미확정 값(`after_unknown`)은 참조(`configuration.expressions.*.references`)로 **모호하지 않을 때만** 채우고, 아니면 `unknown`.
   - 부착 지점(`aws_instance.vpc_security_group_ids` 등)을 찾아 같은 ENI 에 붙는 SG 목록을 만든다. 참조와 리터럴이 섞인 목록은 plan 에 리터럴이 안 보이므로 HCL 에서 원소를 센다.
2. `verify/sg_oracle.py` — 대상 SG 마다 부착 범위(scope)를 정하고, 범위 안 SG 들의 규칙을 합산한다.
   - 보호 서비스(예: ingress tcp 22)마다: 방향·프로토콜·포트 범위가 겹치는 규칙의 출처를 모아 IPv4/IPv6 **집합**(`verify/netset.py`, `ipaddress.collapse_addresses`)을 만든다.
   - `EXCESS = 실효 집합 − 승인 집합`. 비어 있지 않으면 FAIL. 참조 SG 도 승인 목록에 없으면 EXCESS.
   - `required_access` 가 실효 집합에 완전히 포함되지 않으면 MISSING → FAIL (필요한 접근을 끊은 패치).
   - `unknown` 출처가 있고 EXCESS/MISSING 이 없으면 UNKNOWN (자동 승인 금지).
   - 서로 다른 ENI 의 규칙은 섞지 않는다 (`12-two-enis`). 부착 지점이 없으면 SG 단독으로 평가하고 caveat 를 남긴다.
3. 이 계층이 증명하는 것은 **SG 규칙상 허용 집합**이다. NACL·라우팅·공인 IP·호스트 방화벽·서비스 리스닝은 보지 않으므로 "실제 인터넷에서 접속 가능하다/불가능하다" 의 증명이 아니다. 그 부분은 V8 이 (제한적으로) 본다.

## 4. 파일 지도

```
src/iacpatch/
  cli.py            명령: selfcheck / scan / predeploy / oracle / pr / postdeploy / recover
  config.py         설정 (환경변수 > iacpatch.config.json > 기본값; 비밀값은 환경변수만)
  models.py         공용 데이터 구조 (Finding, EvidenceBundle, PatchCandidate, LayerResult, ...)
  evidence.py       Evidence Bundle 생성
  intent.py         Intent Spec 로딩/검증 (플레이스홀더, draft, 인터넷 전체 승인 거부)
  pipeline.py       predeploy 오케스트레이션 (일반 Python, 프레임워크 없음)
  postdeploy.py     V7 / V8 / 복구
  report.py         PR 본문·콘솔 요약
  runrecord.py      실행 기록 (data/runs/<id>/)
  tools/            trivy.py, terraform.py, awscli.py, github.py, runner.py
  generator/        base.py(응답 계약/파싱), llm_providers.py(mock/anthropic/openai/compatible), llm_generator.py, rule_based.py, prompts/sg_v1.md
  verify/           netset.py, sgmodel.py, plan_model.py, sg_oracle.py, v6.py, layers.py(V1~V5), combine.py
  policy/           validator.py, risk.py, gate.py
policy/             patch_policy.json, risk_rubric.json, cis_mapping.json, intent/*.json
scenarios/          dev/ (개발용) · eval/ (평가용, 개발 중 맞춰 고치지 않음)
tests/unit/         unittest (외부 의존성 없음). test_pipeline_integration.py 만 terraform/trivy 필요
tests/fixtures/     plans/ (실제 plan JSON), trivy/ (실제 Trivy JSON), src/ (케이스 HCL), mock_llm/ (seeded 응답), intents/
```

## 5. 팀원에게 설명할 때 쓰는 문장

- "AI 는 후보만 만든다. 검증·위험도·자동화 권한은 전부 결정론적 코드가 정하고, AI 는 등급을 낮추는 제안만 할 수 있다."
- "스캐너를 통과했다고 성공이 아니다. `sg_baseline_cidr_split` fixture 를 돌리면 V1~V5 가 전부 PASS 인데 V6 만 FAIL 이고 게이트는 BLOCK 이다."
- "모르는 건 모른다고 한다. 외부 prefix list 나 plan 시점 미확정 값이 있으면 UNKNOWN → HOLD_FOR_HUMAN 이지 PASS 가 아니다."
- "원본은 절대 안 건드린다. 후보는 `data/runs/<id>/candidates/NN/files/` 에만 있고, PR 도 `--execute` 를 붙여야 만든다. apply 는 사람이 한다."
