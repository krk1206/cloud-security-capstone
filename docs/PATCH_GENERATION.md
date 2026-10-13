# 보안 패치는 어떻게 만들어지나 — "보안패치 어떻게 구현?" 에 대한 답 (2026-09-22)

지도교수 9/22 메모: "보안패치 어떻게 구현?" 아래는 이 저장소에서 **패치 후보가 실제로 만들어지는 경로 세 가지**와, 그 후보가 어디까지 신뢰되는지다. 한 줄 요약: **패치는 "생성기" 가 만들고, 생성기가 누구든(규칙·사람·AI) 같은 입력을 받고 같은 검증(V1~V6)을 통과해야 PR 이 된다. 생성기의 출력은 신뢰 대상이 아니라 검증 대상이다.**

## 1. 입력은 항상 같다 — Evidence Bundle

생성기가 받는 것 (`src/iacpatch/evidence.py`, `cc_prompt.py` 도 같은 정보만 프롬프트에 넣는다):

| 항목 | 어디서 | 예 |
|---|---|---|
| Trivy finding | `trivy config --format json` 원문에서 룰 ID·리소스·파일·줄 (`review/inputs.py list_findings`) | AVD-AWS-0107, `aws_security_group.baseline`, main.tf 12~18줄 |
| 대상 파일 전체 | 시나리오 디렉터리의 `.tf` | main.tf 원문 |
| 의도(intent) | `policy/intent/*.json` — 승인 출처(SG) / 승인 권한·필수 권한(IAM). **실행 전에 고정** (D-2, D-7) | SSH 22 ← 10.0.0.0/8 / `s3:GetObject`,`s3:ListBucket` on `report-archive` |

주지 **않는** 것: 우리 검증 방식(V6 오라클의 존재·판정 논리), 기대 라벨, 다른 후보. 규칙 기반과 AI 가 같은 정보로 경쟁해야 E1 비교가 공정하다.

## 2. 생성 경로 세 가지

### 2.1 규칙 기반 생성기 (baseline) — `src/iacpatch/generator/rule_based.py`

- 일부러 단순하다. Trivy 가 지목한 줄이 속한 블록에서 **리터럴** 값만 승인값으로 치환한다.
  - SG: `cidr_blocks = ["0.0.0.0/0"]` → `["10.0.0.0/8"]` (ipv6 도 같은 방식, `aws_vpc_security_group_ingress_rule` 의 `cidr_ipv4` 는 승인 출처가 1개일 때만)
  - IAM: 지목된 `aws_iam_policy`/`aws_iam_role_policy` 의 Statement 가 **하나**이고 Action/Resource 가 리터럴이며 승인 권한이 **하나**일 때 통째로 치환
- 못 하는 것은 **NOT_SUPPORTED 로 기록**하고 숨기지 않는다: 변수·locals·`join()` 경유, `dynamic` 블록, prefix list, 참조 SG, 모듈, Statement 2개 이상, NotAction/Condition/Deny, `data.aws_iam_policy_document`, 신뢰 정책, 규칙 삭제가 필요한 경우.
- 실측: SG A 케이스 9개 중 후보 생성 4 (00, 05, 07, 08 — 나머지는 NOT_SUPPORTED(변수·문자열 조합·dynamic) 또는 finding 없음(01, 06)), IAM probe 5개는 `experiments/candidate-sets/eval-iam-rule/results.md` 의 E1 표. 이 한계가 연구 질문 3("변형에 대한 대응력") 의 비교 기준이다.

### 2.2 Claude Code (AI, 사람이 세션을 연다) — `scripts/cc_prompt.py` → 사람 → `scripts/cc_add.py`

- 유료 API 를 쓰지 않는다 (D-5). 프로그램이 모델을 호출하지 않는다 (D-11).
- 흐름: `cc_prompt.py <케이스>` 가 고정 프롬프트(`experiments/candidate-sets/eval-claude-code/prompt.md` v1)를 만든다 → 사람이 **새 Claude Code 세션**에 붙여넣는다 → 응답의 코드 블록을 `candidates/cc-<케이스>-r<n>.tf` 로 저장 → `cc_add.py` 가 sha256·라벨(`expected`, 실행 전에 적음)·메모와 함께 manifest 에 등록.
- 제약: `CLAUDE.md` + `.claude/settings.json` 이 그 세션에서 apply/aws/push/자격증명을 막는다. `scripts/cc_batch.sh` 는 같은 프롬프트를 반복 수집하는 보조 스크립트(사람이 시작, 도구 금지 플래그) — 아직 실행 확인 전(UNVERIFIED).
- 현재 후보 수: **0** (수집은 이번 주 B 의 과제). 개발 중 내가 쓴 예제는 `manual:` 로 표기하고 LLM 결과로 세지 않는다.

### 2.3 seeded / manual (개발·평가용 재료) — `experiments/candidate-sets/eval-seeded-*/candidates/*.tf`

- 알려진 우회 패턴(CIDR 분할, prefix list, `s3:*`→`*`, Resource `*` 유지, 필수 권한 삭제 …)을 **사람/AI 세션이 손으로 작성**한 것. LLM 이 자연히 내는 비율을 재는 재료가 아니라, **검증 계층이 그 패턴을 잡는지** 재는 재료다 (E2).
- manifest 의 `_authorship_note` 에 작성 주체를 적는다. 사람이 직접 만든 ground truth(`ground-truth/`)는 이번 주 A 의 과제로 따로 분리한다 (D-10).

## 3. 생성 뒤에 일어나는 일 (생성기가 누구든 같다)

```
후보 .tf ──▶ 정책 검증 (허용 파일·리소스 타입·삭제 금지) ──▶ V1~V6 ──▶ 위험도 기준표 ──▶ 검토 수준
                 │ 위반 → POLICY_BLOCKED                         │ FAIL → BLOCKED      HIGH → REPORT_ONLY
                 ▼                                              ▼                    MEDIUM → FULL_REVIEW (승인 필수)
             기록(data/reviews/<id>/)                           UNKNOWN → PENDING     LOW → LIGHT_REVIEW
                                                                                          ▼
                                                                          PR 초안 (`iacpatch pr --review`) → 사람 승인 → 사람이 apply → V7/V8
```

- 후보는 **파일 전체**로 받는다 (diff 가 아니라). 그래야 sha256 으로 고정되고, 나중에 같은 파일을 다시 검증할 수 있다.
- 자동 재시도 루프(생성 → 정책/검증 실패 → 실패 내용을 feedback 으로 다시 생성, 최대 `max_attempts`)는 1주차 파이프라인(`src/iacpatch/pipeline.py run_predeploy`) 에 **코드로는 있다**. 그러나 실제 LLM 을 호출하지 않으므로(D-5) 규칙 기반·mock 에서만 도는 형태이고, **실험 결과에 쓰는 경로(`review`)에는 재시도가 없다.** Claude Code 는 사람이 세션을 열기 때문에 "다시 받기" 가 곧 새 반복(r2)이다. 운영계획서의 Observe→Reason→Act→Verify 루프는 이 저장소에서는 "사람 + 검증 표" 로 구현돼 있다 (docs/AI_CONSTRAINTS.md).
- 생성기 인터페이스는 하나다 (`generator/base.py` `PatchGenerator.generate(bundle, feedback=None, attempt=1) -> PatchCandidate{status, files, error, rationale}`). 규칙 기반·mock·(안 쓰는) LLM 어댑터가 같은 형태를 낸다. 새 생성기를 붙여도 검증·기록 코드는 안 바뀐다.

## 4. 교수·심사위원 예상 질문

1. **"AI 가 고치는 거냐?"** — 후보를 내는 건 규칙 기반 생성기 또는 Claude Code 세션(사람이 연다). 어느 쪽이든 후보는 검증 대상이지 신뢰 대상이 아니다. 자동 apply 는 없다.
2. **"규칙 몇 줄이면 되는 걸 왜 AI 로?"** — 그래서 규칙 기반이 baseline 이다. 변형(변수 경유, dynamic, 두 Statement) 에서 규칙 기반이 NOT_SUPPORTED 를 내는 비율 vs AI 가 후보를 내는 비율·그 후보의 검증 통과율을 비교한다 (E1). "AI 가 낫다" 는 가정하지 않는다.
3. **"AI 한테 무슨 정보를 주냐?"** — 1절 표. 검증 방식은 안 준다.
4. **"AI 출력이 위험하면?"** — 정책 검증(범위 밖 변경 차단) → V5(허용 안 된 변경) → V6(실효 상태) → 위험도(IAM 은 최소 MEDIUM = 승인 필수). 기록은 지우지 않는다.
5. **"패치가 기능을 깨면?"** — intent 의 필수 접근/권한이 사라지면 V6 가 FAIL (`breaks-required-*` 케이스). 배포 후 실제 기능은 V8 (미실행).

## 5. 팀이 채울 것

- [ ] B: Claude Code 후보 수집 (SG 00-baseline, IAM iam-00-literal-list × 3회부터), 라벨은 실행 전에.
- [ ] A: `ground-truth/` 3쌍 (사람이 직접 취약→정상).
- [ ] 발표에 "생성기 세 경로 + 같은 검증" 그림 한 장 (3절 그림을 그대로 써도 됨).
