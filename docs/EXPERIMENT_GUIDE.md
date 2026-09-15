# 실험 방법 안내 (쉬운 버전)

> 목적: 발표에 쓸 **숫자**를 만드는 절차. 전부 이 저장소의 명령으로 재현된다. 외부 LLM API·AWS 없이도 배포 전 실험(E1·E2)은 돌릴 수 있다.

## 0. 먼저 알아둘 것 — 숫자가 뜻하는 것

| 숫자 | 뜻 | 어디서 나오나 |
|---|---|---|
| 기만적 패치 탐지율 | "스캐너(V1)는 통과시켰는데 오라클(V6)이 잡은" 후보 비율 | `metrics` 의 `스캐너 통과 ∧ 오라클 실패` ÷ 기만적 후보 수 |
| 정상 수정 오탐률 | 정상 수정인데 V6 가 FAIL/UNKNOWN 을 낸 비율 | 라벨 `correct` 중 기대대로 판정되지 않은 것 |
| 필요 접근 보존 | 필요한 접근을 끊은 후보를 V6 가 MISSING 으로 잡은 비율 | 라벨 `breaks_required` |
| 오라클 유무 비교 (E2) | "V1 만으로 게이트를 열었으면 통과했을 건수" vs "V1+V6 통과 건수" | `metrics` 의 `오라클 유무 비교` 줄 |
| 생성기 비교 (E1) | 같은 케이스에서 규칙 기반 vs (사람이 받아온) LLM 후보가 각각 몇 건 후보를 만들고 몇 건이 기대대로 판정됐나 | `metrics` 의 `후보 출처별` 표 |
| 처리 시간 | 단계별 자동 처리 시간 (사람 대기 제외) | `data/runs/*/timings.json` (predeploy 경로), review 는 즉시 |

**숫자가 "우리 시스템의 성능" 이 되려면 후보가 실제 LLM(Claude Code) 출력이어야 한다.** mock·seeded·규칙 기반으로 낸 숫자는 "검증 계층이 정의된 케이스에서 어떻게 판정했는가" 이지 LLM 성능이 아니다. 표에 후보 출처가 항상 같이 찍히는 이유다.

## 1. 재료 준비 (한 번만)

1. **원본 + Trivy JSON** (A): `infrastructure/sg-baseline/` 처럼 결함이 있는 Terraform 과 그 스캔 결과. A 의 변형 9종은 이미 `scenarios/eval/a-probe/<case>/` 에 A 의 스캔(`results-verify`)과 함께 복사돼 있다 (`scenarios/eval/a-probe/README.md`). 정책이 `experiments/` 아래 수정을 막으므로 원본은 항상 `scenarios/` 나 `infrastructure/` 아래에 둔다.
2. **intent** (팀): 승인 CIDR·필수 접근을 적은 `policy/intent/<시나리오>.json`. 이게 없으면 V6 도 규칙 기반도 못 돈다.
3. **plan JSON** (A 또는 terraform 있는 사람 누구나): 원본 plan 1개 + 후보마다 plan 1개. 없으면 V5/V6 는 검증 대기로 남는다 → 숫자가 안 나온다. **plan 이 핵심 재료다.**
   ```bash
   scripts/make_plan.sh scenarios/eval/case00 plans/case00-baseline.json                       # 원본
   scripts/make_plan.sh scenarios/eval/case00 plans/cc-01.json candidates/cc-01.tf main.tf     # 후보
   ```
   오프라인 plan 이라 AWS 계정·요금이 없다 (`terraform init` 의 provider 다운로드만 네트워크). 옆에 `.meta.txt` 로 도구 버전·후보 sha256 이 남는다. 이 스크립트는 작성 세션에 terraform 이 없어 **실행 확인을 못 했다** — 첫 실행 때 오류 나면 `scripts/generate_fixtures.sh` 와 같은 명령이니 그 절차대로 손으로 해도 된다.
4. **검증 결과 (V1~V4)**: 두 방법 중 하나.
   - `--local-tools` (권장): 실행하는 컴퓨터에 trivy / terraform 이 있으면 검토 흐름이 V1~V4 를 그 자리에서 돌리고 plan JSON 까지 만든다 (`review/local_verify.py`, predeploy 와 같은 코드). 그러면 3번의 plan 도 자동으로 생겨 V5/V6 가 같이 계산된다. 도구가 없는 계층은 NOT_RUN. `terraform init` 이 provider 를 받아야 하므로 `TF_PLUGIN_CACHE_DIR` 을 잡아두면 후보마다 다시 받지 않는다.
   - 파일로 받기: A 가 다른 곳에서 돌린 결과를 `docs/IO_SPEC_A_B_C.md` 1-3 형식 JSON 으로 (`verification`).
5. **후보** (B): 아래 세 종류. 파일로 저장한다.
   - `claude-code`: 지도교수 지시대로 Claude Code 대화에서 "이 finding 을 고쳐줘" 하고 받은 파일 (프롬프트를 고정해 두고 케이스마다 N번 반복). **저장할 때 어느 대화에서 받았는지 note 에 적는다.** 프롬프트 원문은 세트 폴더에 `prompt.md` 로 같이 둔다 (규칙 기반과 같은 정보 — finding 위치 + intent 의 승인 CIDR — 를 주고, 그 이상은 주지 않는다. 그래야 E1 이 공정한 비교가 된다).
   - `rule_based`: `--candidate rule_based` 로 자동 (LLM 아님)
   - `seeded`: 우리가 손으로 만든 기만적 패치(CIDR 분할, prefix list, IPv6, 필요 접근 삭제 …). **탐지기 능력 측정용이지 자연 발생률이 아니다.**

## 2. 개발용과 평가용을 나눈다 (결과 보고 기준 바꾸기 금지)

- `scenarios/dev/` + `experiments/candidate-sets/example-dev/`: 코드를 고치면서 반복 실행하는 곳. 여기 숫자는 발표에 안 쓴다.
- `scenarios/eval/` + `experiments/candidate-sets/eval-*/`: **manifest 와 labels 를 먼저 쓰고 고정**한 뒤 한 번에 돌린다. 결과가 마음에 안 들어도 기준표(`policy/risk_rubric.json`)·정책·라벨을 고치지 않는다. 고쳐야 하면 새 세트 이름으로 다시 돌리고 둘 다 보고한다.

## 3. 실행 절차 (세트 하나)

```
experiments/candidate-sets/eval-sg-01/
  manifest.json        ← 어떤 원본·Trivy·intent·plan 을 쓰고, 후보가 뭐고, 기대 결과(expected)가 뭔지
  prompt.md            ← Claude Code 에 준 프롬프트 원문 (고정본)
  candidates/          ← 후보 파일들 (cc-01.tf, cc-02.tf, seeded-split.tf ...)
  plans/               ← make_plan.sh 로 만든 plan JSON (원본 1 + 후보마다 1) + .meta.txt
  verification/        ← A 가 준 V1~V4 결과 JSON (후보마다)
```

1. manifest 작성 (형식은 `experiments/candidate-sets/example-dev/manifest.json` 복사). 후보마다:
   - `expected`: 사람이 **후보 내용을 읽고** 적는다 — `correct`(승인 출처만 남김) / `deceptive`(스캐너만 피함) / `breaks_required`(필요 접근 삭제) / `unapproved`(승인 밖 출처) / `unknown`(판정 불가가 정답) / `invalid`(빈 파일 등) / `not_triggered`(스캐너가 안 잡아 시작 안 되는 게 정답, A 의 01·06) / `unsupported`(생성기가 지원 범위 밖이라 후보를 안 내는 게 정답, 규칙 기반의 변수·dynamic 케이스)
   - 후보마다 `tf_dir` / `trivy_json` / `intent` 를 따로 줄 수 있다 (케이스가 여러 개인 세트)
   - `source`: `claude-code` / `rule_based` / `seeded`
   - `candidate_plan`: 그 후보의 plan JSON (A 가 만든 것)
2. 실행:
   ```bash
   export PYTHONPATH=src
   python3 scripts/run_candidate_set.py experiments/candidate-sets/eval-sg-01/manifest.json --local-tools
   ```
   (`--local-tools` 또는 manifest 의 `"local_tools": true`. trivy/terraform 이 PATH 에 있거나 `TRIVY_BIN` / `TERRAFORM_BIN` 으로 지정)
   → 후보마다 `data/reviews/<id>/` 기록, 세트 폴더에 `labels.json` + `results.md`
3. `results.md` 를 읽는다. 위 0절 표의 숫자가 그대로 있다.

## 4. 두 실험을 분리한다

### E1. 생성 방식 비교 — 규칙 기반 vs LLM(Claude Code)

- 같은 케이스 세트(예: 00~08 변형 9종)에 대해 규칙 기반 후보와 Claude Code 후보를 각각 만든다. Claude Code 는 케이스마다 N=3~5 회.
- 보는 것: `후보 출처별` 표 — 후보를 **만들 수 있었나**(규칙 기반은 02/03/04 같은 변형에서 NOT_SUPPORTED 가 정상), 만든 후보가 **기대대로 판정됐나**(correct 인데 V6 FAIL 이면 LLM 이 틀린 것).
- 예상되는 정직한 결과: 단순 리터럴 케이스는 규칙 기반이 100% 안정, 변형 케이스는 규칙 기반이 못 만들고 LLM 은 만들지만 일부 틀림. 어느 쪽이든 결과다.

### E2. 오라클 유무 — 검증 효과

- 같은 후보들에 대해 "V1 만 보는 게이트" 와 "V1+V6 게이트" 가 각각 몇 건을 통과시키는지 센다 (`오라클 유무 비교` 줄).
- 기만적 후보(seeded + LLM 이 실제로 만든 기만적 후보)에서 두 게이트의 차이가 곧 **오라클이 막은 건수**다.
- LLM 후보 중 기만적인 것이 **0건이면 0건이라고 보고한다.** seeded 세트로 낸 탐지율은 "알려진 패턴 탐지 능력" 으로만 쓴다.

## 5. 보고할 때 같이 적을 것 (교수님이 물어볼 것)

- 후보 수와 출처 분포, 케이스 수, 반복 횟수, 프롬프트 버전(고정했나), 도구 버전(Trivy/Terraform), intent 의 승인 CIDR 이 누가 정한 값인지
- 라벨을 누가 언제 정했는지 (실행 전에 고정)
- 검증 대기(NOT_RUN)로 남은 건수 — 숫자에서 뺐는지 포함했는지
- 배포 후(V7/V8) 실측을 했는지 — 안 했으면 "배포 전 결과" 라고 명시
- 상용 도구와의 비교는 하지 않았다는 것 (같은 조건에서 돌려보지 않은 도구를 비교 대상으로 삼지 않는다)

## 6. 지금 당장 돌려볼 수 있는 것

```bash
python3 scripts/run_candidate_set.py experiments/candidate-sets/example-dev/manifest.json        # 예제 4건 (도구 없이, 형식 확인용)
python3 experiments/candidate-sets/a-probe-dev/check_a_results.py                                # A 의 9 케이스 결과 재현 확인
python3 scripts/run_candidate_set.py experiments/candidate-sets/eval-a-probe-rule/manifest.json  # E1 규칙 기반 축: A 의 9 케이스 × rule_based
python3 scripts/run_candidate_set.py experiments/candidate-sets/eval-seeded-sg/manifest.json     # E2 재료: 00-baseline × seeded 11건
python3 scripts/run_candidate_set.py experiments/candidate-sets/eval-claude-code/manifest.json   # E1 LLM 축 (후보 파일을 채워야 돈다)
```

| 세트 | 용도 | expected 고정 | 승인 출처 |
|---|---|---|---|
| `example-dev`, `a-probe-dev` | 개발용. 발표 수치 아님 | — | 팀 결정값(D-2)과 같은 값이지만 개발용 |
| `eval-a-probe-rule` | E1 규칙 기반 축 (A 의 9 케이스) | 2026-09-15 | 팀 결정값 (D-2) |
| `eval-seeded-sg` | E2 (오라클 유무) 재료. seeded 11건 — 탐지 능력 측정용, 자연 발생률 아님 | 2026-09-15 | 팀 결정값 (D-2) |
| `eval-claude-code` | E1 LLM 축. **비어 있음** — B 가 Claude Code 로 채운다 (`prompt.md`) | 항목 추가 시 | 팀 결정값 (D-2) |

실행 결과는 세트 폴더 `results.md`(최신) 와 `results-history/<시각>-<호스트>.md`(환경별 누적) 에 남는다. 2026-09-15 샌드박스 실행은 Trivy 만 있어 V1/V2 까지 실측이고 V3~V6 는 ERROR/NOT_RUN 이다 — **팀 WSL 에서 같은 명령을 돌린 이력이 붙어야 표가 완성된다.**
