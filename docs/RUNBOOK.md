# 실행 방법 (Windows / WSL)

의존성: Python 3.10+ 표준 라이브러리만. 외부 도구는 Terraform(또는 OpenTofu), Trivy, (배포 후 단계만) AWS CLI.

## 0. 한눈에

| 하고 싶은 것 | 명령 | 필요한 것 |
|---|---|---|
| 도구 확인 | `python -m iacpatch selfcheck` | — |
| 단위 테스트 | `scripts/run_tests.sh` / `scripts\run_tests.bat` | Python (통합 테스트는 terraform+trivy 있으면 자동 포함) |
| 데모 (정상 패치) | `scripts/predeploy_demo.sh` / `scripts\predeploy_demo.bat` | terraform + trivy |
| 데모 (기만적 패치 차단) | `scripts/predeploy_demo.sh sg_baseline_cidr_split` | terraform + trivy |
| 실제 LLM 으로 실행 | 아래 3절 | + API 키(환경변수) |
| PR 만들기 | `python -m iacpatch pr --run <predeploy id>` 또는 `--review <review id>` (미리보기) → `--execute` | git 원격 권한, GITHUB_TOKEN(선택) |
| 배포 후 검증 | `python -m iacpatch postdeploy ...` (미리보기) → `--execute` | AWS CLI 프로필 |
| 복구 | `python -m iacpatch recover --run <id> --tf-dir infrastructure/sg-baseline` → `--execute` | AWS CLI 프로필 |

**자동으로 절대 하지 않는 것:** `terraform apply`, `git push`, PR 생성, PR 병합. 전부 `--execute` 를 붙인 사람의 명령으로만.

## 0-1. B·C 로컬 검토 흐름 (3~4주차) — 도구·API·AWS·네트워크 전부 불필요

A 가 넘긴 **Terraform 원본 + Trivy JSON** 만 있으면 된다. trivy/terraform 을 실행하지 않고 파일만 읽는다.

```bash
# WSL
export PYTHONPATH=$PWD/src
python3 -m iacpatch findings --trivy-json infrastructure/sg-baseline/baseline-scan.json           # finding 목록 보기
python3 -m iacpatch review --tf-dir infrastructure/sg-baseline --trivy-json infrastructure/sg-baseline/baseline-scan.json \
  --rule AVD-AWS-0107 --candidate manual:<내가 만든 main.tf 또는 폴더 또는 응답.json> --candidate-note "누가 어떻게 만들었는지" --scenario s1
#   → data/reviews/<id>/review.md, pr_body.md, state.json
python3 -m iacpatch review ... --verification <A 의 결과.json>            # A 결과가 오면 붙여서 다시 실행
python3 -m iacpatch review ... --baseline-plan a.json --candidate-plan b.json --intent policy/intent/sg-baseline.json   # plan 있으면 V5/V6 로컬 계산
python3 -m iacpatch metrics                                             # 기록 집계
```
```powershell
# Windows PowerShell
$env:PYTHONPATH = "$PWD\src"
python -m iacpatch review --tf-dir infrastructure/sg-baseline --trivy-json infrastructure/sg-baseline/baseline-scan.json --candidate mock:sg_baseline_ok --scenario s1
scripts\review_demo.bat manual      # 더블클릭도 됨 (manual | mock | split)
```

- 후보 지정: `mock:<tests/fixtures/mock_llm 의 이름>` 또는 `manual:<경로>` (.json = 응답 계약, .tf = 대상 파일 전체 대체, 폴더 = *.tf + candidate.json)
- 같은 룰의 finding 이 여러 개면 멈춘다 → `--resource aws_security_group.xxx` 또는 `--line N` 으로 지정
- 결과 읽는 법: `state.json.state` (REVIEW_REQUIRED 는 "검토 자료 준비됨" 이지 "검증 통과" 아님), `verification_status`, review.md 4절 표
- 예제와 재현 명령: `examples/bc/README.md`. 입출력 형식: `docs/IO_SPEC_A_B_C.md`

## 0-2. 검토 흐름에서 V1~V4 까지 로컬 실행 (`--local-tools`)

WSL 에 trivy 와 terraform 이 있으면 A 가 결과 파일을 따로 만들지 않아도 된다.

```bash
export PYTHONPATH=src
export TF_PLUGIN_CACHE_DIR=$HOME/.terraform.d/plugin-cache; mkdir -p "$TF_PLUGIN_CACHE_DIR"   # provider 를 후보마다 다시 받지 않게
python3 -m iacpatch review --tf-dir scenarios/eval/a-probe/00-baseline --trivy-json scenarios/eval/a-probe/00-baseline/trivy-scan.json \
  --candidate rule_based --intent experiments/candidate-sets/a-probe-dev/intents/00-baseline.json --scenario a00 --local-tools
```

- V1/V2: 원본·후보를 로컬 trivy 로 다시 스캔해 비교 (입력 스캔과 FAIL 키 집합이 다르면 리포트 '검증 메모' 에 표시)
- V3/V4: 오프라인 plan (AWS 접속 없음). 성공하면 `data/reviews/<id>/local_verify/plan_*.json` 이 생기고 V5/V6 도 같이 계산된다
- 도구가 없으면 그 계층은 NOT_RUN. `--verification` 파일을 주면 로컬 실행은 하지 않는다
- 세트 단위: `python3 scripts/run_candidate_set.py <manifest> --local-tools`

## 1. WSL (Ubuntu) — 권장

```bash
cd ~/cloud-security-capstone            # 저장소
scripts/setup_wsl.sh                    # 도구 확인 (설치는 안내만)
export PYTHONPATH=$PWD/src              # 또는: pip install -e .  (iacpatch 명령이 생김)
export IACPATCH_TF_VAR_FILE=terraform.tfvars.example
python3 -m iacpatch selfcheck
scripts/run_tests.sh                    # 단위 116개 + 통합 7개(도구 있으면)
scripts/predeploy_demo.sh               # mock 정상 패치 → CREATE_PR_AUTO
scripts/predeploy_demo.sh sg_baseline_cidr_split   # 기만적 패치 → V6 FAIL → BLOCK
```

결과는 `data/runs/<id>/` 에 남는다 (`pr_body.md`, `candidate.diff`, `run.json`).

WSL 에서 Windows 폴더를 쓰면 줄끝 `\r` 문제가 있으니 저장소는 WSL 파일시스템(`~/...`)에 두는 것을 권장한다 (worklog 2026-09-11 참조).

## 2. Windows (PowerShell)

```powershell
cd C:\path\to\cloud-security-capstone
$env:PYTHONPATH = "$PWD\src"
$env:IACPATCH_TF_VAR_FILE = "terraform.tfvars.example"
python -m iacpatch selfcheck
scripts\run_tests.ps1
scripts\predeploy_demo.ps1                       # 또는 scripts\predeploy_demo.bat 더블클릭
scripts\predeploy_demo.ps1 sg_baseline_cidr_split
```

terraform.exe / trivy.exe 가 PATH 에 없으면 `$env:TERRAFORM_BIN = "C:\tools\terraform.exe"`, `$env:TRIVY_BIN = "C:\tools\trivy.exe"`.

## 3. 실제 LLM API 로 실행

API 제공업체는 미정이므로 세 종류를 준비했다. **키는 환경변수로만** 넘긴다 (파일·기록에 저장되지 않음).

```bash
# Anthropic
export LLM_PROVIDER=anthropic LLM_MODEL=<model-id> ANTHROPIC_API_KEY=<key>
# OpenAI
export LLM_PROVIDER=openai LLM_MODEL=<model-id> OPENAI_API_KEY=<key>
# OpenAI 호환 (로컬/타 벤더)
export LLM_PROVIDER=openai_compatible LLM_MODEL=<model-id> LLM_BASE_URL=https://.../v1 LLM_API_KEY=<key>

python3 -m iacpatch predeploy --target-dir infrastructure/sg-baseline \
  --intent policy/intent/sg-baseline.json --scenario real-llm-01 --generator llm --offline
```

먼저 `policy/intent/sg-baseline.example.json` 을 `sg-baseline.json` 으로 복사해 `__FILL_ME__` 를 **팀이 정한 실제 승인 CIDR** 로 바꾸고 `status` 를 `active` 로 바꿔야 한다. 코드가 CIDR 을 추측하지 않으며, 플레이스홀더가 남아 있으면 INSUFFICIENT_INFO 로 끝난다.

실제 API 호출은 아직 이 저장소에서 실행·검증되지 않았다 (docs/STATUS.md). 첫 실행 때 `data/runs/<id>/candidates/01/llm_meta.json` 의 `stop_reason` 과 `llm_raw_response.txt` 를 확인할 것.

## 4. Rule-based baseline 비교

```bash
python3 -m iacpatch predeploy --target-dir infrastructure/sg-baseline --intent policy/intent/sg-baseline.json \
  --scenario rule-01 --generator rule_based --offline
```

## 5. 오라클만 따로 (실험용)

```bash
python3 -m iacpatch oracle --plan tests/fixtures/plans/01-cidr-split/plan.json \
  --src-dir tests/fixtures/src/01-cidr-split --intent <intent.json> --json
```

## 6. 운영 경로 전체 (사람 승인 포함)

1. `predeploy` → `data/runs/<id>/pr_body.md` 검토
2. `python3 -m iacpatch pr --run <id>` (명령 미리보기) → 검토 후 `--execute` 또는 출력된 `pr_commands.sh` 를 직접 실행. `review` 흐름(실험 기록)에서 왔으면 `--review <data/reviews id>` — LIGHT_REVIEW/FULL_REVIEW 만 허용
3. GitHub 에서 사람이 리뷰·승인·병합
4. WSL 에서 사람이 `cd infrastructure/sg-baseline && terraform plan && terraform apply` (프로필 `capstone`)
5. `python3 -m iacpatch postdeploy --intent policy/intent/sg-baseline.json --tf-dir infrastructure/sg-baseline --aws-profile capstone` (미리보기) → `--execute`
   - V8 은 `--v8-checks <json>` 으로 체크 정의를 넘겨야 한다 (docs/MODULE_SPEC.md 끝). 인스턴스가 없으면 V8 은 실행 불가.
6. 실패 시 `python3 -m iacpatch recover --run <id> --tf-dir infrastructure/sg-baseline --aws-profile capstone` (미리보기) → `--execute`
   - git 되돌리기만으로 복구 완료로 치지 않는다. apply 후 `plan` 이 "변경 없음" 이고 describe 결과가 기록돼야 RECOVERED.

## 7. 온라인 plan (상태 기준)

`--online` (또는 `IACPATCH_OFFLINE_PLAN=0`) 이면 provider override 없이 프로필로 실제 상태를 읽어 plan 한다. 그러면 V5 의 `plan_actions_delete/replace` 가 실제 액션을 반영한다. 배포된 상태에서 검증할 때 이 모드를 쓴다.

## 8. 자주 나는 문제

| 증상 | 원인/해결 |
|---|---|
| `INSUFFICIENT_INFO: placeholders present` | intent 파일의 `__FILL_ME__` 를 실제 값으로. 추측 금지 |
| `V3 SKIPPED terraform not available` | `TERRAFORM_BIN` 경로 확인 |
| `trivy scan failed ... --tf-vars` | `IACPATCH_TF_VAR_FILE` 이 대상 디렉터리에 존재하는지 |
| `V4 FAIL ... No valid credential sources` | `--offline` 을 빼먹었거나 프로필 없음 |
| 게이트가 `HOLD_FOR_HUMAN` | V6 UNKNOWN(외부 prefix list, 미확정 값, 외부 SG) 또는 도구 SKIPPED. PASS 가 아니다 |
