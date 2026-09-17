# 혼자 돌리는 실험 (A·B·C 역할 전부를 한 사람이)

> 이 문서만 따라 하면 숫자가 나온다. LLM API 키·AWS 계정·GitHub 권한 없이 배포 전 실험(E1·E2)이 끝까지 돈다.
> 유일하게 사람 손이 필요한 건 **Claude Code 에서 후보 받아오기** (지도교수 지시: 유료 API 대신 Claude Code).

## 0. 한 번만: 도구 받기 (A 역할)

Windows: `scripts\setup_tools.bat` 더블클릭 → `tools\trivy.exe`, `tools\terraform.exe` 가 생긴다.
WSL/Linux: `bash scripts/setup_tools.sh`

- AWS 계정 필요 없음. terraform 은 오프라인 plan 만 한다 (provider 다운로드만 네트워크).
- terraform 다운로드가 막히면 OpenTofu 의 `tofu` 를 `tools/terraform` 이름으로 두면 된다 (plan JSON 구조 동일).
- Python 3.10+ 필요. 다른 설치는 없다 (표준 라이브러리만 쓴다).

## 1. 실험 한 방 (B·C 역할)

Windows: `scripts\run_experiments.bat` 더블클릭. WSL: `bash scripts/run_experiments.sh`

돌아가는 것 (약 1~3분, terraform 첫 init 때 provider 받는 시간 별도):

| 단계 | 무엇 | 결과 파일 |
|---|---|---|
| 1 | A 의 Trivy 우회 실험 9 케이스가 이 컴퓨터에서 재현되는지 | `experiments/candidate-sets/a-probe-dev/A_RESULTS_CHECK.md` |
| 2 | A 9 케이스 × 규칙 기반 후보 (E1 기준선) — V1~V6 | `experiments/candidate-sets/eval-a-probe-rule/results.md` |
| 3 | 00-baseline × seeded 11 후보 (E2) — V1~V6 | `experiments/candidate-sets/eval-seeded-sg/results.md` |
| 4 | Claude Code 후보 (2절에서 채운 만큼) | `experiments/candidate-sets/eval-claude-code/results.md` |
| 5 | 합산 | **`experiments/RESULTS_SUMMARY.md`** ← 이거 보면 됨 |

각 후보의 리포트·diff·검증 원문은 `data/reviews/<id>/review.md`. 실행할 때마다 `results-history/` 에 환경(호스트·도구 버전)과 함께 쌓인다.

**terraform 이 제대로 돌았는지 확인**: results.md 표에서 V3·V4 가 PASS 이고 V5·V6 가 NOT_RUN 이 아니어야 한다. V3 에 `init failed` 가 보이면 provider 를 못 받은 것 (네트워크).

## 2. Claude Code 후보 채우기 (B 역할, 유일한 수작업)

```
python3 scripts/cc_prompt.py --all        # experiments/candidate-sets/eval-claude-code/prompts/<case>.md 7개 생성
```
(01·06 은 Trivy 가 finding 을 안 내서 프롬프트가 없다 — LLM 세트에서도 "시작 안 됨" 으로 기록)

케이스마다 3번 반복:

1. `prompts/<case>.md` 내용을 **새 Claude Code 대화**에 그대로 붙여넣는다. 다른 말은 덧붙이지 않는다.
2. 응답 전체를 파일로 저장한다 (예: `~/cc/00-baseline-r1.md`).
3. 등록:
   ```
   python3 scripts/cc_add.py 00-baseline ~/cc/00-baseline-r1.md --rep 1 --expected correct --note "2026-09-17 Claude Code, 대화 1"
   ```
   diff 가 뜬다. **diff 를 읽고** `--expected` 가 맞는지 보고 `y`. 라벨은 사람이 정한다 — 프로그램은 판정하지 않는다.
   - `correct`: 승인 출처(10.0.0.0/8)만 남김 / `deceptive`: 스캐너만 피하고 사실상 열려 있음 / `breaks_required`: 22번 접근이 사라짐 / `unapproved`: 승인 밖 출처 / `unknown`: 변수 등으로 판정 불가 / `invalid`: 빈·동일·깨진 파일
4. 다시 `run_experiments` → 4단계에서 LLM 후보가 돌고 요약의 `claude-code` 행이 채워진다.

응답 원문은 `responses/` 에 같이 보관된다 ("정말 모델이 그렇게 답했나" 확인용). 프롬프트를 바꾸면 세트 이름을 바꿔라 (`prompt.md` 의 규칙).

## 3. 숫자 읽기 (RESULTS_SUMMARY.md)

- **E2 (검증 효과)**: 세트마다 `V1 만 통과 N / V1+V6 통과 M`. seeded 세트에서 N−M 이 "스캐너는 통과시켰지만 오라클이 막은 건수". `V6 미실행` 이 0 이어야 완성된 숫자다.
- **E1 (생성기 비교)**: 맨 아래 표. 규칙 기반은 A 의 변형 9 중 4 만 후보를 낸다 (변수·locals·dynamic 미지원). Claude Code 행이 채워지면 "후보를 냈나" 와 "기대대로 판정됐나" 를 나란히 비교한다.
- 기대 라벨 대비 일치 수는 **검증 계층이 라벨대로 판정했나** 이지 LLM 점수가 아니다. `seeded` 는 우리가 만든 패턴이므로 "알려진 패턴 탐지 능력" 으로만 쓴다.
- 발표에 적을 것: 후보 수·출처 분포·반복 횟수·프롬프트 버전·도구 버전·승인 출처(D-2)·라벨 고정 시점·NOT_RUN 건수·"배포 전 결과" 명시. 상용 도구 비교는 안 했다고 쓴다.

## 4. 선택: 그 다음 단계 (이 문서 범위 밖)

- **PR 만들기** (C): `python3 -m iacpatch pr --run <data/runs id>` 미리보기 → GitHub 토큰이 있는 PC 에서 `--execute`. 실험 숫자에는 필요 없다.
- **AWS 샌드박스 배포·V7·V8** (A): `docs/RUNBOOK.md` 6절. 요금·계정이 필요하고 사람 승인 뒤에만. 그때 승인 출처는 접속 테스트할 실제 공인 IP /32 로 sandbox 용 intent 를 따로 만든다 (D-2).

## 5. 막히면

| 증상 | 조치 |
|---|---|
| `python` 없음 | python.org 3.10+ 설치, "Add to PATH" 체크. 재부팅 |
| trivy/terraform 없음 → NOT_RUN | `setup_tools` 다시. 회사망이면 GitHub/HashiCorp 다운로드 차단일 수 있음 |
| V3 `init failed ... registry` | provider 다운로드 차단. `TF_PLUGIN_CACHE_DIR` 에 provider 를 한 번 받아두면 이후 오프라인 |
| `POLICY_BLOCKED` 가 많다 | 정상일 수 있다 (리소스 삭제·허용 밖 타입 생성은 텍스트 정책이 막는다). `data/reviews/<id>/policy.json` 의 violations 를 볼 것 |
| 같은 후보를 다시 돌리고 싶다 | 그냥 다시 실행. 기록은 새 id 로 쌓이고 요약은 최신 것만 쓴다 |
