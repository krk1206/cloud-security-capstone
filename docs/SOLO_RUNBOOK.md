# 혼자 돌리는 실험 (A·B·C 역할 전부를 한 사람이)

> 이 문서만 따라 하면 숫자가 나온다. LLM API 키·AWS 계정·GitHub 권한 없이 배포 전 실험(E1·E2)이 끝까지 돈다.
> 유일하게 사람 손이 필요한 건 **Claude Code 에서 후보 받아오기** (지도교수 지시: 유료 API 대신 Claude Code).

## 실행기: `IaCPatch.exe` → 브라우저 화면 (2026-09-28, bat/tkinter 창 대체)

**받는 법**
1. GitHub 저장소 → **Actions** → "Build IaCPatch.exe (Windows)" 의 최근 실행 → 아래 **Artifacts** 의 `IaCPatch-portable` (GitHub 로그인 필요). 태그(`v*`)를 push 했으면 **Releases** 에서 로그인 없이 받는다.
2. zip 을 **빈 새 폴더**에 푼다 (기존 폴더에 덮어쓰지 말 것 — 옛 파일과 섞이면 화면 위 "설치 검사" 칩이 빨갛게 되고 실험을 막는다).
3. 그 폴더의 `IaCPatch.exe` 를 더블클릭 → 기본 브라우저에 화면이 열린다 (`http://127.0.0.1:8765/`, 이 PC 안에서만 접속됨). Python 설치 불필요.
   직접 만들려면 `packaging\build_exe.bat` (PyInstaller, 1회). Python 이 있는 PC 에선 `IaCPatch.bat` 도 같은 화면을 연다.

**화면 탭**

| 탭 | 하는 일 |
|---|---|
| 4주차 · 위험도 기준표 | 기준표(`policy/risk_rubric.json`) 표시 → 라벨 25건을 실제 검토 흐름으로 **도구 없이** 재계산(커밋된 plan 쌍) → 기대 등급 vs 코드 등급 · 상한 강제 전수 검사(72 조합) · 계산기 · 게이트 데모 |
| 5주차 · 패치 → 검증 → PR | 세트의 후보 / 규칙 기반 생성 / 붙여넣기(Claude Code 출력) 중 하나로 한 후보를 돌린다 → V1~V6 표 · 위험도 요인 · 검토 수준 · diff · **PR 미리보기**(브랜치·제목·명령만, push 는 사람) |
| 실험 · 전체 실행 | 단위 테스트(0/8) → 실험 8단계(스캐너 사각 탐색·오라클 차등 검증 포함) → `report/index.html`. 처음 한 번은 전부, 이후엔 바뀐 후보만 |
| 결과 · 리포트 | `report/index.html` |
| 설치 · 도구 | trivy/terraform 을 `tools\` 에 받기(처음 한 번), 설치 검사, 하는 것/안 하는 것 |

- 화면을 닫으면(탭 닫기) 3분 뒤 프로세스가 스스로 끝난다. 바로 끝내려면 화면 오른쪽 위 **종료**.
- 콘솔로만 돌리려면 `IaCPatch.exe --console` (리포트만 `--report-only`, 전부 다시 `--fresh`). 주소만 찍고 브라우저를 안 열려면 `--no-open`, 포트 지정 `--port 9000`, 리포트를 다른 경로에 쓰려면 `--report-out 경로`.
- 로그: `experiments/run_experiments.log`. 리포트는 `report/` (git 에 안 올라감). 화면에서 돌린 후보 기록은 `data/reviews/` 에 시나리오 `ui/…` 로 남아 실험 세트의 최신 기록을 덮지 않는다.
- **속도 (2026-09-22 수정)**: 팀 PC 에서 후보 하나에 3~4분 걸리던 원인은 Windows 에서 `terraform init` 이 후보마다 AWS provider(수백 MB)를 두 번씩 복사하던 것. 이제 (1) 처음 한 번 설치한 provider 를 `data/cache/tf-template/` 에 두고 하드링크로 되살려 복사를 없앴고, (2) 세트의 원본(baseline) 스캔·plan 은 한 번만 만들어 `data/cache/baseline/` 에 두며, (3) 원본·후보·intent·정책·코드·도구 버전이 전부 같은 후보는 이전 기록을 그대로 쓴다 (results.md 머리에 "재사용 N건"). 판정 코드는 그대로다. 팀 PC 실측(09-22, Terraform 1.16.1): 후보당 6~12초, 8단계 전체 약 10분 30초. 전부 다시 돌리려면 "전부 다시 돌리기" 체크 또는 `--fresh`. 캐시를 통째로 끄려면 환경변수 `IACPATCH_NO_CACHE=1`.
- 하지 않는 것: LLM API 호출, Claude Code 자동 호출, AWS 접속, `terraform apply`, `git push`, PR 생성 (D-5, D-11). 실험 결과의 의미와 한계는 리포트 맨 위 노란 상자에 적혀 있다.
- 같은 검증을 GitHub 가 PR 마다 자동으로 돌린다: `.github/workflows/iacpatch-verify.yml` (단위 테스트 + 후보 세트 4개 실측 + 검증 표를 PR 댓글로). exe 빌드(`build-exe.yml`)도 결과 표와 로그 끝부분을 PR 댓글로 단다. 첫 실행 기록: `docs/CI_FIRST_RUN.md`.

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

- **PR 만들기** (C): 실험 기록에서 바로 — `python -m iacpatch pr --review <data/reviews id>` 미리보기(명령만 출력, 원본 안 건드림) → `pr_body.md` 확인 → GitHub 권한 있는 PC 에서 `--execute` (또는 출력된 `pr_commands.sh` 를 직접). 검토 수준이 LIGHT_REVIEW/FULL_REVIEW 인 기록만 받고 BLOCKED/PENDING 은 거부한다. 첫 후보는 B PC 실측의 `eval-a-probe-rule/00-baseline`(LIGHT_REVIEW) 기록이 적당하다. 실험 숫자에는 필요 없다.
- **AWS 샌드박스 배포·V7·V8** (A): `docs/RUNBOOK.md` 6절. 요금·계정이 필요하고 사람 승인 뒤에만. 그때 승인 출처는 접속 테스트할 실제 공인 IP /32 로 sandbox 용 intent 를 따로 만든다 (D-2).

## 5. 막히면

| 증상 | 조치 |
|---|---|
| `python` 없음 | python.org 3.10+ 설치, "Add to PATH" 체크. 재부팅 |
| trivy/terraform 없음 → NOT_RUN | `setup_tools` 다시. 회사망이면 GitHub/HashiCorp 다운로드 차단일 수 있음 |
| V3 `init failed ... registry` | provider 다운로드 차단. `TF_PLUGIN_CACHE_DIR` 에 provider 를 한 번 받아두면 이후 오프라인 |
| `POLICY_BLOCKED` 가 많다 | 정상일 수 있다 (리소스 삭제·허용 밖 타입 생성은 텍스트 정책이 막는다). `data/reviews/<id>/policy.json` 의 violations 를 볼 것 |
| 같은 후보를 다시 돌리고 싶다 | 그냥 다시 실행. 기록은 새 id 로 쌓이고 요약은 최신 것만 쓴다 |
