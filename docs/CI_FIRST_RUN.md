# GitHub Actions 첫 실행 기록 (PR #4, 2026-09-28)

`docs/STATUS.md` 가 "첫 실행 결과를 여기에 기록" 이라고 약속한 문서. 숫자는 Actions 페이지에서 읽은 그대로이고, 못 읽은 것은 "확인 필요" 로 남긴다.
push 는 B 가 GitHub Desktop 으로 했다 (A 계정 `krk1206` 로 로그인 — B 계정·collaborator 등록은 뒤에). PR: https://github.com/krk1206/cloud-security-capstone/pull/4 (`claude/iacpatch-sg-slice` → `main`, 44 커밋).

## 실행 결과

| # | 워크플로 | 커밋 | 결과 | 시간 | 실행 |
|---|---|---|---|---|---|
| 1 | IaC Security Scan (A, `iac-scan.yml`) | 0495b71 | 성공 | 23s | [36450346244](https://github.com/krk1206/cloud-security-capstone/actions/runs/36450346244) |
| 2 | IaCPatch verify (unit + experiments) #1 | 0495b71 | **성공** — unit 9s, experiments(Terraform 1.16.1 + Trivy 0.74.0, 후보 세트 4 `--fresh` + 오라클 실험) 4m 58s | 5m 13s | [36450346384](https://github.com/krk1206/cloud-security-capstone/actions/runs/36450346384) |
| 3 | Build IaCPatch.exe (Windows) #1 | 0495b71 | **실패** — 빌드는 성공, "Smoke test" 단계 exit 1 | 53s | [36450346329](https://github.com/krk1206/cloud-security-capstone/actions/runs/36450346329) |
| 4 | IaC Security Scan #6 | 9fd2985 | 성공 (Trivy IaC Scan 24s, 아티팩트 trivy-scan-results) | 27s | [36456065463](https://github.com/krk1206/cloud-security-capstone/actions/runs/36456065463) |
| 5 | IaCPatch verify #2 | 9fd2985 | **성공** — unit 9s, experiments 4m 9s, 아티팩트 `iacpatch-report-2` (360 KB) | 4m 25s | [36456065586](https://github.com/krk1206/cloud-security-capstone/actions/runs/36456065586) |
| 6 | Build IaCPatch.exe #2 | 9fd2985 | **실패** — 콘솔판·창 없는 판 빌드 둘 다 성공(각 exe 생성), "Smoke test (console exe …)" 단계 exit 1 | 1m 12s | [36456065448](https://github.com/krk1206/cloud-security-capstone/actions/runs/36456065448) |

확인 필요: verify 가 PR 에 다는 고정 댓글(`<!-- iacpatch-ci-summary -->`, 후보 세트 표)이 실제로 달렸는지 — 로그인 없이 PR 댓글을 못 읽었다. PR 페이지에서 `github-actions` 댓글 유무를 보면 된다.

## exe 빌드가 두 번 실패한 이유 (Actions 로그는 로그인 없이 못 읽어 샌드박스에서 재현)

1. **#1 (창 없는 exe 로 스모크)**: `--windowed` exe 는 `sys.stdout`/`sys.stderr` 가 `None` 이라 `print`·unittest 가 죽고, PowerShell 은 GUI 앱을 기다리지 않아 종료 코드도 못 받는다 → 9fd2985 에서 `_ensure_streams()`(출력을 `experiments/exe-console.log` 로), 콘솔판 `IaCPatch-console.exe` 추가, 창 없는 판은 `Start-Process -Wait` 로 검사.
2. **#2 (콘솔 exe 로 스모크)**: 빌드는 됐는데 여전히 실패. 샌드박스에서 exe 와 같은 방식(`python src/iacpatch/app.py …`, 즉 패키지가 아니라 __main__ 스크립트)으로 돌려 보니 두 군데서 죽는다:
   - `from .report_html import build` / `from .web.server import serve` → `ImportError: attempted relative import with no known parent package`. `python -m iacpatch.app` 과 `IaCPatch.bat` 은 패키지로 시작해서 멀쩡했고, PyInstaller 는 `app.py` 를 스크립트로 시작해서 죽는다. **즉 더블클릭 exe 도 화면이 안 떴을 것이다.**
   - `report_html.py`·`fuzz/runner.py`·`review/candidates.py`·`generator/llm_providers.py` 가 `Path(__file__).parents[n]` 으로 저장소 루트를 잡는데, onefile exe 안에서 `__file__` 은 임시 풀림 폴더(`sys._MEIPASS`)라 리포트가 엉뚱한 폴더를 읽는다.
   수정(다음 커밋): `app.py` 는 절대 import 만 쓰고 스크립트로 시작되면 `src/` 를 경로에 넣는다; `config.package_root()` 가 exe 면 exe 위치에서, 소스면 `src/iacpatch` 기준으로 루트를 잡고 네 모듈이 이걸 쓴다. 회귀 테스트 `tests/unit/test_app_report.py::EntryScriptModeTests`(스크립트 모드로 `--console --report-only` 실제 실행, 상대 import 0건) + `PackageRootTests`(frozen 흉내).
   **이 수정이 실제 Windows exe 에서 통하는지는 Build #3 이 말해 준다** — 워크플로가 결과와 로그 끝부분을 PR 댓글(`<!-- iacpatch-exe-build -->`)로 달게 바꿨으므로 다음부터는 로그인 없이 원인을 읽을 수 있다.

| 7 | IaC Security Scan / verify #3 | a033666 | 성공 (3개 초록: iac-scan 23s, verify unit, verify experiments) | | PR #4 체크 화면 |
| 8 | Build IaCPatch.exe #3 | a033666 | **실패** — 러너 Python 단위 테스트(step 4) exit 1, 콘솔 exe 스모크(step 6) exit 1. 빌드 자체는 성공. 결과 표·로그 끝부분이 PR 댓글로 달림 (로그인 없이는 못 읽음 → B 가 펼쳐서 캡처) | 1m 18s | [36460764934](https://github.com/krk1206/cloud-security-capstone/actions/runs/36460764934) |

Build #3 뒤 추가: 스모크가 `--selfcheck`(루트·exe 여부·임시 폴더·도구·설치 검사)부터 찍고 명령마다 종료 코드 표식을 남기며, 결과 표와 **로그 전문을 브랜치 `ci-logs` 에 push** 한다 — 브랜치는 로그인 없이 `git fetch origin ci-logs` 로 읽힌다 (Actions 로그·PR 댓글은 로그인 필요). 이 브랜치는 어떤 워크플로도 다시 돌리지 않는다.

## 워크플로 단계 (build-exe.yml, 수정 후)

러너 Python 으로 단위 테스트(Windows, 실패해도 계속) → exe 2종 빌드 → 콘솔 exe 스모크(`--exec scripts/pyver.py`, `--console --report-only --no-open`; **여기서 실패하면 아티팩트 없음**) → 창 없는 exe 실행 확인 → exe 안에서 단위 테스트(참고용, 실패해도 아티팩트는 올림) → 결과 표 + 로그 끝부분을 PR 댓글·작업 요약에 → `IaCPatch-portable-<sha>.zip` 아티팩트.
"참고용" 으로 둔 이유: Windows 전용 테스트 문제와 exe 문제를 분리하기 위해서. 초록이 되면 막는 단계로 올린다.
