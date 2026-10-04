# data/runs/

`python -m iacpatch predeploy ...` 실행마다 `<YYYYmmdd-HHMMSS>-<id>/` 폴더가 생긴다 (git 에는 올리지 않는다).

| 파일 | 내용 |
|---|---|
| `run.json` | 요약: 시나리오, 도구 버전, 대상 finding, 후보 요약, 검증/정책/위험도/게이트 결과, 단계별 시간 |
| `settings.json` | 사용한 설정 (비밀값 없음) |
| `bundle.json` | Evidence Bundle (생성기 입력) |
| `baseline_files.json` | 원본 *.tf 스냅샷 (복구용) |
| `trivy_before.json` / `plan_baseline.json` | 원본 스캔/plan 원문 |
| `candidates/NN/` | 시도별: `candidate.json`, `files/` (패치 후보 파일 — 원본과 분리), `llm_raw_response.txt`, `llm_meta.json`, `trivy_after.json`, `plan_candidate.json`, `policy.json`, `verification.json` |
| `risk.json` / `gate.json` | 위험도 산출과 게이트 결정 |
| `candidate.diff` / `pr_body.md` | 사람이 읽는 diff 와 PR 본문 |
| `timings.json` | 단계별 자동 처리 시간(초) — MTTR 의 '사람 대기 제외' 구간 |

샌드박스에서 실제로 실행한 기록의 요약본은 `data/runs-sample/` 에 있다.
