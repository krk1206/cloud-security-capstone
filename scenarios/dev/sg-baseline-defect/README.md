# sg-baseline-defect — 단위 시험용 고정본 (결함 상태)

`infrastructure/sg-baseline/` 의 **결함 상태**(SSH 22 가 0.0.0.0/0 에 열림) 사본이다.
단위 시험(tests/unit)은 이 폴더를 읽는다 — `infrastructure/sg-baseline/` 은 파이프라인이
패치해서 바뀌는 살아있는 폴더라 시험 입력으로 쓰면 패치가 성공할 때마다 시험이 깨졌다 (2026-11-17 분리).

- 이 폴더는 고치지 않는다. 워크플로 ①·③·Trivy 게이트의 대상이 아니다.
- `baseline-scan.json` 은 같은 결함 상태의 Trivy 결과(A 가 커밋한 원본과 동일).
