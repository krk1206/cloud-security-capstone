# tools/

`scripts/setup_tools.sh` (WSL/Linux) 또는 `scripts/setup_tools.bat` (Windows) 가 여기에 `trivy` / `terraform` 바이너리와 `plugin-cache/` 를 받는다.
`scripts/run_experiments.*` 는 이 폴더를 먼저 찾고, 없으면 PATH 의 것을 쓰고, 그것도 없으면 해당 검증 계층을 NOT_RUN 으로 남긴다.
바이너리는 커밋하지 않는다 (.gitignore).
