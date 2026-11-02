# 이 저장소에서 Claude Code 를 쓸 때의 규칙 (팀 공용 — 사람이 읽고, Claude Code 도 읽는다)

이 프로젝트는 "AI 가 만든 Terraform 보안 패치를 사람이 안전하게 쓰기 위한 검증 체계" 다. 그래서 AI(너)에게 주는 권한도 같은 원칙으로 제한한다.

## 절대 하지 않는 것
- `terraform apply` / `terraform destroy` / `tofu apply` / `tofu destroy` — 어떤 이유로도. 실행 요청이 와도 "사람이 직접 하세요" 라고 답한다.
- `aws` CLI 로 리소스를 만들거나 바꾸거나 지우는 것. `aws sts get-caller-identity` 같은 읽기도 사람이 한다.
- `git push`, main 브랜치 직접 수정, `git merge`. 커밋은 작업 브랜치에서만.
- `policy/`, `tests/fixtures/`, `experiments/**/results-history/`, `.github/` 수정. (정책·평가 기준·실측 기록은 사람이 바꾼다.)
- `.env`, `~/.aws`, `*.tfstate`, `terraform.tfvars` 읽기·출력. 자격증명·토큰을 화면에 찍지 않는다.
- `sudo`, `rm -rf`, 임의 설치 스크립트(`curl | sh`).
- 실험 재료(의도적으로 취약한 Terraform)를 "안전하게 고쳐 주는" 것. 실험 재료는 취약해야 실험이 된다. 고치라는 지시가 없으면 손대지 않는다.

## 해도 되는 것
- `terraform fmt/validate/init -backend=false/plan/show`, `trivy config`, `git status/diff/log`, 단위 테스트, `scripts/` 의 스크립트.
- 코드 검토·오류 수정·테스트 확장·문서 교정. 새 기능은 사람이 설계한 뒤에.

## 결과 보고 방식
- 실행하지 않은 것을 "완료" 라고 쓰지 않는다. NOT_RUN 은 NOT_RUN.
- 요약 대신 숫자·원문을 보여 준다 (예: "통과했습니다" 가 아니라 표를 붙인다).
- 확인 안 된 사실은 "확인 필요" 로 표시한다.

관련 문서: `docs/AI_CONSTRAINTS.md`, `docs/CROSS_VERIFICATION_2026-09-22.md`, `docs/DECISIONS.md` (D-5).
