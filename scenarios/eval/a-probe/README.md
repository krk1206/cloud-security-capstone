# A 의 Trivy 우회 실험 케이스 9종 (평가용 원본 사본)

- 출처: `experiments/trivy-sg-probe/cases/<case>/main.tf` (A, origin/main 74a6f38, 2026-09-08 실험) — **byte 단위 동일 사본**
- `trivy-scan.json`: A 가 `trivy config --include-non-failures --format json` 으로 만든 `experiments/trivy-sg-probe/results-verify/<case>.json` 그대로 (Trivy 0.74.0, WSL2)
- 여기로 복사한 이유: 정책(`policy/patch_policy.json` protected_paths)이 `experiments/` 아래 파일 수정을 막기 때문에
  검토 흐름의 **원본 디렉터리**로는 쓸 수 없다. 실험 기록(A 의 폴더)은 손대지 않고, 사본을 원본으로 쓴다.
- 동일성 확인: `diff -r` 로 두 폴더의 main.tf 가 같음을 언제든 확인할 수 있다.
  ```bash
  for c in scenarios/eval/a-probe/*/; do n=$(basename $c); diff -q $c/main.tf experiments/trivy-sg-probe/cases/$n/main.tf; done
  ```
- 케이스 설명·A 의 결과 표: `experiments/trivy-sg-probe/RESULTS.md`, `VERIFY.md`. 01·06 은 A 실측에서 AVD-AWS-0107 미검출(우회) 케이스.
