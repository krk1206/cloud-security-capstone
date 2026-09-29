# A 의 Trivy 우회 실험 결과 — 우리 로더 판독 + 로컬 재스캔 대조

- A 의 결과 파일: `experiments/trivy-sg-probe/results-verify/*.json` (A: Trivy 0.74.0, 2026-09-08)
- 로컬 재스캔: Version: 0.74.0 (내장 체크 번들, `--skip-check-update`), 실행 환경: 이 저장소를 돌린 컴퓨터
- 판독: `iacpatch.review.inputs.list_findings` (검토 흐름이 쓰는 것과 같은 로더). '통과/실패' 는 MisconfSummary 합계

| 케이스 | A 통과/실패 | A AWS-0107 | A FAIL 룰 | 로컬 재스캔 통과/실패 + FAIL 룰 | 일치 |
|---|---|---|---|---|---|
| 00-baseline | 70/1 | FAIL | AVD-AWS-0107 | 70/1 AVD-AWS-0107 | 동일 |
| 01-cidr-split | 71/0 | PASS | - | 71/0 - | 동일 |
| 01b-control | 70/1 | FAIL | AVD-AWS-0107 | 케이스 폴더 없음 | - |
| 02-var-default | 70/1 | FAIL | AVD-AWS-0107 | 70/1 AVD-AWS-0107 | 동일 |
| 03-string-build | 70/1 | FAIL | AVD-AWS-0107 | 70/1 AVD-AWS-0107 | 동일 |
| 04-dynamic | 69/2 | FAIL | AVD-AWS-0107,AVD-AWS-0124 | 69/2 AVD-AWS-0107,AVD-AWS-0124 | 동일 |
| 05-separate | 68/4 | FAIL | AVD-AWS-0104,AVD-AWS-0107,AVD-AWS-0124,AVD-AWS-0124 | 68/4 AVD-AWS-0104,AVD-AWS-0107,AVD-AWS-0124,AVD-AWS-0124 | 동일 |
| 06-prefix-list | 71/0 | PASS | - | 71/0 - | 동일 |
| 07-ipv6-only | 70/1 | FAIL | AVD-AWS-0107 | 70/1 AVD-AWS-0107 | 동일 |
| 08-second-sg | 68/3 | FAIL | AVD-AWS-0028,AVD-AWS-0107,AVD-AWS-0131 | 68/3 AVD-AWS-0028,AVD-AWS-0107,AVD-AWS-0131 | 동일 |

**전 케이스 일치** — A 의 표(RESULTS.md/VERIFY.md)가 다른 컴퓨터·내장 체크 번들로 재현됐다.
