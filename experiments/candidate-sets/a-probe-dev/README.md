# a-probe-dev — A 의 Trivy 우회 실험 9종을 B·C 검토 흐름에 통과시킨 개발용 세트

## 무엇을 돌렸나

| 재료 | 출처 |
|---|---|
| 원본 Terraform 9종 | A: `experiments/trivy-sg-probe/cases/<case>/main.tf` → `scenarios/eval/a-probe/<case>/` 로 byte 동일 복사 (정책이 `experiments/` 수정을 막아서) |
| 입력 스캔 | A: `experiments/trivy-sg-probe/results-verify/<case>.json` (Trivy 0.74.0, 2026-09-08) 그대로 |
| intent | `intents/<case>.json` — `make_intents.py` 가 생성. 대상 SG 주소는 A 의 RESULTS.md 표에서, **승인 CIDR 10.0.0.0/8 은 예제 값** (팀 승인값 아님 → 이 세트는 dev) |
| 후보 | `rule_based` 9건 (규칙 기반 생성기, LLM 아님) |
| 검증 | `--local-tools`: 실행 환경의 trivy/terraform 으로 V1~V4. plan 이 생기면 V5/V6 도 로컬 계산 |

```bash
export PYTHONPATH=src
python3 experiments/candidate-sets/a-probe-dev/check_a_results.py            # A 의 결과 표 재현 확인 → A_RESULTS_CHECK.md
python3 scripts/run_candidate_set.py experiments/candidate-sets/a-probe-dev/manifest.json   # → results.md
```

## 2026-09-15 실행 결과 (샌드박스: Trivy 0.74.0 있음, terraform 은 provider 다운로드 차단)

`A_RESULTS_CHECK.md`: A 의 9 케이스 통과/실패 수·FAIL 룰 집합이 **전부 동일하게 재현**됐다 (다른 컴퓨터, 내장 체크 번들).

`results.md` 요약:

| 케이스 | 결과 | 뜻 |
|---|---|---|
| 01, 06 | NO_FINDING | A 실측대로 Trivy 가 0107 을 안 잡음 → **finding 이 없으니 파이프라인이 시작되지 않는다.** V6 는 "패치가 이런 모양이 됐을 때" 잡는 것이지, 처음부터 이런 모양인 원본은 스캐너 한계 그대로다 (설계 한계로 명시할 것) |
| 02, 03, 04 | INFO_INSUFFICIENT (NOT_SUPPORTED) | 규칙 기반은 변수/locals/dynamic 을 못 고친다 — E1 의 규칙 기반 열이 이렇게 나오는 게 정상 |
| 00, 05, 07, 08 | REVIEW_REQUIRED / PENDING | 후보 생성됨. V1·V2 PASS (로컬 Trivy 재스캔, 입력 스캔과 키 집합 동일). V3·V4 ERROR(provider 못 받음), V5·V6 NOT_RUN → **검증 완료 아님** |

기대 라벨 대비: not_triggered 2/2, unsupported 3/3, correct 0/4 — correct 4건은 V3~V6 가 안 돌아 "확인 못 함" 이 맞다.
terraform + provider 가 있는 환경(팀 WSL)에서 같은 명령을 돌리면 V3~V6 까지 채워진다. 그때 correct 4건이 채워지는지가 확인 항목.

라벨 정정 이력: 07-ipv6-only 는 실행 전 `unsupported` 로 적었다가 `correct` 로 고쳤다 (manifest 의 `expected_history`). 생성기가 `ipv6_cidr_blocks = []` 로 고쳤고, v4 승인 출처가 남으므로 규칙 삭제가 아니다 — 내가 독스트링을 잘못 읽은 것이지 생성기 오류가 아니다.

## 이 숫자로 말할 수 있는 것 / 없는 것

- 있는 것: A 의 결과 파일이 우리 로더로 읽히고 재현된다. 규칙 기반 생성기가 A 의 9 변형 중 4건만 후보를 낸다 (E1 기준선). Trivy 우회 원본 2건은 파이프라인 진입 자체가 안 된다.
- 없는 것: 패치가 맞다는 것(V3~V6 미완), LLM 성능(후보가 LLM 이 아님), 발표 수치(승인 CIDR 이 예제값).
