# scenarios/ — 파이프라인 입력 시나리오

| 폴더 | 용도 |
|---|---|
| `dev/`  | 개발 중 반복 실행하는 시나리오 (게이트 로직을 맞추는 데 사용). 평가 수치에 포함하지 않는다 |
| `eval/` | 평가 전용. **개발 중 게이트/정책을 이 케이스에 맞춰 고치지 않는다.** 실험 프로토콜 확정 후에만 실행한다 |
| `arch/` | 지도교수 9/29 지시의 **아키텍처 단위 시나리오** (`webapp-2tier`: VPC 2계층 웹 17 리소스, 의도적 설정 오류 7줄). 샌드박스 apply 시연·Trivy 점검·AI 해석·패치 세트(`experiments/candidate-sets/arch-webapp-*`)의 원본. `infrastructure/` 가 아니라 여기에 두는 이유: 일부러 취약한 실험 재료라서 — `iac-scan.yml` 의 PR 게이트(HIGH/CRITICAL 이면 실패)는 `infrastructure/**` 만 본다. 실제 샌드박스에 올리는 패치는 `sandbox` 브랜치로 (docs/SOLO_ABC_RUNBOOK.md) |

`infrastructure/sg-baseline/` 은 실제 AWS 샌드박스에 배포하는 기준 시나리오(운영 경로)다.
`tests/fixtures/src/` 는 오라클 단위 테스트용 plan fixture 원본이며, 생성기가 수정하는 대상이 아니다 (policy 의 protected_paths 로 보호됨).
