# scenarios/ — 파이프라인 입력 시나리오

| 폴더 | 용도 |
|---|---|
| `dev/`  | 개발 중 반복 실행하는 시나리오 (게이트 로직을 맞추는 데 사용). 평가 수치에 포함하지 않는다 |
| `eval/` | 평가 전용. **개발 중 게이트/정책을 이 케이스에 맞춰 고치지 않는다.** 실험 프로토콜 확정 후에만 실행한다 |

`infrastructure/sg-baseline/` 은 실제 AWS 샌드박스에 배포하는 기준 시나리오(운영 경로)다.
`tests/fixtures/src/` 는 오라클 단위 테스트용 plan fixture 원본이며, 생성기가 수정하는 대상이 아니다 (policy 의 protected_paths 로 보호됨).
