# E2 실험 결과 — 스캐너 vs 오라클 (실제 plan 기반)

- plan JSON: `tests/fixtures/plans/*` (OpenTofu v1.10.6 로 생성해 커밋)
- 스캐너 열: A 의 Trivy 0.74.0 스캔 원문(`tests/fixtures/trivy/*.json`)에서 AVD-AWS-0107 이 FAIL 인지
- 오라클 열: `iacpatch.verify.sg_oracle.evaluate` (실제 V6 코드) 가 그 plan 을 판정
- 승인 출처(intent): 10.0.0.0/8 (팀 결정값 D-2). expected 는 실행 전 케이스 내용 보고 적음
- 이 표의 숫자는 **검증 계층의 탐지력**이지 LLM 성능이 아니다 (후보가 LLM 이 아니라 알려진 패턴/변형).

## 핵심 (E2)

- **스캐너는 통과(PASS)시켰지만 오라클이 잡은(FAIL) 케이스: 5건** — 스캐너만 믿었으면 그대로 배포됐을 기만적 패치를 오라클이 막았다.
- 기만/취약 케이스(expected=FAIL) 16건 중 오라클이 16건 탐지 (16/16).
- 정상 케이스(expected=PASS) 5건 중 오라클이 5건 통과 (오탐 0건).
- 전체 23건 중 기대대로 판정 23건.

| 케이스 | 스캐너(0107) | 오라클(V6) | 기대 | 일치 | 패턴 |
|---|---|---|---|---|---|
| 00-baseline | FAIL | FAIL | FAIL | O | 취약 대조군: 0.0.0.0/0 그대로 |
| 00b-baseline-fixed | PASS | PASS | PASS | O | 정상 수정: 승인 출처 10.0.0.0/8 로만 |
| 01-cidr-split | PASS | FAIL | FAIL | O | 기만: 0.0.0.0/1 + 128.0.0.0/1 (합집합=전체) |
| 02-var-default | FAIL | FAIL | FAIL | O | 변수 경유 0.0.0.0/0 (plan 에서 해소) |
| 03-string-build | FAIL | FAIL | FAIL | O | join() 문자열 조합 0.0.0.0/0 |
| 04-dynamic | FAIL | FAIL | FAIL | O | dynamic 블록 0.0.0.0/0 |
| 05-separate | FAIL | FAIL | FAIL | O | 별도 ingress_rule 리소스로 0.0.0.0/0 |
| 06-prefix-list | PASS | FAIL | FAIL | O | 기만: prefix list(0.0.0.0/0) 참조 |
| 07-ipv6-only | FAIL | FAIL | FAIL | O | IPv6 ::/0 개방 |
| 08-second-sg | FAIL | FAIL | FAIL | O | 인접 SG(legacy)로 우회, 같은 인스턴스 합산 |
| 09-partial-port-range | FAIL | FAIL | FAIL | O | 포트 범위(20-30)가 22 포함 |
| 10-all-protocols | FAIL | FAIL | FAIL | O | protocol=-1 전체 개방 |
| 11-sg-ref-source | FAIL | FAIL | FAIL | O | SG 참조 출처 (승인 안 함 → 초과) |
| 12-two-enis | FAIL | PASS | PASS | O | 다른 ENI 의 개방 SG 는 섞지 않음 |
| 13-external-sg-attached | PASS | UNKNOWN | UNKNOWN | O | plan 밖 외부 SG 부착 → 판정 불가 |
| 14-target-deleted | PASS | FAIL | FAIL | O | 대상 리소스 삭제 (규칙 사라짐) |
| 15-separate-rules-fixed | PASS | PASS | PASS | O | 정상 수정: 별도 규칙을 승인 출처로 |
| 17-unknown-value | PASS | UNKNOWN | UNKNOWN | O | EIP 참조로 값 미확정 → 판정 불가 |
| 18-self-ref | PASS | FAIL | FAIL | O | self 참조 (승인 안 함) |
| 19-ipv6-approved | PASS | PASS | PASS | O | 정상: 승인된 IPv6 대역만 |
| 20-icmp-only | PASS | PASS | PASS | O | ICMP 만 개방 (SSH/TCP 무관) |
| 21-rdp-open | FAIL | FAIL | FAIL | O | RDP(3389) 개방 (승인 없음) |
| 22-sg-rule-legacy | PASS | FAIL | FAIL | O | 레거시 규칙 리소스로 0.0.0.0/0 |

## 읽는 법
- 스캐너 PASS + 오라클 FAIL = 스캐너가 못 잡은 것을 오라클이 잡음 (01-cidr-split, 06-prefix-list 가 대표). **이게 프로젝트의 핵심 주장.**
- 스캐너 FAIL + 오라클 FAIL = 둘 다 잡음 (오라클이 스캐너를 대체하는 게 아니라, 스캐너가 놓치는 변형까지 커버).
- 오라클 UNKNOWN = plan 밖 요소(외부 SG, 미확정 값)로 판정 불가 → 자동 승인 차단, 사람 검토 (13, 17).
- 한계: 01·06 은 원본이 스캐너를 우회하므로 실제 파이프라인에서는 finding 자체가 없어 시작되지 않는다(NO_FINDING). 이 표는 '패치 결과가 그런 모양이 됐을 때 오라클이 잡는가'를 본 것 (docs/criticism 비판 8).
