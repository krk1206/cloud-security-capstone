"""탐지 방식 증거 — 검사 단계마다 '어떻게 잡았나 · 무엇을 근거로 · 어떤 파일이 근거인가' 를 기록 파일에서 꺼내 보여 준다.

  standards   외부 기준(AWS·CIS·SK쉴더스 항목, 확인 상태 포함)과 팀 요구사항을 따로 적은 표
  calibrate   검증 도구 사전 점검: 정답이 정해진 시료로 Trivy·대역 계산·validate·접속 판정 규칙을 먼저 확인
  recheck     대역 계산 교차 확인 (오라클과 다른 방식의 별도 구현)
  hcl_lines   .tf 텍스트에서 블록 줄 위치 찾기
  topomap     설계도 ↔ Terraform 코드 대응표
  cards       배포 전 검사(V1~V6) 증거 카드
  postcards   실제 AWS 검사 증거 카드 (시험 환경 반영 확인 · V7 · V8)
  primary     카드마다 처음부터 펼쳐 보여 줄 핵심 증거 고르기 (나머지는 '자세히' 안)
  plain       화면용 쉬운 이름 (보안 그룹 주소 → '웹 서버', 22 → 'SSH 22', open → '연결됨') — 값은 그대로
  report      증거 보고서 HTML (맨 위 한눈에 보기 + 단계별 증거)

이 패키지는 판정을 새로 내리지 않는다. 판정은 기록(verification.json · measure.json) 값을 그대로 쓴다.
"""
