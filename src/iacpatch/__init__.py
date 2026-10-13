"""iacpatch — AWS IaC 보안 패치 검증 파이프라인 (capstone).

패키지 구성 (자세한 설명은 docs/ARCHITECTURE.md):

    tools/       외부 도구 어댑터 (trivy / terraform / aws cli / git / github)
    evidence.py  Trivy finding + 코드 컨텍스트 + Intent → Evidence Bundle
    intent.py    사람이 정의한 승인 출처(Intent Spec) 로딩/검증
    generator/   패치 후보 생성기 (LLM: mock/실제 API, Rule-based baseline)
    verify/      검증 계층 V1~V8 (결정론적 코드, LLM 사용 안 함)
    policy/      Policy Validator, Risk Rubric Scorer, Gate 결정
    pipeline.py  전체 흐름 오케스트레이션 (pre-deploy / post-deploy / recover)
    runrecord.py 실행 기록 (입력·출력·모델·프롬프트 버전·검증 결과)

외부 의존성 없음 (Python 표준 라이브러리만 사용).
"""

__version__ = "0.1.0"
