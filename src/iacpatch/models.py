"""공통 데이터 모델.

모든 모듈이 주고받는 구조체를 한 곳에 정의한다. dataclass + to_dict() 로 JSON 직렬화한다.

용어 (README/RoadMap 과 동일하게 유지):
  - Finding        : Trivy(trivy config)가 보고한 Misconfiguration 1건
  - EvidenceBundle : LLM/Rule-based 생성기에 넘기는 입력 묶음 (finding + 코드 + intent + 제약)
  - PatchCandidate : 생성기가 만든 패치 후보 (원본과 분리 저장, 절대 원본을 덮어쓰지 않음)
  - LayerResult    : 검증 계층(V1~V8) 하나의 결과
  - Verdict        : 계층 결과 상태. PASS / FAIL / UNKNOWN / SKIPPED / ERROR / WARN
  - ValidityReport : V1~V6(배포 전) 또는 V7~V8(배포 후) 결과 묶음과 종합 판정
  - RiskDecision   : Risk Rubric 산출 (위험도 + 자율성 상한)
  - GateDecision   : 최종 게이트 결정 (검증 축과 위험도 축을 합친 결과)
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Verdict(str, Enum):
    PASS = "PASS"          # 계층 조건 충족
    WARN = "WARN"          # 조건은 충족했으나 주의 사항 있음 (차단 아님)
    FAIL = "FAIL"          # 계층 조건 불충족 → 차단
    UNKNOWN = "UNKNOWN"    # 판정 불가 (미확정 값, 해석 불가 출처 등) → 자동 승인 금지
    SKIPPED = "SKIPPED"    # 도구 없음/전제 미충족으로 실행하지 않음 → PASS 로 간주하지 않음
    ERROR = "ERROR"        # 계층 실행 자체가 실패 (도구 오류 등) → PASS 로 간주하지 않음


class Validity(str, Enum):
    """검증 축(Validity)의 종합 판정."""
    PASS = "PASS"              # 필수 계층 전부 PASS(또는 WARN)
    FAIL = "FAIL"              # 하나라도 FAIL
    INCOMPLETE = "INCOMPLETE"  # FAIL 은 없지만 UNKNOWN/SKIPPED/ERROR 가 있어 통과라고 말할 수 없음


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AutonomyLevel(str, Enum):
    """자율성 등급. 위험도가 낮을수록 HIGH. (README 2.3절 표기와 동일)"""
    HIGH = "HIGH"      # PR 자동 생성 + 경량 확인 후 병합 (무인 apply 는 여전히 금지)
    MEDIUM = "MEDIUM"  # PR 생성 + plan/검증 결과 전체 첨부 + 사람 승인 필수
    LOW = "LOW"        # 패치를 커밋하지 않고 진단 리포트만


AUTONOMY_ORDER = {AutonomyLevel.LOW: 0, AutonomyLevel.MEDIUM: 1, AutonomyLevel.HIGH: 2}
RISK_TO_AUTONOMY_CAP = {
    RiskLevel.LOW: AutonomyLevel.HIGH,
    RiskLevel.MEDIUM: AutonomyLevel.MEDIUM,
    RiskLevel.HIGH: AutonomyLevel.LOW,
}


class GateAction(str, Enum):
    CREATE_PR_AUTO = "CREATE_PR_AUTO"            # 자율성 HIGH: PR 자동 생성 (병합 전 경량 확인)
    CREATE_PR_APPROVAL = "CREATE_PR_APPROVAL"    # 자율성 MEDIUM: PR 생성 + 승인 필수
    REPORT_ONLY = "REPORT_ONLY"                  # 자율성 LOW 또는 정보 부족: 패치 커밋 안 함
    HOLD_FOR_HUMAN = "HOLD_FOR_HUMAN"            # 검증 INCOMPLETE: 자동 승인 금지, 사람이 판단
    BLOCK = "BLOCK"                              # 검증 FAIL 또는 정책 위반: PR 생성 안 함


def _to_jsonable(obj: Any) -> Any:
    if isinstance(obj, Enum):
        return obj.value
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(v) for v in obj]
    return obj


class _Jsonable:
    def to_dict(self) -> Dict[str, Any]:
        return _to_jsonable(self)

    def to_json(self, **kw: Any) -> str:
        kw.setdefault("ensure_ascii", False)
        kw.setdefault("indent", 2)
        return json.dumps(self.to_dict(), **kw)


# ---------------------------------------------------------------------------
# Trivy finding
# ---------------------------------------------------------------------------
@dataclass
class Finding(_Jsonable):
    rule_id: str                      # 예: "AVD-AWS-0107" (Trivy JSON 의 AVDID; 없으면 ID 를 정규화)
    severity: str                     # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    resource: str                     # 예: "aws_security_group.vulnerable_ssh"
    filename: str                     # Trivy Target (파일 경로, 스캔 루트 기준)
    start_line: int
    end_line: int
    title: str = ""
    message: str = ""
    resolution: str = ""
    status: str = "FAIL"              # FAIL / PASS (--include-non-failures 사용 시)
    references: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        """V1/V2 비교용 키. 라인 번호는 패치 후 이동하므로 제외한다."""
        return f"{self.rule_id}|{self.filename}|{self.resource}"


# ---------------------------------------------------------------------------
# Intent (사람이 정의한 승인 출처) — intent.py 에서 검증/로딩
# ---------------------------------------------------------------------------
@dataclass
class ServiceSpec(_Jsonable):
    """보호 대상 서비스: 방향 + 프로토콜 + 포트 범위."""
    direction: str          # "ingress" | "egress"
    protocol: str           # "tcp" | "udp" | "icmp" | "icmpv6" | "-1"
    from_port: int
    to_port: int
    label: str = ""

    @property
    def id(self) -> str:
        return f"{self.direction}/{self.protocol}/{self.from_port}-{self.to_port}"


@dataclass
class ApprovedSources(_Jsonable):
    cidrs_v4: List[str] = field(default_factory=list)
    cidrs_v6: List[str] = field(default_factory=list)
    security_group_refs: List[str] = field(default_factory=list)   # 리소스 주소 또는 sg-... ID 또는 "self"
    prefix_list_refs: List[str] = field(default_factory=list)      # 리소스 주소 또는 pl-... ID (전개 결과가 CIDR 승인 안에 있어야 함)


@dataclass
class RequiredAccess(_Jsonable):
    """패치 후에도 반드시 유지돼야 하는 접근 (V6 MISSING 판정, V8 허용 통신 성공 확인에 사용)."""
    service: ServiceSpec
    source_cidr: str        # v4 또는 v6 CIDR
    label: str = ""


# ---------------------------------------------------------------------------
# Evidence bundle / patch candidate
# ---------------------------------------------------------------------------
@dataclass
class EvidenceBundle(_Jsonable):
    bundle_version: str
    scenario_id: str
    target_dir: str                       # 원본 Terraform 디렉터리 (저장소 기준 상대 경로)
    finding: Finding
    related_findings: List[Finding]       # 같은 디렉터리의 나머지 FAIL finding (참고용)
    files: Dict[str, str]                 # 파일명 → 내용 (target_dir 안의 *.tf)
    editable_files: List[str]             # 생성기가 수정해도 되는 파일 (정책)
    intent: Dict[str, Any]                # intent spec 원문 (JSON dict)
    constraints: Dict[str, Any]           # 허용 리소스 타입, 금지 토큰 등 (policy 에서 발췌)
    cis_mapping: Dict[str, Any]           # 룰 ↔ CIS 직접 대응 항목 (없으면 빈 dict)
    tool_versions: Dict[str, str]
    created_at: str


@dataclass
class PatchCandidate(_Jsonable):
    candidate_id: str
    origin: str                            # "llm" | "rule_based" | "mock" | "seeded"
    generator: str                         # 예: "llm:anthropic:claude-...", "rule_based:v1", "mock:<fixture>"
    status: str                            # "PATCH" | "INSUFFICIENT_INFO" | "ABSTAIN" | "GENERATION_FAILED" | "NOT_SUPPORTED"
    files: Dict[str, str]                  # 파일명 → 수정 후 전체 내용 (target_dir 기준 상대 경로)
    rationale: str = ""
    proposed_autonomy: Optional[str] = None  # LLM 제안 등급 (하향 전용). None 이면 제안 없음
    assumptions: List[str] = field(default_factory=list)
    error: str = ""                        # GENERATION_FAILED 사유 (잘림, 파싱 실패 등)
    prompt_version: str = ""
    prompt_sha256: str = ""
    model: str = ""
    raw_response_path: str = ""            # 원문 응답 저장 위치 (run record 안)
    attempt: int = 1


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
@dataclass
class LayerResult(_Jsonable):
    layer: str                  # "V1".."V8"
    name: str
    verdict: Verdict
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    executed: bool = True       # 실제로 실행했는가 (SKIPPED 면 False)
    tool: str = ""              # 사용한 도구/버전


@dataclass
class ValidityReport(_Jsonable):
    phase: str                          # "pre_deploy" | "post_deploy"
    layers: List[LayerResult]
    validity: Validity
    summary: str

    def layer(self, name: str) -> Optional[LayerResult]:
        for l in self.layers:
            if l.layer == name:
                return l
        return None


# ---------------------------------------------------------------------------
# Risk / policy / gate
# ---------------------------------------------------------------------------
@dataclass
class RiskDecision(_Jsonable):
    risk_level: RiskLevel
    autonomy_cap: AutonomyLevel
    score: int
    factors: List[Dict[str, Any]]       # [{factor, value, points, note}]
    rubric_version: str


@dataclass
class PolicyResult(_Jsonable):
    ok: bool
    violations: List[str]
    checks: List[Dict[str, Any]]
    policy_version: str


@dataclass
class GateDecision(_Jsonable):
    action: GateAction
    validity: Validity
    policy_ok: bool
    risk_level: Optional[RiskLevel]
    autonomy_cap: Optional[AutonomyLevel]
    llm_proposed_autonomy: Optional[AutonomyLevel]
    final_autonomy: Optional[AutonomyLevel]
    reasons: List[str]
