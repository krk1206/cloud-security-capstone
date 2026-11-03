"""화면·보고서에 표시할 이름. 보안 그룹 주소·포트·출발지 대역을 읽기 쉬운 이름으로 바꾼다.

값은 바꾸지 않는다 — 이름만 붙인다. 예:
  aws_security_group.bastion        → Bastion 보안 그룹
  tcp 22                            → SSH 22
  0.0.0.0/0                         → 0.0.0.0/0 (인터넷 전체)
  203.0.113.0/24, 198.51.100.0/24   → 관리자 허용 목록 (203.0.113.0/24, 198.51.100.0/24)
  aws_security_group.web (출처)     → 웹 서버
이름은 설계도 파일(intents/arch-3tier-flows.json)의 tiers.label 에서 읽는다. 없으면 주소를 그대로 쓴다.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

PORT_NAMES = {22: "SSH", 3389: "RDP", 3306: "MySQL", 6379: "Redis", 8080: "API", 80: "HTTP", 443: "HTTPS", 5432: "PostgreSQL"}
DESIGN = Path("experiments") / "candidate-sets" / "arch-3tier-sg" / "intents" / "arch-3tier-flows.json"

_cache: Dict[str, Dict[str, Any]] = {}


def _design(root: Optional[Path]) -> Dict[str, Any]:
    if root is None:                      # 호출한 쪽이 루트를 모르면 프로그램 루트 (exe 옆 저장소)
        try:
            from .. import app as _app
            root = _app.ROOT
        except Exception:
            root = None
    key = str(root or "")
    if key not in _cache:
        d: Dict[str, Any] = {}
        try:
            if root:
                d = json.loads((Path(root) / DESIGN).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            d = {}
        labels = {t.get("security_group"): t.get("label") for t in d.get("tiers") or [] if t.get("security_group") and t.get("label")}
        allow = [c for e in d.get("external") or [] if e.get("id") == "admin" for c in e.get("cidrs_v4") or []]
        _cache[key] = {"labels": labels, "admin": allow}
    return _cache[key]


def server(addr: Any, root: Optional[Path]) -> str:
    """보안 그룹 주소 → 그 보안 그룹이 붙은 서버 이름 (웹 서버, MySQL …). 모르면 주소 끝 이름."""
    a = str(addr or "")
    lab = _design(root)["labels"].get(a)
    if lab:
        return lab
    return a.split(".", 1)[1] if a.startswith("aws_security_group.") else a


def sg(addr: Any, root: Optional[Path]) -> str:
    """보안 그룹 주소 → 'Bastion 보안 그룹'."""
    return f"{server(addr, root)} 보안 그룹"


def port(proto: Any, lo: Any, hi: Any = None) -> str:
    """('tcp', 22, 22) → 'SSH 22' / ('-1', 0, 0) → '모든 포트'."""
    if str(proto) in ("-1", "all"):
        return "모든 포트"
    hi = lo if hi is None else hi
    if lo == hi:
        try:
            n = int(lo)
        except (TypeError, ValueError):
            return f"{proto} {lo}"
        return f"{PORT_NAMES[n]} {n}" if n in PORT_NAMES else f"{str(proto).upper()} {n}"
    return f"{str(proto).upper()} {lo}~{hi}"


def port_text(p: Any) -> str:
    """'22' 같은 포트 글자 → 'SSH 22'. 범위·여러 개는 그대로."""
    s = str(p or "")
    return port("tcp", int(s), int(s)) if s.isdigit() else s


def sources(values: Iterable[Any], root: Optional[Path]) -> str:
    """출처 목록 → 쉬운 말. 관리자 허용 목록과 같으면 그 이름, 0.0.0.0/0 은 '인터넷 전체', 보안 그룹은 서버 이름."""
    vals = [str(v) for v in values]
    admin = _design(root)["admin"]
    if admin and sorted(vals) == sorted(admin):
        return "관리자 허용 목록 (" + ", ".join(vals) + ")"
    out: List[str] = []
    for v in vals:
        if v == "0.0.0.0/0":
            out.append("0.0.0.0/0 (인터넷 전체)")
        elif v == "::/0":
            out.append("::/0 (IPv6 인터넷 전체)")
        elif v.startswith("aws_security_group."):
            out.append(server(v, root))
        else:
            out.append(v)
    return ", ".join(out) or "?"


def probe_result(r: Any) -> str:
    """통신 시험 결과 낱말 → 화면 용어 (판정은 그대로). 접속 성공 / 접속 차단 / 그 밖(연결 거부·측정 오류)은 판정 불가 쪽."""
    s = str(r or "")
    if s.startswith("error:"):
        return f"측정 오류 ({s.split(':', 1)[1]})"
    return {"open": "접속 성공", "timeout": "접속 차단 (응답 없음)", "refused": "연결 거부", "error": "측정 오류", "closed": "접속 차단",
            "fail": "응답 이상"}.get(s, s or "-")


def flow_port(to_label: Any, port: Any) -> str:
    """'MySQL' + 3306 → 'MySQL 3306' / 'Bastion' + 22 → 'Bastion SSH 22' (도착 이름과 포트 이름이 같으면 한 번만)."""
    to, pt = str(to_label or ""), port_text(port)
    return pt if to and pt.startswith(to) else f"{to} {pt}".strip()


# Terraform 오류 문장(영어) → 화면 요약. 원문은 증거 블록에 그대로 남긴다 (여기서는 화면 한 줄만).
_TF_ERRORS = [
    ("No value for required variable", r'variable "([^"]+)"', "기본값 없는 변수에 값 미지정"),
    ("Reference to undeclared resource", r'resource "([^"]+)" "([^"]+)" has not been declared', "선언되지 않은 리소스 참조"),
    ("Reference to undeclared input variable", r'variable with the name "([^"]+)"', "선언되지 않은 변수 참조"),
    ("Reference to undeclared local value", r'local value with the name "([^"]+)"', "선언되지 않은 local 값 참조"),
    ("Unsupported argument", r'argument named "([^"]+)"', "지원되지 않는 속성 사용"),
    ("Missing required argument", r'argument "([^"]+)" is required', "필수 속성 누락"),
    ("Unsupported attribute", r'attribute named "([^"]+)"', "존재하지 않는 속성 참조"),
    ("Unsupported block type", r'[Bb]locks of type "([^"]+)"', "지원되지 않는 블록 사용"),
    ("Duplicate resource", r'resource named "([^"]+)"', "같은 이름의 리소스 중복 선언"),
    ("Invalid reference", None, "잘못된 참조"),
    ("Incorrect attribute value type", r'attribute "([^"]+)"', "속성 값 형식 오류"),
    ("Argument or block definition required", None, "구문 오류 (블록 형식)"),
    ("Invalid block definition", None, "구문 오류 (블록 형식)"),
    ("Unclosed configuration block", None, "구문 오류 (닫는 괄호 누락)"),
    ("Invalid expression", None, "구문 오류 (잘못된 식)"),
    ("validate failed, plan not attempted", None, "V3(구문·속성·참조 검사) 실패로 plan 미실행"),
]


def tf_error_ko(text: Any) -> str:
    """Terraform 오류 → 요약 한 줄 + 대상 이름. 예: 'Reference to undeclared resource … "aws_security_group" "admin" …'
    → '선언되지 않은 리소스 참조 (aws_security_group.admin)'. 모르는 오류는 원문 첫 줄을 그대로 (판정은 바꾸지 않음)."""
    raw = str(text or "")
    flat = " ".join(raw.split())
    for key, pat, ko in _TF_ERRORS:
        if key in flat:
            m = re.search(pat, flat) if pat else None
            what = ".".join(m.groups()) if m else ""
            return f"{ko} ({what})" if what else ko
    first = next((ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.strip().startswith("---")), "")
    first = re.sub(r"^(?:Error|error):\s*", "", first)
    return first[:160]


# 이전 기록(measure.json · calibration.json · state.json 등)에 저장된 문구 → 지금 화면 용어.
# 기록 파일은 바꾸지 않는다 — 화면·보고서에 표시할 때만 바꾼다. 판정·비교에 쓰는 값(열림 확인·끊김·맞음 등)은 여기서 바꾸지 않는다.
_LEGACY = [
    ('스캔 결과와 원본 코드가 일치하지 않는다 (지목된 줄 내용이 다름). 스캔을 다시 하거나 같은 시점의 원본을 써야 한다', '스캔 결과와 원본 코드 불일치 (지목된 행 내용이 다름) — 재스캔 또는 같은 시점의 원본 사용 필요'),
    (' 이 원본 디렉터리에 없다', ' 이 원본 디렉터리에 없음'),
    ('빈 후보: 파일 목록이 없다', '빈 후보: 파일 목록 없음'),
    ('빈 후보: 모든 파일 내용이 비어 있다', '빈 후보: 모든 파일 내용이 비어 있음'),
    (' (새 파일 생성은 허용하지 않는다)', ' (새 파일 생성 불가)'),
    ('원본과 동일한 후보: 변경된 내용이 없다', '원본과 동일한 후보: 변경 내용 없음'),
    ('수정 이유(rationale) 미기재 — 검토 전에 사람이 적어야 한다', '수정 이유(rationale) 미기재 — 검토 전 사람이 작성 필요'),
    ('IPv4 CIDR 이 아닌 값이 있다', 'IPv4 CIDR 이 아닌 값 포함'),
    ('콘솔 출력(get-console-output --latest)은 실시간이 아니다 — 2026-10-23 실측에서 새 줄이 보이기까지 20~40초 늦은 경우가 있었다. 그래서 (1) 측정은 apply 가 끝나고 2분 뒤부터 할 수 있고 (2) 측정 시작 때 본 seq 보다 2 이상 커진 결과만 쓴다. 둘을 합치면 판정에 쓴 측정은 콘솔 지연이 2분 남짓을 넘지 않는 한 apply 뒤에 시작된 것이다.', '콘솔 출력(get-console-output --latest)은 실시간이 아님 — 2026-10-23 실측에서 새 줄 표시까지 20~40초 지연 사례. 따라서 (1) apply 완료 2분 후부터 측정 가능 (2) 측정 시작 시점 seq 보다 2 이상 증가한 결과만 사용. 두 조건을 합치면 콘솔 지연이 2분 남짓을 넘지 않는 한 판정에 사용한 측정은 apply 이후 시작.'),
    ('Trivy JSON 파일이 없다: ', 'Trivy JSON 파일 없음: '),
    ('Trivy JSON 을 읽을 수 없다: ', 'Trivy JSON 읽기 실패: '),
    ('Trivy JSON 이 올바른 JSON 이 아니다 (', 'Trivy JSON 형식 오류 — 올바른 JSON 아님 ('),
    ('Trivy JSON 형식이 아니다 (Results 키 없음): ', 'Trivy JSON 형식 아님 (Results 키 없음): '),
    ('Trivy JSON 의 Results 가 리스트가 아니다: ', 'Trivy JSON 의 Results 가 리스트 아님: '),
    ('연결된 검증 결과에 실패가 있어 후보를 반영하면 안 됨', '검증 결과에 실패 포함 — 후보 반영 불가'),
    (' — 검증 대기 계층이 있음 (패치 검증 완료 아님)', ' — 미검증 단계 존재 (패치 검증 완료 아님)'),
    ('검증 결과가 전부 있기 전에는 검토 수준을 정하지 않는다 (위험도는 참고용으로만 표시)', '모든 검증 결과 확보 전에는 검토 수준을 정하지 않음 (위험도는 참고용으로만 표시)'),
    ('검증 대기 — ', '미검증 — '),
    ('검증 대기: ', '미검증: '),
    ('A 의 Trivy 재스캔 결과 없음', 'Trivy 재검사 결과 없음'),
    ('A 의 Trivy 전후 비교 결과 없음', 'Trivy 수정 전·후 비교 결과 없음'),
    ('A 의 terraform validate 결과 없음', 'terraform validate 결과 없음'),
    ('A 의 terraform plan 결과 없음', 'terraform plan 결과 없음'),
    ('후보 plan JSON 또는 intent 없음', '후보 plan JSON 또는 요구사항(intent) 없음'),
    ('배포 후 실측 없음', '실제 AWS 검사 측정 없음'),
    ('통신 확인 없음', '통신 시험 없음'),
    (' — 로컬 재스캔 불가', ' — 로컬 재검사 불가'),
    ('V3/V4 는 OpenTofu 로 실행했다 (팀 환경 Terraform 1.16.1 과 다름). plan JSON 구조는 같다', 'V3/V4 는 OpenTofu 로 실행 (팀 환경 Terraform 1.16.1 과 다름). plan JSON 구조는 동일'),
    ("콘솔 출력(get-console-output --latest)은 실시간이 아니다 — 2026-10-23 실측에서 새 줄이 보이기까지 20~40초 늦은 경우가 있었다. 그래서 (1) 측정은 apply 가 끝나고 2분 뒤부터 할 수 있고 (2) 측정 시작 때 본 seq 보다 2 이상 커진 결과만 쓴다. seq+1 은 측정 시작 때 아직 안 보였으므로 seq+2 의 시험은 '측정 시작 − 콘솔 지연 + 15초' 뒤에 시작했다 → apply 가 끝나고 '135초 − 콘솔 지연' 뒤. 콘솔 지연이 135초 미만이면 판정에 쓴 시험은 모두 apply 뒤에 시작한 것이다 (AWS 문서에 콘솔 지연 상한 숫자는 없음 — 실측값만 근거).", "콘솔 출력(get-console-output --latest)은 실시간이 아님 — 2026-10-23 실측에서 새 줄 표시까지 20~40초 지연 사례. 따라서 (1) apply 완료 2분 후부터 측정 가능 (2) 측정 시작 시점 seq 보다 2 이상 증가한 결과만 사용. seq+1 은 측정 시작 시 미표시였으므로 seq+2 의 시험은 '측정 시작 − 콘솔 지연 + 15초' 이후 시작 → apply 완료 '135초 − 콘솔 지연' 이후. 콘솔 지연이 135초 미만이면 판정에 사용한 시험은 모두 apply 이후 시작 (AWS 문서에 콘솔 지연 상한 수치 없음 — 실측값만 근거)."),
    ('원본 파일·도구 버전이 같을 때만 재사용한다', '원본 파일·도구 버전이 같을 때만 재사용'),
    ('IPv6 출처 ', 'IPv6 출발지 '),
    ('설계도에 IPv6 통신이 없습니다', '설계도에 IPv6 통신 없음'),
    ('설계도에 없는 서버 (', '설계 외 서버 ('),
    (' 을 단 자원은 설계도의 어느 계층도 아닙니다', ' 연결 리소스는 설계도의 어느 계층에도 속하지 않음'),
    (' 에 plan 으로 확인할 수 없는 보안 그룹이 붙어 있습니다 — 그 규칙은 판단할 수 없습니다', ' 에 plan 으로 확인 불가한 보안 그룹 연결 — 해당 규칙 판정 불가'),
    (' 이 plan 에 없습니다', ' 이 plan 에 없음'),
    (' 이 어떤 자원에도 붙어 있지 않습니다', ' 이 어떤 리소스에도 연결되지 않음'),
    (' 의 보안 그룹도 붙어 있다 — 두 계층 규칙이 합쳐집니다', ' 의 보안 그룹도 연결 — 두 계층 규칙 합산'),
    (' 의 인바운드 규칙이 확정되지 않았습니다 (', ' 의 인바운드 규칙 미확정 ('),
    (': 출처 보안 그룹 ', ': 출발지 보안 그룹 '),
    (' 를 plan 에서 확인할 수 없습니다 (', ' 를 plan 에서 확인 불가 ('),
    (' 내용을 확인할 수 없습니다 (', ' 내용 확인 불가 ('),
    (': 출처를 확정할 수 없는 규칙 (', ': 출발지 미확정 규칙 ('),
    ("연결 거부 = 패킷이 서버까지 감 → 보안 그룹이 막았다는 증거 아님", "연결 거부 — 패킷이 서버까지 도달 (보안 그룹 차단 증거 아님)"),
    ("응답 없음 (보안 그룹이 버림)", "접속 차단 (응답 없음 — 보안 그룹 차단)"),
    ("막혀야 하는데 연결됨", "차단 경로인데 접속 성공"),
    ("열려야 하는데 ", "허용 경로인데 접속 실패: "),
    ("측정 시작 뒤에 새로 잰 값이 아님 (측정기 결과가 갱신되지 않음)", "측정 시작 후 신규 측정값 아님 (측정 결과 미갱신)"),
    ("측정 시작 뒤에 새로 잰 값이 아님", "측정 시작 후 신규 측정값 아님"),
    ("설계도에 없는 통신 → 막혀야 함", "설계 외 경로 → 접속 차단 기대"),
    ("설계 통신: ", "설계 기준 경로: "),
    ("참고만 — 이 PC 는 학교망 방화벽·프록시 영향을 받을 수 있어 판정에 넣지 않음", "참고용 — 학교망 방화벽·프록시 영향 가능성으로 판정 제외"),
    ("AWS 측정 지점 결과와 같음", "AWS 측정 지점 결과와 일치"),
    ("AWS 측정 지점 결과와 다름", "AWS 측정 지점 결과와 불일치"),
    ("이 통신을 직접 시험한 새 결과가 없음 (측정기 결과 없음·갱신 안 됨)", "이 경로를 직접 시험한 신규 결과 없음 (측정 결과 없음·미갱신)"),
    ("측정 못 함: ", "미측정: "),
    ("열림·막힘 시험이 둘 다 있어야 판정", "허용·차단 경로 시험이 모두 있어야 판정 가능"),
    ("모두 기대대로 (열림 ", "모두 기대 결과와 일치 (접속 성공 "),
    (" · 막힘 ", " · 접속 차단 "),
    (" · 설계 통신 ", " · 설계 기준 경로 "),
    ("개 중 시험으로 확인 ", "개 중 시험 확인 "),
    ("열려야 함: open=통과 / 막혀야 함: timeout=통과, open=실패, refused·오류=판정 불가",
     "허용 경로: open(접속 성공)=통과 / 차단 경로: timeout(접속 차단)=통과, open=실패, refused·오류=판정 불가"),
    ("측정 시작 때 본 seq 보다 2 이상 커진 결과만 사용", "측정 시작 시점 seq 보다 2 이상 증가한 결과만 사용"),
    ("설계 통신 9개가 모두 시험 환경 안 측정 지점에서 시험돼야 통과", "설계 기준 경로 9개 모두 시험 환경 내부 측정 지점에서 시험되어야 통과"),
    ("이 PC 결과는 참고", "이 PC 결과는 참고용"),
    ("설계도에 없는 통신", "설계 외 허용 경로"),
    ("끊긴 통신", "허용 규칙 없는 필수 통신"),
    ("번째 줄", "행"),
    ("(없는 속성 이름)", "(존재하지 않는 속성 이름)"),
    # plan 확인(plancheck.py) · 반영(testbed_ops.py) 기록
    ("apply 하지 않는다 — ", "차단 (apply 미실행) — "),
    ("apply 해도 된다 — 보안 그룹만 제자리 수정 ", "반영 가능 — 보안 그룹 제자리 수정 "),
    ("이 바뀌어서)", " 변경)"),
    ("바뀌는 것이 없다 — 이미 apply 했거나 배포된 것과 같은 파일이다", "변경 없음 — 이미 반영됨 또는 배포 파일과 동일"),
    ("교체·삭제는 없지만 사람이 plan 을 읽고 판단해야 한다 — ", "교체·삭제 없음 — 사람의 plan 검토 필요: "),
    ("plan 을 만들지 못했다 — ", "plan 생성 실패 — "),
    ("apply 하지 않음 — 교체·삭제가 나옴", "차단 — 교체·삭제 포함"),
    ("apply 해도 됨 — 보안 그룹만 제자리 수정", "반영 가능 — 보안 그룹 제자리 수정만 포함"),
    ("사람이 plan 을 읽고 판단", "사람의 plan 검토 필요"),
    ("바뀌는 것 없음", "변경 없음"),
    ("plan 을 만들지 못함", "plan 생성 실패"),
    ("새로 만듦", "생성"),
    ("원본 apply (배포·되돌리기)", "원본 반영 (apply)"),
    ("후보 apply —", "후보 반영 (apply) —"),
    ("destroy (전부 삭제)", "시험 환경 삭제 (destroy)"),
    # 설계도 기준 구조 검사(topology_oracle) 기록
    ("설계도와 일치 — 설계 통신 ", "설계 기준과 일치 — 정상 통신 경로 "),
    ("개 모두 열림, 설계 밖 통신 없음", "개 모두 허용, 설계 외 허용 경로 없음"),
    ("설계도와 다름 ", "설계 기준과 불일치 "),
    ("판단할 수 없음 — ", "판정 불가 — "),
    ("끊김: ", "허용 규칙 없는 필수 통신: "),
    ("밖이 열려 있습니다", "밖까지 허용"),
    ("열린 대역 ", "허용 대역 "),
    ("설계도에 이 출처의 통신이 없습니다", "설계도에 이 출발지의 통신 없음"),
    ("(합치면 인터넷 전체 0.0.0.0/0)", "(합집합 = 인터넷 전체 0.0.0.0/0)"),
    ("VPC 안 모든 서버", "VPC 내 모든 서버"),
    ("이 열려 있습니다 — IP 대역으로는 계층을 구분할 수 없어 웹·Bastion 등 모든 서버가 들어올 수 있습니다", " 허용 — IP 대역으로는 계층 구분 불가, 웹·Bastion 등 모든 서버 접근 가능"),
    ("설계는 ", "설계 기준은 "),
]


_LEGACY_RE = [
    (re.compile(r" 은\(는\) ([^;]+?)번 포트로 들어올 수 없습니다"), r": \1번 포트 허용 규칙 없음 (필수 통신)"),
    (re.compile(r" 에서 ([^;]+?) 로 가는 ([^;]+?) 규칙이 없습니다"), r" → \1 \2 허용 규칙 없음 (필수 통신)"),
    (re.compile(r" 에 출처를 확정할 수 없는 ([^;]+?) 규칙이 있어 이 통신이 열려 있는지 판단할 수 없습니다"), r" 에 출발지 미확정 \1 규칙 존재 — 이 경로의 허용 여부 판정 불가"),
]


def legacy(text: Any) -> str:
    """저장된 옛 문구를 지금 화면 용어로 (모르는 문구는 그대로)."""
    s = str(text or "")
    for old, new in _LEGACY:
        if old in s:
            s = s.replace(old, new)
    for rx, new in _LEGACY_RE:
        s = rx.sub(new, s)
    return s


# 사전 점검(calibration.json)에 저장된 판정·결과 낱말 → 화면 용어 (저장 값·비교는 그대로)
def cal_verdict(v: Any) -> str:
    s = str(v or "")
    if s == "맞음":
        return "일치"
    if s == "틀림":
        return "불일치"
    if s.startswith("못 잡음"):
        return "미탐지 (알려진 한계 — 이전 측정과 동일)"
    if s.startswith("잡음"):
        return "탐지 (이전 측정과 다름 — 확인 필요)"
    if s.startswith("참고"):
        return "참고 (이 네트워크는 무응답 대신 즉시 오류 반환)"
    return s


def cal_result(r: Any) -> str:
    return {"지적": "탐지", "통과": "미탐지(통과)"}.get(str(r or ""), str(r or ""))
