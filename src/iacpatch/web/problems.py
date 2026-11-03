"""결과 화면의 '발견된 문제' — 무엇이 · 왜 문제인지 · 어떻게 고치는지 (교수 피드백 2026-10-31).

판정 값은 기록(verification.json · policy.json · state.json)을 그대로 쓰고, 여기서는 사람이 읽을 문장만 만든다.
'왜' 의 설계도 근거는 그 기록에 같이 저장한 설계도 사본(input/design.json)을 먼저 쓴다 — 설계도가 나중에 바뀌어도
그 기록은 당시 설계도로 설명한다 (새 설계도 기준 결과가 필요하면 새로 검사한다).
문장은 판정을 바꾸지 않는다. 확인하지 않은 것은 '확인하지 않은 것' 으로 따로 적고, 통과처럼 보이게 쓰지 않는다.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

PORT_NAME = {22: "SSH", 3389: "RDP", 3306: "MySQL", 6379: "Redis", 80: "HTTP", 443: "HTTPS", 5432: "PostgreSQL"}
RULE_KO = {"AVD-AWS-0107": "보안 그룹이 SSH(22) · RDP(3389) 를 인터넷 전체(0.0.0.0/0)에 열어 둠",
           "AVD-AWS-0104": "아웃바운드 통신을 인터넷 전체로 허용", "AVD-AWS-0345": "S3 권한을 무제한(s3:*)으로 줌",
           "AVD-AWS-0342": "역할 전달 권한(iam:PassRole)을 제한 없이 줌"}


_ENV_ERR_RE = re.compile(r"shared config profile|no valid credential|NoCredentialProviders|InvalidClientTokenId|ExpiredToken|"
                         r"failed to refresh cached credentials|could not load credentials|SSO session", re.I)


def _port(p: Any, ctx: str = "") -> str:
    """'22' → 'SSH(22)'. 받는 쪽 이름에 이미 들어 있으면 번호만 ('MySQL 의 3306 포트' — 'MySQL 의 MySQL(3306)' 방지)."""
    s = str(p or "")
    try:
        n = int(s)
    except ValueError:
        return s
    name = PORT_NAME.get(n)
    return f"{name}({n})" if name and name.lower() not in str(ctx).lower() else s


def _has_batchim(word: str) -> Optional[bool]:
    """마지막 글자에 받침이 있는가 (조사 고르기용). 괄호 안 설명은 건너뛴다: '사용자(인터넷)' → '자'. 모르면 None."""
    w = re.sub(r"\([^)]*\)\s*$", "", str(word or "")).strip()
    if not w:
        return None
    c = w[-1]
    if "가" <= c <= "힣":
        return (ord(c) - 0xAC00) % 28 != 0
    if c.isdigit():
        return c in "013678"                      # 영 일 삼 육 칠 팔
    if c.isascii() and c.isalpha():
        return c.lower() in "lmn"                 # MySQL · Bastion 은 받침, ALB · NLB · Redis 는 받침 없음 (읽는 소리 기준 근사)
    return None


def _j(word: Any, pair: str) -> str:
    """단어 + 알맞은 조사. pair: '이가' '을를' '은는' '와과' '으로'. 판단이 안 되면 '이(가)' 처럼 둘 다 적는다."""
    w = str(word or "")
    b = _has_batchim(w)
    if pair == "으로":
        last = re.sub(r"\([^)]*\)\s*$", "", w).strip()[-1:] or " "
        rieul = ("가" <= last <= "힣" and (ord(last) - 0xAC00) % 28 == 8) or last.lower() == "l" or last in "178"   # ㄹ 받침은 '로' (일 · 칠 · 팔)
        return w + ("(으)로" if b is None else "로" if (not b or rieul) else "으로")
    first, second = {"이가": ("이", "가"), "을를": ("을", "를"), "은는": ("은", "는"), "와과": ("과", "와")}[pair]
    return w + (f"{first}({second})" if b is None else first if b else second)


def _labels(design: Optional[Dict[str, Any]]) -> Dict[str, str]:
    d = design or {}
    return {str(x.get("id")): str(x.get("label") or x.get("id")) for x in (d.get("tiers") or []) + (d.get("external") or [])}


def _flow_port(f: Dict[str, Any], ctx: str = "") -> str:
    if f.get("port") is not None:
        return _port(f.get("port"), ctx)
    a, b = f.get("from_port"), f.get("to_port")
    return _port(a, ctx) if a == b else f"{a}-{b}"


def _sg_of(design: Optional[Dict[str, Any]], tier: str) -> str:
    t = next((x for x in (design or {}).get("tiers") or [] if x.get("id") == tier), None)
    return str((t or {}).get("security_group") or "")


def _rule_where(rule: str) -> str:
    """'aws_security_group.db#ingress[1]' → 'aws_security_group.db 의 인바운드 규칙 2번째'."""
    m = re.match(r"^([^#]+)#(ingress|egress)\[(\d+)\]$", rule or "")
    if not m:
        return rule or ""
    return f"{m.group(1)} 의 {'인바운드' if m.group(2) == 'ingress' else '아웃바운드'} 규칙 {int(m.group(3)) + 1}번째"


def _design_name(des: Optional[Dict[str, Any]], design: Optional[Dict[str, Any]]) -> str:
    d = design or {}
    iid = (des or {}).get("intent_id") or d.get("intent_id") or "설계도"
    ver = (des or {}).get("intent_version") or d.get("intent_version") or "?"
    return f"고객 설계도({iid} v{ver})"


def _v6_problems(v6: Dict[str, Any], design: Optional[Dict[str, Any]], dname: str) -> List[Dict[str, Any]]:
    det = v6.get("details") or {}
    labels = _labels(design)
    flows = (design or {}).get("flows") or []
    out: List[Dict[str, Any]] = []
    for e in det.get("excess") or []:
        dst, src = str(e.get("dst") or ""), str(e.get("src") or "")
        dl, sl = str(e.get("dst_label") or dst), str(e.get("src_label") or src)
        port = _port(e.get("ports"), dl)
        allowed = [f"{labels.get(str(f.get('from')), f.get('from'))} → {labels.get(str(f.get('to')), f.get('to'))} {_flow_port(f, dl)}"
                   for f in flows if str(f.get("to")) == dst]
        why = (f"{dname}에서 {_j(dl, '으로')} 들어오는 통신은 {' · '.join(allowed)} 뿐입니다." if allowed
               else f"{dname}에는 {_j(dl, '으로')} 들어오는 통신이 없습니다.")
        if e.get("kind") == "vpc_wide":
            why += " 출발지를 VPC 대역(IP)으로 열면 어느 서버에서 오는지 구분할 수 없어 설계도에 없는 서버도 접근할 수 있습니다."
        elif e.get("kind") == "outside_approved":
            why += " 허용 대역보다 넓게 열려 있습니다."
        sg = _sg_of(design, dst) or str(e.get("rule") or "").split("#")[0]
        where = _rule_where(str(e.get("rule") or ""))
        if e.get("kind") == "undesigned_target":
            # 설계도에 없는 리소스로 들어오는 통신 (D-30) — 설계에서 뺐는데 코드에 남았거나, 처음부터 설계에 없던 리소스
            res = ", ".join((e.get("resources") or [])[:3]) or dl
            out.append({"kind": "design_extra", "layer": "V6", "tag": "설계에 없는 리소스",
                        "what": f"{_j(sl, '이가')} {dl}의 {port} 포트에 접근할 수 있게 허용돼 있습니다.",
                        "why": f"{dname}에 이 리소스({res})가 없습니다. 설계에서 뺐는데 코드에 남아 있거나 설계에 없던 리소스라, 고객이 원하지 않는 통신이 열려 있습니다.",
                        "how": f"이 리소스가 필요하면 설계도에 구성요소로 추가하고(흐름 화면 ① 설계도 바꾸기), 필요 없으면 코드에서 리소스와 보안 그룹({e.get('security_group') or sg}) 규칙을 지운 뒤 다시 검사하세요.",
                        "where": where, "detail": e.get("detail"), "flow": {"src": sl, "dst": dl, "ports": port, "src_id": src, "dst_id": dst,
                                                                         "rule": str(e.get("rule") or "")}})
            continue
        if src in labels and src not in ("internet", "admin"):
            how = f"{dl} 보안 그룹({sg})에서 {sl}에서 오는 {port} 허용 규칙을 지우고 다시 검사하세요."
        else:
            how = (f"{dl} 보안 그룹({sg})의 {port} 규칙 출발지를 설계도가 허용한 대상으로 좁히고 다시 검사하세요"
                   + (f" (허용: {' · '.join(allowed)})." if allowed else "."))
        out.append({"kind": "design_extra", "layer": "V6", "tag": "고객 설계에 없는 통신",
                    "what": f"{_j(sl, '이가')} {dl}의 {port} 포트에 접근할 수 있게 허용돼 있습니다.",
                    "why": why, "how": how, "where": where, "detail": e.get("detail"),
                    "flow": {"src": sl, "dst": dl, "ports": port, "src_id": src, "dst_id": dst, "rule": str(e.get("rule") or "")}})
    for f in det.get("flows") or []:
        if f.get("status") != "broken":
            continue
        dl, sl = str(f.get("dst_label") or f.get("dst")), str(f.get("src_label") or f.get("src"))
        port = _port(f.get("ports"), dl)
        out.append({"kind": "design_missing", "layer": "V6", "tag": "허용 규칙 없는 필수 통신",
                    "what": f"{sl} → {dl} {port} 통신을 허용하는 보안 그룹 규칙이 없습니다.",
                    "why": f"{dname}에 있는 통신({f.get('label') or ''})이라 서비스나 관리 접속에 필요합니다. 규칙 기준 판정이며, 실제 연결은 AWS 시험 환경 검사(V8)에서 확인합니다.",
                    "how": f"{dl} 보안 그룹({_sg_of(design, str(f.get('dst')))})에 {sl}에서 오는 {port} 인바운드 규칙을 되돌리고 다시 검사하세요.",
                    "where": "", "detail": "; ".join(f.get("reasons") or [])[:200],
                    "flow": {"src": sl, "dst": dl, "ports": port, "src_id": f.get("src"), "dst_id": f.get("dst"), "missing": True}})
    return out


def _policy_reason(v: str) -> tuple:
    """정책 확인 위반 하나 → (kind, tag, why, how). 위반 종류마다 이유가 다르다."""
    if v.startswith("exec_guard:"):
        return ("unsafe_code", "실행 전 안전 점검",
                "이 PC 에서 파일을 읽거나 외부에서 코드를 내려받을 수 있는 구문이라, Trivy · Terraform 을 실행하지 않고 멈췄습니다.",
                "그 구문을 빼고 다시 제출하세요.")
    if v.startswith("forbidden_tokens:"):
        return ("unsafe_code", "금지 코드",
                "provisioner · local-exec 같은 코드는 terraform 을 실행하는 PC 에서 명령을 실행할 수 있어 팀 정책이 금지합니다.",
                "그 코드를 빼고 다시 제출하세요.")
    if v.startswith(("file_count", "file_exists", "path_", "file_protected", "file_size")):
        return ("policy", "허용 파일 밖 수정", "팀 정책은 정해진 파일만, 정해진 개수 안에서 고치도록 허용합니다 (새 파일 · 변경 금지 파일 · 다른 폴더 불가).",
                "보안 문제가 있는 파일만 고쳐 다시 제출하세요.")
    if v.startswith("protected_blocks"):
        return ("policy", "설정 블록 변경", "terraform · provider 설정 블록은 검사 환경과 배포 대상을 바꿀 수 있어 수정 코드에서 바꿀 수 없습니다.",
                "설정 블록을 원래대로 두고 다시 제출하세요.")
    if v.startswith("diff_nonempty"):
        return ("policy", "변경 없음", "원본과 내용이 같아 검사할 수정이 없습니다.", "고친 파일을 제출하세요.")
    return ("policy", "허용 범위 밖 수정", "팀 정책은 정해진 리소스 종류 · 속성만 바꾸도록 허용합니다 (교체 · 삭제 · 허용 밖 리소스 생성 금지).",
            "허용 범위 밖의 변경을 되돌리고 다시 제출하세요.")


def problems(st: Dict[str, Any], ver: Optional[Dict[str, Any]], pol: Optional[Dict[str, Any]],
             design: Optional[Dict[str, Any]], design_rec: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """기록 하나의 문제 목록 (화면용). 통과한 기록이면 빈 목록."""
    from ..proof.cards import policy_ko
    dname = _design_name(design_rec, design)
    out: List[Dict[str, Any]] = []
    state = str(st.get("state") or "")
    if state == "POLICY_BLOCKED" or (pol and pol.get("ok") is False):
        for v in (pol or {}).get("violations") or []:
            kind, tag, why, how = _policy_reason(str(v))
            out.append({"kind": kind, "layer": "정책", "tag": tag, "what": policy_ko(v), "why": why, "how": how,
                        "where": "", "detail": str(v)[:200], "flow": None})
        return out
    if state in ("CANDIDATE_INVALID", "INFO_INSUFFICIENT", "INPUT_ERROR", "NO_FINDING", "AMBIGUOUS_FINDING"):
        from ..proof.plain import legacy
        msg = "; ".join(legacy(x) for x in st.get("errors") or [])[:300]
        out.append({"kind": "input", "layer": "입력", "tag": "검사 시작 불가", "what": msg or "검사를 시작하지 못했습니다.",
                    "why": "검사할 코드나 입력이 조건에 맞지 않습니다.", "how": "제출 파일 · 입력을 확인하고 다시 검사하세요.", "where": "", "detail": "", "flow": None})
        return out
    layers = {str(l.get("layer")): l for l in (((ver or {}).get("report") or {}).get("layers") or [])}
    v1 = layers.get("V1") or {}
    if v1.get("verdict") == "FAIL":
        m = re.search(r"(AVD-AWS-\d+)\D+(aws_[A-Za-z0-9_.]+)", str(v1.get("summary") or ""))
        rid, res = (m.group(1), m.group(2)) if m else ("", "")
        out.append({"kind": "old_issue", "layer": "V1", "tag": "기존 보안 문제 남음",
                    "what": f"Trivy 가 지적한 문제가 수정 후에도 남아 있습니다: {RULE_KO.get(rid, rid)} ({res}).",
                    "why": "이번 수정의 목적이 이 문제를 없애는 것입니다. 남아 있으면 수정이 목적을 이루지 못한 것입니다.",
                    "how": f"{res} 의 해당 규칙을 {_j(dname, '이가')} 허용한 대상으로 좁히고 다시 검사하세요.", "where": res, "detail": v1.get("summary"), "flow": None})
    v2 = layers.get("V2") or {}
    if v2.get("verdict") == "FAIL":
        for n in ((v2.get("details") or {}).get("new") or [])[:5]:
            out.append({"kind": "new_issue", "layer": "V2", "tag": "새 보안 문제",
                        "what": f"수정 후 새로 생긴 문제: {RULE_KO.get(str(n.get('rule_id')), n.get('title') or n.get('rule_id'))} ({n.get('resource')}, {n.get('filename')} {n.get('start_line')}행).",
                        "why": f"Trivy 심각도 {n.get('severity')} — 수정하면서 원래 없던 보안 문제를 만들었습니다.",
                        "how": f"{n.get('filename')} {n.get('start_line')}행 부근의 새 설정을 되돌리거나 허용 대상으로 좁히고 다시 검사하세요.",
                        "where": f"{n.get('filename')}:{n.get('start_line')}", "detail": n.get("message"), "flow": None})
    v3 = layers.get("V3") or {}
    if v3.get("verdict") == "FAIL":
        from ..proof.plain import tf_error_ko
        for dgn in ((v3.get("details") or {}).get("diagnostics") or [])[:3]:
            rng = (dgn.get("range") or {})
            loc = f"{rng.get('filename')} {((rng.get('start') or {}).get('line'))}행" if rng else ""
            out.append({"kind": "code_error", "layer": "V3", "tag": "코드 작성 오류",
                        "what": f"Terraform 코드 오류: {tf_error_ko(str(dgn.get('summary') or '') + ' ' + str(dgn.get('detail') or ''))}" + (f" ({loc})" if loc else ""),
                        "why": "코드가 Terraform 문법 · 참조 규칙에 맞지 않아 실행 계획을 만들 수 없습니다. 이후 검사는 진행하지 않았습니다.",
                        "how": f"{_j(loc, '을를') if loc else '오류 위치를'} 고치고 다시 검사하세요. 오류 원문은 V3 증거에 있습니다.", "where": loc, "detail": dgn.get("detail"), "flow": None})
    v4 = layers.get("V4") or {}
    if v4.get("verdict") == "FAIL":
        summ = str(v4.get("summary") or "")
        from ..proof.plain import tf_error_ko      # 영어 오류 → 한 줄 요약 (원문은 V4 증거 카드에 그대로)
        env = bool(_ENV_ERR_RE.search(summ))       # 코드가 아니라 이 PC 의 검사 환경(AWS 설정 · 자격 증명) 문제로 보이는 오류
        out.append({"kind": "env_error" if env else "plan_error", "layer": "V4", "tag": "검사 환경 오류" if env else "변경 예정 계산 실패",
                    "what": f"실행 계획(plan)을 만들 수 없습니다: {tf_error_ko(summ)}",
                    "why": ("오류 문구가 AWS 설정 · 자격 증명을 가리킵니다. 제출한 코드가 아니라 검사 환경 문제일 수 있습니다. "
                            "plan 을 못 만들면 허용 범위 · 설계 일치 검사를 할 수 없습니다.") if env
                           else "무엇이 바뀌는지 계산할 수 없으면 허용 범위 · 설계 일치 검사를 할 수 없습니다.",
                    "how": ("코드를 고치기 전에 검사 환경을 확인하세요 (배포 전 검사는 AWS 접속 없이 돌아야 합니다). 확인 후 같은 코드로 다시 검사하세요." if env
                            else "오류 문구에 나온 값(예: 기본값 없는 변수)을 정하거나 코드를 고치고 다시 검사하세요."),
                    "where": "", "detail": v4.get("summary"), "flow": None})
    v5 = layers.get("V5") or {}
    if v5.get("verdict") == "FAIL":
        from ..proof.cards import V5_REPLACE, V5_SCOPE, violation_kind, violation_ko
        for v in ((v5.get("details") or {}).get("violations") or [])[:4]:
            rep = violation_kind(v) == V5_REPLACE
            txt = violation_ko(v, None)
            txt = txt.split(" · ", 1)[1] if txt.startswith((V5_SCOPE + " · ", V5_REPLACE + " · ")) else txt   # 구분은 tag 에 있음
            out.append({"kind": "scope", "layer": "V5", "tag": "교체 · 삭제 위험" if rep else "허용 범위 밖 수정",
                        "what": txt,
                        "why": ("실행 계획(plan)에 리소스 교체(삭제 후 재생성) · 삭제가 있습니다. 운영 중인 서비스가 끊기거나 연결된 서버에서 보안 그룹이 빠질 수 있어 자동 처리 대상에서 막습니다."
                                if rep else "팀 정책은 보안 그룹 · IAM 의 정해진 속성만, 정해진 개수 안에서 바꾸도록 허용합니다. 보안 문제와 관계없는 변경은 검토 범위를 넓혀 막습니다."),
                        "how": "보안 문제와 관계없는 변경을 되돌리고 다시 검사하세요." if not rep
                               else "교체 · 삭제가 생기지 않게 (예: 이름 · 설명 등 교체를 부르는 속성은 그대로 두고) 규칙만 고쳐 다시 검사하세요.",
                        "where": "", "detail": str(v), "flow": None})
    v6 = layers.get("V6") or {}
    if v6.get("verdict") in ("FAIL", "UNKNOWN") and isinstance(v6.get("details"), dict):
        if (v6.get("details") or {}).get("kind") == "topology":
            out += _v6_problems(v6, design, dname)
        if v6.get("verdict") == "UNKNOWN":
            out.append({"kind": "unknown", "layer": "V6", "tag": "판정 불가", "what": f"설계 일치를 판정하지 못했습니다: {str(v6.get('summary') or '')[:160]}",
                        "why": "plan 시점에 값이 정해지지 않은 출발지(변수 · prefix list 등)는 통과로 치지 않습니다.",
                        "how": "값을 코드에 확정하거나 사람이 직접 확인하세요.", "where": "", "detail": "", "flow": None})
        elif not out and v6.get("verdict") == "FAIL":
            out.append({"kind": "design", "layer": "V6", "tag": "고객 설계 불일치", "what": str(v6.get("summary") or "")[:200],
                        "why": f"{_j(dname, '와과')} 보안 그룹 규칙이 다릅니다.", "how": "요구사항 표의 위반 항목을 고치고 다시 검사하세요.", "where": "", "detail": "", "flow": None})
    return out


def unchecked(intent_kind: Optional[str], post_status: Optional[str], testbed: Optional[bool] = None, auto_design: bool = False) -> List[str]:
    """이번 결과가 확인하지 '않은' 것 — 통과처럼 보이지 않게 따로 적는다. testbed=False: 실제 AWS 시험 환경이 없는 프로젝트.
    auto_design: 이 기록의 설계도가 자동 기준(지금 코드 − 위험한 통신, D-33) — 고객이 확인한 구조가 아님."""
    out = ["Trivy 규칙에 없는 보안 문제 (Trivy 가 아는 규칙만 찾음)"]
    if auto_design:
        out.insert(0, "고객이 원하는 구조 — 이 검사의 기준은 자동 기준(지금 코드 − 위험한 통신)이라 고객이 확인한 구조가 아님 "
                      "(③ 에서 사람이 확인 · 수정하면 그 버전으로 다시 검사)")
    if intent_kind == "topology":
        out.append("보안 그룹 아웃바운드(egress) · NACL · 라우팅 — 고객 설계 비교(V6)는 인바운드 규칙만 봄")
    if not post_status:
        out.append("AWS 에서의 실제 연결 · 차단 — 이 프로젝트는 AWS 시험 환경이 없어 확인하지 않음 (V7 · V8 없음)" if testbed is False
                   else "AWS 에서의 실제 연결 · 차단 — AWS 시험 환경 검사(V7 · V8) 전")
    out.append("S3 · IAM 등 보안 그룹 밖 리소스의 고객 설계 일치 (Trivy 기본 검사만 함)" if intent_kind == "topology"
               else "보안 그룹 · IAM 밖 리소스의 요구사항 일치 (Trivy 기본 검사만 함)")
    out.append("운영 AWS 계정 — 이 프로그램은 시험 환경만 다룸")
    return out
