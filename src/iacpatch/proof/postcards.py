"""실제 AWS 검사 증거 카드 — 시험 환경 반영(apply) · V7 · V8. 측정 기록(measure.json)을 읽어 1차 카드와 같은 모양으로 만든다.

측정 기록 위치
  수정 후 (후보)  data/reviews/<기록>/postdeploy/<시각>/measure.json   (run_measure 가 기록에 연결)
  수정 전 (원본)  data/measurements/<시각>/measure.json                (기록과 무관한 기준 측정)
판정은 measure.json 의 값만 쓴다.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..evidence_log import load_commands, sha256_file
from . import plain, primary, standards
from .cards import HOW, LAYER_NAMES

ACCOUNT_RE = re.compile(r"\b\d{12}\b")
VKO = {"PASS": "통과", "FAIL": "실패", "UNKNOWN": "판정 불가", "NOT_RUN": "미실행", "SKIPPED": "건너뜀", "ERROR": "오류", "INFO": "참고"}
# 측정 기록(measure.json)의 설계 경로 상태 값 → 화면 용어. 기록 값은 그대로 두고(비교·색은 원래 값으로) 표시할 때만 바꾼다.
FLOW_ST = {"열림 확인": "접속 성공 확인", "끊김": "접속 실패 (필수 통신 안 됨)", "측정 못 함": "미측정 (판정 불가)"}


def _flow_st(s: Any) -> str:
    t = str(s or "")
    if t in FLOW_ST:
        return FLOW_ST[t]
    if t.startswith("끊김 의심"):
        return "판정 불가 — 경로 시험 실패 (실패 구간 미확정)"
    return t


def mask_account(s: str) -> str:
    """AWS 계정 번호(12자리)를 화면·보고서에 내보내지 않는다."""
    return ACCOUNT_RE.sub("############", s or "")


def _j(p: Path) -> Optional[Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _latest(dirs: List[Path]) -> Optional[Path]:
    hits = sorted([d for d in dirs if (d / "measure.json").exists()], key=lambda d: d.name)
    return hits[-1] if hits else None


def find_measurements(record_dir: Path, root: Path) -> Dict[str, Optional[Path]]:
    after = _latest([d for d in (record_dir / "postdeploy").glob("*") if d.is_dir()]) if (record_dir / "postdeploy").is_dir() else None
    base_root = root / "data" / "measurements"
    before = _latest([d for d in base_root.glob("*") if d.is_dir()]) if base_root.is_dir() else None
    return {"after": after, "before": before}


def _layer(doc: Optional[Dict[str, Any]], k: str) -> Dict[str, Any]:
    return next((l for l in (doc or {}).get("layers") or [] if l.get("layer") == k), {})


def _cmd_rows(d: Optional[Path]) -> List[Dict[str, Any]]:
    if d is None:
        return []
    rows = []
    for c in load_commands(d / "commands.json"):
        argv = [mask_account(str(a)) for a in (c.get("argv") or [])]
        if argv:
            argv[0] = re.split(r"[\\/]", argv[0])[-1]
        rows.append({"step": c.get("step"), "cmd": " ".join(argv) if argv else None, "started_at": c.get("started_at"), "elapsed_s": c.get("elapsed_s"),
                     "returncode": c.get("returncode"), "ok": c.get("ok"), "note": plain.legacy(mask_account(c.get("note") or "")),
                     "stderr_tail": mask_account(c.get("stderr_tail") or "")[-400:], "cached": False})
    return rows


def _base(layer: str, name: str, q: str, how: str = "") -> Dict[str, Any]:
    return {"layer": layer, "name": name, "question": q, "how": how, "verdict": None, "verdict_ko": None, "summary": "", "record_summary": "", "status": "pending",
            "method": {"steps": [], "commands": []}, "evidence": [], "basis": {"standard": [], "team": [], "tool": [], "cross": []},
            "reason": "", "limits": [], "leaves": []}


def _excess_key(e: Dict[str, Any]) -> str:
    # 출발지 이름은 옛 기록 문구도 지금 용어로 맞춰 비교한다 (빌드가 달라도 같은 경로끼리 짝지음)
    return f"{plain.legacy(e.get('src_label'))} → {e.get('dst_label')} {e.get('ports')}"


def _flow_text(e: Dict[str, Any]) -> str:
    """'웹 서버 → MySQL (MySQL 3306)'."""
    return f"{plain.legacy(e.get('src_label'))} → {e.get('dst_label')} ({plain.port_text(e.get('ports'))})"


def _aws_rule_text(rule: Any, root: Optional[Path]) -> str:
    """'aws_security_group.bastion (sg-0a5f…) ingress[0]' → 'Bastion 보안 그룹 sg-0a5f… · 인바운드 규칙 #1'."""
    t = mask_account(str(rule or ""))
    m = re.match(r"^(aws_security_group\.\S+)\s*(?:\((sg-[0-9a-f]+)\))?\s*(ingress|egress)\[(\d+)\]$", t)
    if not m:
        return t
    way = "인바운드" if m.group(3) == "ingress" else "아웃바운드"
    sgid = f" {m.group(2)}" if m.group(2) else ""
    return f"{plain.sg(m.group(1), root)}{sgid} · {way} 규칙 #{int(m.group(4)) + 1}"


def card_v7(rec_v6: Dict[str, Any], after: Optional[Dict[str, Any]], before: Optional[Dict[str, Any]], adir: Optional[Path], bdir: Optional[Path],
            root: Optional[Path] = None) -> Dict[str, Any]:
    c = _base("V7", LAYER_NAMES["V7"][0], LAYER_NAMES["V7"][1], HOW["V7"])
    c["method"]["steps"] = ["시험 환경 폴더의 상태 파일에서 보안 그룹 주소 → GroupId 확인 (terraform show -json, AWS 변경 없음)",
                            "aws ec2 describe-security-groups — AWS 적용 규칙 직접 조회 (읽기 전용)",
                            "aws ec2 describe-network-interfaces — 보안 그룹이 연결된 서버·로드밸런서 확인",
                            "AWS 조회 값으로 설계 기준 비교 재계산 (V6 와 같은 계산, 입력만 plan → AWS)"]
    doc = after or before
    if doc is None:
        c["reason"] = "측정 기록 없음 — 시험 환경 배포 후 측정 시 생성"
        c["limits"] = ["보안 그룹 규칙만 확인 — 실제 통신 여부는 V8"]
        return c
    c["method"]["commands"] = _cmd_rows(adir if after else bdir)
    l7 = _layer(doc, "V7")
    v = l7.get("verdict")
    c["verdict"], c["verdict_ko"], c["status"] = v, VKO.get(str(v), v), "done" if v else "pending"
    det = l7.get("details") or {}
    flows, ex = det.get("flows") or [], det.get("excess") or []
    st_ko = {"ok": "허용", "broken": "허용 규칙 없음", "unknown": "판정 불가"}
    ident = doc.get("identity") or {}
    c["evidence"].append({"t": "kv", "title": "측정 대상" + (" · 수정 후" if after else " · 수정 전"), "rows": [
        ["측정 시각", doc.get("started_at", "")], ["리전", doc.get("region", "")],
        ["시험 환경 보안 그룹 파일 지문 (sha256)", (ident.get("testbed_security_groups_sha256") or "?")[:16] + "…"],
        ["동일 내용 파일", ", ".join(_neutral_matches(ident.get("matches"))) or "없음 (원본·후보와 모두 다름)"],
        ["확인한 AWS 보안 그룹", f"{len((doc.get('state') or {}).get('sg_ids') or {})}개 (상태 파일에서 ID 확인)"]]})
    if flows:
        c["evidence"].append({"t": "table", "title": f"설계 기준 경로 {len(flows)}개 (AWS 적용 규칙 기준 계산)", "head": ["경로", "포트", "결과"],
                              "rows": [[f"{f.get('src_label')} → {f.get('dst_label')}", plain.port_text(f.get("ports")), st_ko.get(f.get("status"), f.get("status"))] for f in flows],
                              "tones": ["good" if f.get("status") == "ok" else "bad" if f.get("status") == "broken" else "warn" for f in flows]})
    c["evidence"].append({"t": "table", "title": "설계 외 허용 경로 (AWS 적용 규칙)", "head": ["경로", "포트", "불일치 내용", "AWS 규칙"],
                          "rows": [[f"{plain.legacy(e.get('src_label'))} → {e.get('dst_label')}", plain.port_text(e.get("ports")), plain.legacy(e.get("detail", "")), _aws_rule_text(e.get("rule"), root)] for e in ex],
                          "empty": "없음 — 설계 외 허용 경로 0개", "tone": "bad" if ex else "good"})
    rules = det.get("rules") or {}
    rr = []
    for addr, lst in sorted(rules.items()):
        for r in lst:
            rr.append([plain.server(addr, root), plain.port(r.get("protocol"), r.get("from_port"), r.get("to_port")),
                       mask_account(plain.sources([str(x) for x in r.get("sources") or []], root))])
    if rr:
        c["evidence"].append({"t": "table", "title": "AWS 적용 인바운드 규칙 (describe-security-groups)", "head": ["보안 그룹", "포트", "허용 출발지"], "rows": rr})
    if before is not None and after is not None:
        bx = {_excess_key(e): e for e in (_layer(before, "V7").get("details") or {}).get("excess") or []}
        ax = {_excess_key(e): e for e in ex}
        rows = [[_flow_text(bx.get(k) or ax.get(k) or {}), "허용" if k in bx else "없음", "허용" if k in ax else "없음"] for k in sorted(set(bx) | set(ax))]
        c["evidence"].append({"t": "table", "title": "수정 전 → 수정 후 (설계 외 허용 경로)", "head": ["경로", "수정 전", "수정 후"], "rows": rows,
                              "tones": ["bad" if k in ax else "good" for k in sorted(set(bx) | set(ax))], "empty": "수정 전·후 모두 없음"})
    # 교차 확인: V6(plan 계산) 과 V7(AWS 값) 의 '설계 외 허용 경로' 가 같은가
    if rec_v6 and after is not None:
        p6 = {_excess_key(e) for e in (rec_v6.get("details") or {}).get("excess") or []}
        a7 = {_excess_key(e) for e in ex}
        c["basis"]["cross"].append({"k": "V6 (코드·plan 계산) ↔ V7 (AWS 실제 값)",
                                    "v": ("일치" if p6 == a7 else "불일치") + f" — V6 {len(p6)}건 / V7 {len(a7)}건"
                                         + (f" · V6 에만: {', '.join(sorted(p6 - a7))}" if p6 - a7 else "") + (f" · V7 에만: {', '.join(sorted(a7 - p6))}" if a7 - p6 else ""),
                                    "same": p6 == a7})
    if flows:
        c["diagram"] = {"flows": {f.get("id"): f.get("status") for f in flows if f.get("id")},
                        "excess": [{k: e.get(k) for k in ("src", "dst", "ports", "src_label", "dst_label", "kind", "detail")} for e in ex]}
    c["basis"]["team"].append({"k": "설계도 파일", "v": standards.TEAM_REQUIREMENTS["design"]["file"]})
    c["basis"]["tool"].append({"k": "AWS CLI", "v": "describe-security-groups · describe-network-interfaces (읽기 전용 API)"})
    broken = [f for f in flows if f.get("status") == "broken"]
    if v == "PASS":
        c["summary"] = f"설계 기준과 일치 — AWS 적용 규칙 기준 정상 통신 경로 {len(flows)}개 모두 허용 · 설계 외 허용 경로 0개"
    else:
        parts = []
        if ex:
            parts.append(f"AWS 적용 규칙에 설계 외 허용 경로 {len(ex)}개 ({_flow_text(ex[0])}" + (f" 외 {len(ex) - 1}개" if len(ex) > 1 else "") + ")")
        if broken:
            parts.append(f"허용 규칙 없는 필수 통신 {len(broken)}개 ({broken[0].get('src_label')} → {broken[0].get('dst_label')})")
        c["summary"] = ("설계 기준과 불일치 — " if v == "FAIL" else "판정 불가 — ") + (" · ".join(parts) or plain.legacy(l7.get("summary") or ""))
    c["reason"] = plain.legacy(mask_account(l7.get("summary") or ""))
    c["record_summary"] = c["reason"]
    c["limits"] = ["보안 그룹 규칙만 확인 — 실제 통신 여부는 V8",
                   "축소 시험 환경: 보안 그룹 파일은 원본과 동일, 서버·DB 는 대체 프로그램(stand-in), NAT·CloudFront·RDS·ElastiCache 미포함"]
    c["leaves"] = [{"path": str(Path("postdeploy" if after else "data/measurements") / ((adir or bdir).name) / n).replace("\\", "/"), "bytes": None, "sha256": None}
                   for n in ("measure.json", "aws_raw.json", "commands.json")]
    return c


def card_v8(after: Optional[Dict[str, Any]], before: Optional[Dict[str, Any]], adir: Optional[Path], bdir: Optional[Path],
            root: Optional[Path] = None) -> Dict[str, Any]:
    c = _base("V8", LAYER_NAMES["V8"][0], LAYER_NAMES["V8"][1], HOW["V8"])
    c["method"]["steps"] = [
        "설계도에서 허용 경로(화살표 9개)와 차단 경로(그 외)를 정의 — 후보 파일과 무관",
        "시험 환경 내부 측정 지점 5곳(웹·API·Bastion·관리자 지점·인터넷 지점)이 목적지별 TCP 연결을 시도하고 결과를 직렬 콘솔에 기록 (1회 순회 후 15초 대기 반복 — 1회 약 20~30초)",
        "aws ec2 get-console-output --latest (읽기 전용)로 결과 수집. 웹·API 결과는 ALB → 웹, 웹 → NLB → API HTTP 경로로도 수집",
        "apply 완료 2분 후부터 측정 가능. 측정 시작 시점의 결과 번호(seq)보다 2 이상 증가한 결과만 사용 — "
        "사용하는 시험은 apply 완료 '135초 − 콘솔 지연' 이후 시작된 것 (콘솔 지연 실측 20~40초)",
        "판정: 허용 경로 = 접속 성공(open)만 통과 / 차단 경로 = 응답 없음(timeout)만 통과, 접속 성공(open)은 실패, 연결 거부(refused)·오류는 판정 불가 / 설계 기준 경로 9개 모두 시험되어야 통과",
        "이 PC 에서 한 연결 시험은 참고용 (학교망 방화벽·프록시 영향 배제 불가)",
    ]
    doc = after or before
    if doc is None:
        c["reason"] = "측정 기록 없음"
        return c
    c["method"]["commands"] = [x for x in _cmd_rows(adir if after else bdir)
                               if str(x.get("step", "")).startswith(("http:", "tcp:", "aws:ec2 get-console-output"))]
    l8 = _layer(doc, "V8")
    v = l8.get("verdict")
    c["verdict"], c["verdict_ko"], c["status"] = v, VKO.get(str(v), v), "done" if v else "pending"
    det = l8.get("details") or {}
    checks = det.get("checks") or []
    main = [x for x in checks if x.get("role", "주") == "주"]
    ref = [x for x in checks if x.get("role") == "참고"]
    exp_ko = {"open": "접속 성공 기대", "closed": "접속 차단 기대", "?": "?"}
    when = " · 수정 후" if after else " · 수정 전"
    flows = det.get("flows") or []
    nm = det.get("not_measured") or []
    # 요약: 허용 경로 시험 중 접속 성공 수, 차단 경로 시험 중 접속 차단 수
    eo = [x for x in main if x.get("expect") == "open"]
    ec = [x for x in main if x.get("expect") == "closed"]
    unk = [x for x in main if x.get("verdict") not in ("PASS", "FAIL")]
    n_eo = sum(1 for x in eo if x.get("verdict") == "PASS")
    n_ec = sum(1 for x in ec if x.get("verdict") == "PASS")
    tiles = [{"label": "허용 경로 시험", "value": f"{n_eo}/{len(eo)} 접속 성공", "tone": "good" if eo and n_eo == len(eo) else "bad"},
             {"label": "차단 경로 시험", "value": f"{n_ec}/{len(ec)} 접속 차단", "tone": "good" if ec and n_ec == len(ec) else "bad"}]
    if unk:
        tiles.append({"label": "판정 불가 시험", "value": f"{len(unk)}건", "tone": "warn"})
    if nm:
        tiles.append({"label": "미측정 설계 경로", "value": f"{len(nm)}개", "tone": "warn"})
    c["evidence"].append({"t": "stats", "title": "요약" + when, "items": tiles})
    vt = det.get("vantages") or []
    if vt:
        c["evidence"].append({"t": "table", "title": "측정 지점 5곳" + when,
                              "head": ["측정 지점", "수집 경로", "결과 번호 (시작 시 → 사용 값)", "측정 시각 (서버 시계, UTC)", "신규 측정값", "오류"],
                              "rows": [[x.get("label"), x.get("channel") or "-", f"{x.get('base_seq') if x.get('base_seq') is not None else '-'} → {x.get('seq') if x.get('seq') is not None else '-'}",
                                        x.get("at") or "-", {True: "예", False: "아니오"}.get(x.get("fresh"), "-"),
                                        mask_account("; ".join(x.get("errors") or [])) or ""] for x in vt],
                              "tones": ["good" if x.get("fresh") else "bad" for x in vt]})
    odd = [x for x in main if x.get("verdict") != "PASS"]
    if odd:
        c["evidence"].append({"t": "table", "title": f"기대 결과와 다른 시험 {len(odd)}건" + when, "head": ["출발지 → 목적지", "포트", "기대", "결과", "판정"],
                              "rows": [[f"{x.get('from_label')} → {x.get('to_label')}", plain.port_text(x.get("port")), exp_ko.get(x.get("expect"), x.get("expect")),
                                        plain.probe_result(x.get("result")), VKO.get(x.get("verdict"), x.get("verdict"))] for x in odd],
                              "tones": ["bad" if x.get("verdict") == "FAIL" else "warn" for x in odd]})
    c["evidence"].append({"t": "table", "title": f"통신 시험 {len(main)}건" + when,
                          "head": ["출발지 → 목적지", "포트", "기대", "결과", "판정", "근거"],
                          "rows": [[f"{x.get('from_label')} → {x.get('to_label')}", plain.port_text(x.get("port")), exp_ko.get(x.get("expect"), x.get("expect")),
                                    plain.probe_result(x.get("result")) + (f" ({x.get('ms')}ms)" if x.get("ms") is not None else "") + (f" · {x.get('banner')}" if x.get("banner") else "")
                                    + (f" · {x.get('detail')}" if x.get("detail") else ""),
                                    VKO.get(x.get("verdict"), x.get("verdict")), plain.legacy(x.get("why", "") + (f" — {x.get('reason')}" if x.get("verdict") != "PASS" else ""))]
                                   for x in main],
                          "tones": ["good" if x.get("verdict") == "PASS" else "bad" if x.get("verdict") == "FAIL" else "warn" for x in main]})
    if flows:
        c["evidence"].append({"t": "table", "title": "설계 기준 경로 9개 — 실제 시험 확인 여부",
                              "head": ["경로", "상태", "확인 시험"],
                              "rows": [[f.get("label"), _flow_st(f.get("status")),
                                        ", ".join(f"{checks[i].get('from_label', '').split(' (')[0]} → {checks[i].get('to_label')} {checks[i].get('port')}"
                                                  for i in (f.get("rows") or []) if 0 <= i < len(checks)) or "-"] for f in flows],
                              "tones": ["good" if f.get("status") == "열림 확인" else "warn" if f.get("status") == "측정 못 함" else "bad" for f in flows]})
    if before is not None and after is not None:
        def key(x: Dict[str, Any]) -> Any:
            return (x.get("from"), x.get("to"), x.get("port"), x.get("kind", "tcp"))
        bmap = {key(x): x for x in (_layer(before, "V8").get("details") or {}).get("checks") or [] if x.get("role", "주") == "주"}
        rows = []
        for x in main:
            b = bmap.get(key(x))
            if b and (b.get("result") != x.get("result") or b.get("verdict") != x.get("verdict")):
                rows.append([f"{x.get('from_label')} → {x.get('to_label')} ({plain.port_text(x.get('port'))})",
                             f"{plain.probe_result(b.get('result'))} — {VKO.get(b.get('verdict'), '')}",
                             f"{plain.probe_result(x.get('result'))} — {VKO.get(x.get('verdict'), '')}"])
        c["evidence"].append({"t": "table", "title": "수정 전 → 수정 후 결과 변화", "head": ["시험", "수정 전", "수정 후"], "rows": rows, "empty": "변화 없음",
                              "tones": ["good" if "통과" in r[2] else "bad" for r in rows]})
    c["evidence"].append({"t": "table", "title": "미측정 설계 경로", "head": ["경로", "사유"], "rows": [[n.get("label"), plain.legacy(n.get("why"))] for n in nm], "empty": "없음 — 9개 모두 시험 완료"})
    if ref:
        c["evidence"].append({"t": "table", "title": "참고 — 이 PC 에서 수행한 시험 (판정 제외)", "head": ["시험", "포트", "결과", "비고"],
                              "rows": [[f"{x.get('from_label')} → {x.get('to_label')}", plain.port_text(x.get("port")),
                                        plain.probe_result(x.get("result")) + (f" · {x.get('detail')}" if x.get("detail") else ""), plain.legacy(x.get("reason", ""))] for x in ref]})
    c["evidence"].append({"t": "kv", "title": "측정 진행", "rows": [["대기 시간", f"{det.get('waited_s')}초" if det.get("waited_s") is not None else "-"],
                                                                 ["결과 조회 횟수", str(det.get("rounds") or "-")],
                                                                 ["전제", plain.legacy(det.get("assumption") or "-")]]})
    c["basis"]["team"].append({"k": "기대값 출처", "v": "설계도 파일의 설계 기준 경로 9개 (" + standards.TEAM_REQUIREMENTS["design"]["file"] + ")"})
    c["basis"]["tool"].append({"k": "판정 규칙", "v": plain.legacy(det.get("rule") or "")})
    c["basis"]["tool"].append({"k": "규칙 확인", "v": "배포 전 검사 0단계(검증 도구 사전 점검)의 통신 시료: 열린 포트 → open, 닫힌 포트 → refused, 무응답 주소 → timeout"})
    c["basis"]["tool"].append({"k": "결과 수집 경로", "v": "EC2 직렬 콘솔 출력 (get-console-output --latest, Nitro 인스턴스) — 보안 그룹 추가 개방 없이 조회"})
    n_fail = sum(1 for x in main if x.get("verdict") == "FAIL")
    if v == "PASS":
        # 허용·차단 경로별 수는 바로 아래 '요약' 칸에 — 요약 한 줄은 짧게
        c["summary"] = f"통신 시험 {len(main)}건 모두 기대 결과와 일치"
    elif v == "FAIL":
        first = next((x for x in main if x.get("verdict") == "FAIL"), {})
        c["summary"] = (f"통신 시험 {len(main)}건 중 {n_fail}건 기대 결과와 다름 (예: {first.get('from_label')} → {plain.flow_port(first.get('to_label'), first.get('port'))}: "
                        f"{plain.probe_result(first.get('result'))} — {exp_ko.get(first.get('expect'), '')})")
    else:
        c["summary"] = (f"판정 불가 — 통신 시험 {len(main)}건 중 {len(unk)}건 판정 불가" + (f" · 미측정 설계 경로 {len(nm)}개" if nm else ""))
    c["reason"] = plain.legacy(l8.get("summary") or "")
    c["record_summary"] = c["reason"]
    c["limits"] = ["열린 포트에는 실제 서비스(MySQL·Redis)가 아닌 대체 프로그램이 응답 — 연결 가능 여부만 확인",
                   "관리자 지점은 허용 목록 대역(198.51.100.0/24)을 VPC 보조 대역으로 구성 — 보안 그룹은 출발지 주소로 판단하므로 같은 규칙을 시험하나, 실제 관리자 PC 의 인터넷 경로는 아님",
                   "인터넷 지점은 시험 VPC 공개 서브넷의 서버(공인 IP) — 별도 VPC 는 인터넷 게이트웨이 한도로 미구성. "
                   "상대 보안 그룹이 보는 출발지 주소(공인/사설)는 확인 필요 — 어느 쪽이든 관리자 허용 목록 밖이므로 기대값 동일",
                   "콘솔 출력은 실시간이 아님 — 2026-10-23 실측 20~40초 지연 사례 (AWS 문서에 수치 없음). apply 후 2분 대기와 seq 2 이상 증가 규칙으로 대응",
                   "UDP·ICMP 는 시험하지 않음 (설계 기준 경로 9개 모두 TCP)"]
    return c


ORIGINAL_SG = Path("scenarios") / "arch" / "webapp-3tier" / "security_groups.tf"


def _neutral_matches(ms: Any) -> List[str]:
    """측정 기록의 '후보 <파일 이름>' → 화면 이름 '후보 NN' (파일 이름은 기대 결과를 드러낼 수 있음, 2026-10-31 D-24).
    기록 파일(measure.json)은 그대로 두고 화면에 보일 때만 바꾼다."""
    from ..web.cases import _manifest, display_labels
    man, _ = _manifest(TESTBED_SET)
    labels = display_labels(TESTBED_SET, man)
    by_stem: Dict[str, str] = {}
    for c in (man or {}).get("candidates") or []:
        ref = str(c.get("candidate") or "")
        if ref.startswith("manual:") and ref.endswith(".tf"):
            by_stem[Path(ref[7:]).stem] = labels.get(str(c.get("id")), "후보")
    out: List[str] = []
    for m in ms or []:
        t = str(m)
        out.append(by_stem.get(t[3:], t) if t.startswith("후보 ") else t)
    return out
SYNC_BASIS_KO = {"apply": "파일 수정 시각은 apply 이후이나 내용이 마지막 apply 와 같음 (data/testbed_ops.jsonl · 상태 파일 번호 동일)",
                 "plan": "원본 반영 plan 결과 '변경 없음' — 배포 상태와 같은 내용 (상태 파일 번호 동일)",
                 "plan_check": "이 기록의 plan 확인 결과 '변경 없음' — 배포 상태와 같은 내용 (상태 파일 번호 동일)"}


def _switch_entry(root: Path, rid: str, until: str) -> Optional[Dict[str, Any]]:
    """data/testbed_switch.jsonl 에서 이 기록의 후보를 시험 환경에 넣은 마지막 기록 (측정 시작 전)."""
    try:
        lines = (root / "data" / "testbed_switch.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    hit = None
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("which") == "candidate" and e.get("record") == rid and (not until or str(e.get("at") or "") <= until):
            hit = e
    return hit


def _hm(iso: Any) -> str:
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})", str(iso or ""))
    return f"{int(m.group(2))}/{int(m.group(3))} {m.group(4)}:{m.group(5)}:{m.group(6)}" if m else str(iso or "")


def _dur(s: Any) -> str:
    try:
        s = int(s)
    except (TypeError, ValueError):
        return "?"
    return f"{s // 60}분 {s % 60}초" if s >= 60 else f"{s}초"


# ----------------------------------------------------------------------------- plan 확인 (실제 상태 기준 plan — plancheck.py)
PLAN_KIND = {"replace": "교체 (-/+ 삭제 후 재생성)", "delete": "삭제 (-)", "update": "제자리 수정 (~)", "create": "생성 (+)"}
NETWORK_TYPES = ("aws_security_group", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule", "aws_security_group_rule")
PROVIDER_DOC = {"org": "HashiCorp", "doc": "Terraform AWS provider — aws_security_group 문서",
                "item": "description · name 'Forces new resource' / Security Group Deletion Problem",
                "text": "보안 그룹의 description·name 변경 시 삭제 후 재생성(교체). 기본 순서는 삭제 우선이며, AWS 는 다른 리소스에 연결된 보안 그룹의 삭제를 허용하지 않음",
                "status": "공식 문서"}


def _plan_doc(record_dir: Path, rel: Any) -> Optional[Dict[str, Any]]:
    r = str(rel or "")
    if not r or ".." in r or r.startswith(("/", "\\")):
        return None
    d = record_dir / r
    doc = _j(d / "plan_summary.json")
    if isinstance(doc, dict):
        doc["_dir"] = d
        return doc
    return None


def _res_label(addr: Any, root: Optional[Path]) -> str:
    a = str(addr or "")
    return plain.sg(a, root) if a.startswith("aws_security_group.") else a


ATTR_KO = {"description": "설명(description)", "name": "이름(name)", "name_prefix": "이름 접두사(name_prefix)", "vpc_id": "VPC(vpc_id)"}


def _plan_what(e: Dict[str, Any]) -> str:
    """변경 리소스 한 줄: 변경 내용 (짧게 — 교체 원인 값의 전→후는 아래 '교체 원인 값' 블록에)."""
    parts = []
    rp = e.get("replace_paths") or []
    for k in rp:
        parts.append(f"{ATTR_KO.get(k, k)} 변경 → 교체")
    for blk, ko in (("ingress", "인바운드"), ("egress", "아웃바운드")):
        n = e.get(f"{blk}_rules")
        if isinstance(n, list) and len(n) == 2:
            parts.append(f"{ko} 규칙 {n[0]}개 → {n[1]}개" if n[0] != n[1] else f"{ko} 규칙 내용 변경 ({n[1]}개)")
    other = [k for k in e.get("changed") or [] if k not in rp and k not in ("ingress", "egress")]
    if other:
        parts.append("기타: " + ", ".join(other[:5]))
    return " · ".join(parts) or "-"


def _plan_sentence(pdoc: Dict[str, Any], root: Optional[Path]) -> str:
    """BLOCKED 한 줄: 'Bastion 보안 그룹 교체 (설명(description) 변경)'."""
    bad = [e for e in pdoc.get("changes") or [] if e.get("kind") in ("replace", "delete")]
    out = []
    for e in bad[:3]:
        rp = e.get("replace_paths") or []
        out.append(f"{_res_label(e.get('address'), root)} {'교체' if e.get('kind') == 'replace' else '삭제'}"
                   + (f" ({', '.join(ATTR_KO.get(k, k) for k in rp)} 변경)" if rp else ""))
    return ", ".join(out)


def _plan_blocks(pdoc: Dict[str, Any], root: Optional[Path]) -> List[Dict[str, Any]]:
    v = str(pdoc.get("verdict") or "")
    cnt = pdoc.get("counts") or {}
    rows = [["결과", plain.legacy(pdoc.get("verdict_ko") or v) + (" — " + _plan_sentence(pdoc, root) if v == "BLOCKED" else "")],
            ["확인 시각", _hm(pdoc.get("started_at"))],
            ["시험 환경 파일", (", ".join(_neutral_matches(pdoc.get("matches"))) or "원본·후보와 모두 다름") + f" (sha256 {str(pdoc.get('testbed_security_groups_sha256') or '')[:12]}…)"]]
    if cnt:
        rows.append(["변경 리소스", f"교체 {cnt.get('replace', 0)} · 삭제 {cnt.get('delete', 0)} · 제자리 수정 {cnt.get('update', 0)} · 생성 {cnt.get('create', 0)}"])
    if pdoc.get("error"):
        rows.append(["plan 오류", str(pdoc.get("error"))])
    if pdoc.get("drift"):
        rows.append(["Terraform 외부 변경 (drift)", f"{len(pdoc['drift'])}개 — {', '.join(str(x) for x in pdoc['drift'][:3])}"])
    if pdoc.get("terraform_version"):
        rows.append(["도구", f"terraform {pdoc.get('terraform_version')} · plan 형식 {pdoc.get('format_version')}"])
    blocks: List[Dict[str, Any]] = [{"t": "kv", "title": "plan 확인 · 실제 시험 환경 상태 기준", "rows": rows,
                                     "tone": "bad" if v == "BLOCKED" else "good" if v in ("CLEAN", "NO_CHANGES") else "warn"}]
    ch = pdoc.get("changes") or []
    if v != "ERROR":
        blocks.append({"t": "table", "title": "plan 변경 대상 리소스", "head": ["리소스", "변경 방식", "변경 내용"],
                       "rows": [[_res_label(e.get("address"), root), PLAN_KIND.get(str(e.get("kind")), str(e.get("kind"))), _plan_what(e)] for e in ch],
                       "tones": ["bad" if e.get("kind") in ("replace", "delete") else "good" if e.get("kind") == "update" and e.get("type") in NETWORK_TYPES else "warn"
                                 for e in ch],
                       "empty": "없음 — 변경 리소스 없음"})
        why = []
        for e in ch:
            for k in e.get("replace_paths") or []:
                v = (e.get("values") or {}).get(k)
                if isinstance(v, list) and len(v) == 2:
                    why.append([f"{_res_label(e.get('address'), root)} · {ATTR_KO.get(k, k)}", f"'{v[0]}' → '{v[1]}'"])
        if why:
            blocks.append({"t": "kv", "title": "교체 원인 값 (현재 AWS → 후보 파일)", "rows": why, "tone": "bad"})
    # terraform plan 출력에서 리소스 머리줄 · 교체 이유 줄 · 합계 줄 (원문)
    pdir = pdoc.get("_dir")
    try:
        txt = mask_account((pdir / "plan.txt").read_text(encoding="utf-8")) if isinstance(pdir, Path) else ""
    except OSError:
        txt = ""
    pick = []
    for i, ln in enumerate(txt.replace("\r", "").split("\n")):
        s = ln.strip()
        if s.startswith("# ") and ("must be replaced" in s or "will be" in s) or "forces replacement" in s or s.startswith(("Plan:", "No changes", "Error:")):
            pick.append({"n": i + 1, "text": ln.rstrip(), "mark": "forces replacement" in s or "must be replaced" in s or "destroyed" in s})
    if pick:
        blocks.append({"t": "code", "title": "terraform plan 출력 발췌 (원문)", "file": "plan.txt", "tone": "bad" if v == "BLOCKED" else "", "lines": pick[:40]})
    return blocks


def _plan_leaves(pdoc: Dict[str, Any], record_dir: Path) -> List[Dict[str, Any]]:
    d = pdoc.get("_dir")
    if not isinstance(d, Path):
        return []
    rel = d.relative_to(record_dir).as_posix()
    return [{"path": f"{rel}/{n}", "bytes": None, "sha256": None} for n in ("plan_summary.json", "plan.txt", "plan_changes.json", "commands.json") if (d / n).exists()]


def card_plan_blocked(record_dir: Path, root: Path, pdoc: Dict[str, Any]) -> Dict[str, Any]:
    """plan 확인에서 교체·삭제가 나와 apply 하지 않은 후보 — 실제 AWS 검사 차단 (V7·V8 은 하지 않음)."""
    c = _base("임시", "시험 환경 반영 (apply)", "이 후보를 실제 시험 환경에 반영(apply)해도 되는가",
              "apply 전 실제 배포 상태 기준 plan 을 생성해 교체·삭제 발생 여부 확인")
    c["method"]["steps"] = [
        "5단계 [후보 반영] — 시험 환경 폴더의 security_groups.tf 를 이 기록의 후보로 교체 (파일 복사만)",
        "[plan 확인] — 시험 환경 폴더에서 실제 배포 상태 기준 terraform plan 생성. AWS 현재 값을 조회해 비교만 하며 상태 파일 잠금·쓰기 없음",
        "plan 에 교체(-/+)·삭제(-)가 하나라도 있으면 apply 하지 않음 — 배포 전 검사(V4)는 AWS 상태 없이 plan 하므로 확인 불가",
    ]
    c["method"]["commands"] = _cmd_rows(pdoc.get("_dir"))
    c["verdict"], c["verdict_ko"], c["status"] = "FAIL", "차단 (apply 미실행)", "done"
    c["summary"] = "차단 — 실제 상태 기준 plan 에서 " + (_plan_sentence(pdoc, root) or "교체·삭제 발생") + " (apply 미실행)"
    c["reason"] = plain.legacy(pdoc.get("summary") or c["summary"])
    c["record_summary"] = c["summary"]
    c["evidence"] = _plan_blocks(pdoc, root)
    c["basis"]["standard"].append(dict(PROVIDER_DOC))
    c["basis"]["team"].append({"k": "규칙", "v": "plan 에 교체·삭제가 있으면 apply 하지 않음 — 위험도 기준표 v2(2026-09-22 고정)도 리소스 교체·삭제를 점수와 무관하게 '높음(리포트만)'으로 분류"})
    c["basis"]["tool"].append({"k": "plan 명령", "v": "terraform plan -input=false -no-color -lock=false -refresh=true -out=(임시 폴더) → terraform show -json"})
    c["limits"] = ["plan 은 AWS 를 변경하지 않음 — 실제 apply 시 실패 지점은 시험하지 않음 (apply 미실행)",
                   "교체가 발생하는 후보라 시험 환경에 반영하지 않았으므로 V7·V8 미측정"]
    c["leaves"] = _plan_leaves(pdoc, record_dir)
    return c


def _skip_after_plan(k: str) -> Dict[str, Any]:
    c = _base(k, LAYER_NAMES[k][0], LAYER_NAMES[k][1], HOW.get(k, ""))
    c["reason"] = "미실행 — 앞 단계(시험 환경 반영)의 plan 확인에서 교체·삭제가 발생해 apply 하지 않음"
    c["skipped"] = "plan"
    return c


def card_tempenv(record_dir: Path, root: Path, after: Optional[Dict[str, Any]], before: Optional[Dict[str, Any]],
                 adir: Optional[Path], bdir: Optional[Path], plan: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """시험 환경 반영(apply) — 뒤의 V7·V8 이 잰 시험 환경에 무엇이 배포돼 있었는지. 반영은 사람이 확인 창에서 실행하고, 이 카드는 기록으로 확인만 한다.
    plan 확인 기록(plan)이 있으면 그 결과도 증거로 붙인다. 측정 전이면 plan 확인 결과를 이 카드의 답으로 쓴다."""
    c = _base("임시", "시험 환경 반영 (apply)", "V7·V8 측정 시 시험 환경에 이 후보가 반영되어 있었는가",
              "측정 시 시험 환경 폴더의 보안 그룹 파일 지문(sha256)을 이 후보 파일과 비교하고, apply 완료 후 측정했는지 확인")
    c["method"]["steps"] = [
        "5단계 [후보 반영] — 시험 환경 폴더의 security_groups.tf 를 이 기록의 후보로 교체 (기록: data/testbed_switch.jsonl)",
        "[plan 확인] — 실제 배포 상태 기준으로 보안 그룹 제자리 수정만 있고 교체·삭제가 없는지 확인 → 확인 창에서 사람이 plan 검토 후 [apply 실행] (또는 PowerShell 에서 사람이 직접 apply)",
        "측정은 상태 파일이 보안 그룹 파일보다 최신(= apply 완료)이고 apply 후 2분이 지나야 가능",
        "측정 시 시험 환경 파일의 sha256 을 재계산해 이 기록의 후보(수정 전 측정이면 원본)와 일치 여부 확인",
    ]
    doc, d = (after, adir) if after is not None else (before, bdir)
    c["limits"] = [("plan 확인 기록 보관 위치: " + str((plan or {}).get("_dir").relative_to(record_dir).as_posix())) if plan is not None
                   else "PowerShell 에서 직접 plan 한 경우 그 화면은 이 기록에 남지 않음",
                   "상태 파일이 최신이라는 것은 apply 완료까지만 의미 — 실제 적용 규칙 값은 V7 에서 AWS 를 직접 조회해 확인",
                   "시험 환경은 축소판 (서버 1대씩, DB·Redis 는 포트만 여는 대체 프로그램)"]
    if plan is not None and after is None:
        # 측정 전 — plan 확인 단계까지 진행 (apply 전이거나, apply 후 아직 측정 전)
        v = str(plan.get("verdict") or "")
        c["verdict"], c["verdict_ko"] = {"CLEAN": ("INFO", "plan 확인 통과 · 측정 전"), "NO_CHANGES": ("INFO", "변경 없음 · 측정 전"),
                                         "CHECK": ("UNKNOWN", "사람 판단 필요"), "ERROR": ("UNKNOWN", "plan 확인 오류")}.get(v, ("UNKNOWN", v))
        c["status"] = "done"
        c["question"] = "이 후보를 실제 시험 환경에 반영(apply)해도 되는가 (측정 전 — plan 확인 단계)"
        c["summary"] = {"CLEAN": "측정 전 — plan 확인: 보안 그룹 제자리 수정만 포함, 반영 가능 (apply 는 사람이 확인 창에서 실행)",
                        "NO_CHANGES": "측정 전 — plan 확인: 변경 없음 (이미 apply 된 경우 2분 후 수정 후 측정)",
                        "CHECK": "apply 전 — plan 확인: 교체·삭제는 없으나 사람의 plan 검토 필요",
                        "ERROR": "plan 확인 재실행 필요 — " + str(plan.get("error") or "plan 생성 실패")}.get(v, plain.legacy(plan.get("summary") or ""))
        c["reason"] = plain.legacy(plan.get("summary") or "")
        c["record_summary"] = c["summary"]
        c["evidence"] = _plan_blocks(plan, root)
        c["method"]["commands"] = _cmd_rows(plan.get("_dir"))
        c["basis"]["standard"].append(dict(PROVIDER_DOC))
        c["leaves"] = _plan_leaves(plan, record_dir)
        c["scope"] = "plan"
        return c
    if doc is None:
        c["reason"] = "측정 기록 없음 — 시험 환경 반영 후 5단계 측정 시 생성"
        return c
    c["method"]["commands"] = [x for x in _cmd_rows(d) if str(x.get("step", "")).startswith("terraform:show-state")]
    is_after = after is not None
    ident = doc.get("identity") or {}
    sha = str(ident.get("testbed_security_groups_sha256") or "")
    target = (record_dir / "candidate" / "security_groups.tf") if is_after else (root / ORIGINAL_SG)
    label = "이 기록의 후보" if is_after else "원본"
    tsha = sha256_file(target) if target.exists() else None
    same = bool(sha) and (sha == tsha if tsha else any(str(m).startswith(label) for m in ident.get("matches") or []))
    st = doc.get("state") or {}
    te = doc.get("tempenv") or {}
    ok = same and bool(st.get("ok"))
    c["verdict"], c["verdict_ko"], c["status"] = ("PASS" if ok else "FAIL"), ("반영 확인" if ok else "반영 미확인"), "done"
    josa = "과" if label == "원본" else "와"
    rows = [["시험 환경 파일", f"{label}{josa} {'일치' if same else '불일치'} (파일 지문 sha256 {sha[:12]}…)"]]
    if is_after:
        sw = _switch_entry(root, record_dir.name, str(doc.get("started_at") or ""))
        rows.append(["후보 적용 시각", f"{_hm(sw.get('at'))} — 시험 환경 파일을 이 후보로 교체 (기록: data/testbed_switch.jsonl)"
                     if sw else "적용 기록 없음 (수동 복사 가능성 — 파일 지문으로만 확인)"])
        ta = (_j(record_dir / "state.json") or {}).get("testbed_apply") or {}
        if ta.get("ok") and ta.get("candidate_sha256") == sha and str(ta.get("at") or "") <= str(doc.get("started_at") or "9"):
            rows.append(["반영 방법", f"앱 확인 창 — 사람이 plan 검토 후 실행 · {_hm(ta.get('at'))} · plan 확인({ta.get('plan_dir')})의 plan 그대로"])
        else:
            rows.append(["반영 방법", "PowerShell 수동 실행 (앱 기록 없음 — 파일 지문·상태 파일 시각으로 확인)"])
    if te.get("since_apply_s") is not None:
        rows.append(["apply 확인", f"apply 완료 {_dur(te.get('since_apply_s'))} 후 측정 시작"])
    else:
        rows.append(["apply 확인", "apply 완료 2분 후부터 측정 가능 (프로그램 규칙)"])
    if te.get("sync_basis"):
        # 파일 수정 시각이 apply 보다 나중이지만 내용이 배포 상태와 같다고 판단한 근거 (proof_api._sync_basis)
        rows.append(["반영 판단 근거", SYNC_BASIS_KO.get(str(te.get("sync_basis")), str(te.get("sync_basis")))])
    rows.append(["측정 시작", _hm(doc.get("started_at"))])
    c["evidence"].append({"t": "kv", "title": "반영 확인 · " + ("수정 후" if is_after else "수정 전"), "rows": rows, "tone": "good" if ok else "bad"})
    nres = te.get("resources")
    c["evidence"].append({"t": "kv", "title": "AWS 상태 파일 (terraform.tfstate)", "rows": [
        ["확인한 보안 그룹", f"{len(st.get('sg_ids') or {})}개 (상태 파일에서 AWS 보안 그룹 ID 확인)"],
        ["상태 파일 리소스", f"{nres}개" if nres else "기록 없음 (이전 버전 측정)"]]})
    if is_after and before is not None:
        bid = before.get("identity") or {}
        c["evidence"].append({"t": "kv", "title": "수정 전 배포 (원본)", "rows": [
            ["시험 환경 security_groups.tf", (", ".join(_neutral_matches(bid.get("matches"))) or "원본·후보와 모두 다름") + f" · sha256 {str(bid.get('testbed_security_groups_sha256') or '')[:12]}…"],
            ["측정 시작", _hm(before.get("started_at"))]]})
    c["summary"] = (f"반영 확인 — 시험 환경 파일 = {label} (파일 지문 일치) · apply 완료 후 {_hm(doc.get('started_at'))} 측정" if ok
                    else f"반영 미확인 — 시험 환경 파일이 {label}{josa} 불일치 (이 측정은 {label}의 결과 아님)")
    c["reason"] = c["summary"]
    c["record_summary"] = c["summary"]
    c["leaves"] = [{"path": f"{'postdeploy' if is_after else 'data/measurements'}/{d.name}/measure.json", "bytes": None, "sha256": None},
                   {"path": "data/testbed_switch.jsonl", "bytes": None, "sha256": None}]
    if plan is not None and is_after:
        # apply 전에 한 plan 확인 — 이 후보를 반영할 때 교체·삭제가 없었다는 근거
        c["evidence"].extend(_plan_blocks(plan, root))
        c["method"]["commands"] = _cmd_rows(plan.get("_dir")) + list(c["method"]["commands"] or [])
        c["basis"]["standard"].append(dict(PROVIDER_DOC))
        c["leaves"] = _plan_leaves(plan, record_dir) + c["leaves"]
    return c


def as_before(c: Dict[str, Any]) -> Dict[str, Any]:
    """이 기록의 수정 후 측정이 없어 수정 전(원본) 측정을 대신 보여 줄 때 — 판정이 이 후보의 것으로 읽히지 않게 표시한다.
    판정 값(verdict)은 원본 측정 그대로 두고, 화면·보고서에 보이는 말에 '수정 전' 을 붙인다."""
    if c.get("status") != "done":
        return c
    c["scope"] = "before"
    c["verdict_ko"] = "수정 전 " + str(c.get("verdict_ko") or "")
    c["summary"] = "수정 전(원본) 측정 — " + str(c.get("summary") or "")
    c["reason"] = "이 후보의 시험 환경 측정 기록 없음 — 위 값은 수정 전(원본) 배포 측정값"
    c["record_summary"] = c["summary"]
    return c


TESTBED_SET = "arch-3tier-sg"     # 시험 환경(실제 AWS)은 3계층 웹 서비스 하나뿐


def _other_case(record_dir: Path) -> Optional[str]:
    """기록이 시험 환경이 없는 사례면 그 묶음 이름 (예: arch-webapp-sg). 3계층이거나 기록이 없으면 None."""
    st = _j(record_dir / "state.json")
    if not st:
        return None
    parts = str(st.get("scenario") or "").split("/")
    if len(parts) >= 3 and parts[0] == "ui" and parts[1] != TESTBED_SET:
        return parts[1]
    return None


def build_post_cards(record_dir: Path, root: Path) -> Dict[str, Any]:
    other = _other_case(record_dir)
    if other:
        why = "이 사례는 실제 AWS 시험 환경 없음 — 실제 AWS 검사(시험 환경 반영 · V7 · V8)는 3계층 웹 서비스 사례에서만 진행"
        cards = []
        for k, name, q, how in (("임시", "시험 환경 반영 (apply)", "V7·V8 측정 시 시험 환경에 이 후보가 반영되어 있었는가", ""),
                                ("V7", LAYER_NAMES["V7"][0], LAYER_NAMES["V7"][1], HOW.get("V7", "")),
                                ("V8", LAYER_NAMES["V8"][0], LAYER_NAMES["V8"][1], HOW.get("V8", ""))):
            c = _base(k, name, q, how)
            c["reason"] = why
            c["skipped"] = "case"
            cards.append(primary.mark(c))
        return {"cards": cards, "na": why, "case_set": other,
                "after": {"dir": None, "status": None, "at": None, "matches": None},
                "before": {"dir": None, "status": None, "at": None, "matches": None}}
    m = find_measurements(record_dir, root)
    adir, bdir = m["after"], m["before"]
    after = _j(adir / "measure.json") if adir else None
    before = _j(bdir / "measure.json") if bdir else None
    st = _j(record_dir / "state.json") or {}
    post = st.get("post_deploy") if isinstance(st.get("post_deploy"), dict) else {}
    pc = st.get("plan_check") if isinstance(st.get("plan_check"), dict) else {}
    plan = _plan_doc(record_dir, pc.get("path")) if pc else None
    before_info = {"dir": bdir.name if bdir else None, "status": (before or {}).get("status"), "at": (before or {}).get("started_at"),
                   "matches": _neutral_matches(((before or {}).get("identity") or {}).get("matches"))}
    plan_info = {k: pc.get(k) for k in ("run_id", "at", "verdict", "summary", "path")} if pc else None
    if post.get("status") == "PLAN_BLOCKED":
        # 2차의 가장 최근 결과가 'plan 확인에서 교체·삭제'(차단) — apply 하지 않았으므로 V7·V8 은 없다
        bdoc = _plan_doc(record_dir, post.get("path")) or plan or {"verdict": "BLOCKED", "summary": post.get("summary"), "changes": [], "counts": {}}
        cards = [card_plan_blocked(record_dir, root, bdoc), _skip_after_plan("V7"), _skip_after_plan("V8")]
        for c in cards:
            primary.mark(c)
        return {"cards": cards, "plan": plan_info,
                "after": {"dir": post.get("path"), "status": "PLAN_BLOCKED", "at": post.get("at"), "matches": _neutral_matches(post.get("deployed_file_matches"))},
                "before": before_info}
    ver = _j(record_dir / "verification.json") or {}
    v6 = next((l for l in ((ver.get("report") or {}).get("layers") or []) if l.get("layer") == "V6"), {})
    cards = [card_tempenv(record_dir, root, after, before, adir, bdir, plan=plan), card_v7(v6, after, before, adir, bdir, root), card_v8(after, before, adir, bdir, root)]
    for c in cards:
        if c.get("scope") == "plan":
            pass                      # 측정 전 plan 확인 결과 — 수정 전 측정으로 바꿔 보이지 않는다
        elif after is None:
            as_before(c)
        elif c.get("status") == "done":
            c["scope"] = "after"
        primary.mark(c)
        if c.get("scope") == "plan":
            for b in c.get("evidence") or []:
                if str(b.get("title") or "").startswith("plan 변경 대상 리소스") and b.get("rows"):
                    b["key"] = True
    return {"cards": cards, "plan": plan_info,
            "after": {"dir": adir.name if adir else None, "status": (after or {}).get("status"), "at": (after or {}).get("started_at"),
                      "matches": _neutral_matches(((after or {}).get("identity") or {}).get("matches"))},
            "before": before_info}
