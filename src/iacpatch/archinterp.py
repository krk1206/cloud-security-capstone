"""AI 해석 등록 (지도교수 9/29 지시 3단계: "AI 에이전트가 보고 해석할 수 있게").

흐름: scripts/arch_scan.py 가 만든 interpret_prompt.md 를 **사람이** Claude Code 새 세션(또는 Claude 앱)에 붙여 넣는다 → 응답 JSON 을
파일로 저장 → 이 모듈이 등록한다. 모델 자동 호출은 없다 (D-5, B 지시). 출처는 'claude-code-manual' 로 기록한다.

등록할 때 기계적으로 대조하는 것 (AI 를 믿지 않는다 — 신뢰 경계):
    1. 응답의 finding(rule_id·resource·file) 이 실제 Trivy 결과에 있는가  → 없는 것은 '지어낸 finding' 으로 표시
    2. 실제 finding 중 응답이 다루지 않은 것                               → '누락' 으로 표시 (덮어쓰지 않는다)
    3. 응답의 CIS 항목 번호가 팀 매핑표(policy/cis_mapping.json)와 같은가  → 일치 / 불일치 / 매핑표 없음 / AI 미기재
    4. 줄 번호가 실제와 다른가                                             → 표시만 (±2 줄은 허용)
    5. 스키마 필수 필드                                                     → 없으면 등록 거부
결과: <스캔 폴더>/interpretation.json (원문 + 대조 결과 + 출처), interpretation.md, findings.md 의 'AI 해석' 절 갱신.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "iacpatch-arch-interpretation-v1"
REQUIRED_FINDING_FIELDS = ("rule_id", "resource", "what", "why_risky", "fix")
FIX_RISK = ("LOW", "MEDIUM", "HIGH")
INTENDED = ("intended", "incidental", "unknown")


class InterpretationError(ValueError):
    pass


def extract_json(text: str) -> Dict[str, Any]:
    """응답 파일에서 JSON 하나를 꺼낸다 (```json 블록 또는 전체). 설명 문장이 섞여 있으면 첫 '{' 부터 마지막 '}' 까지."""
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    raw = m.group(1) if m else text
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        i, j = raw.find("{"), raw.rfind("}")
        if i < 0 or j <= i:
            raise InterpretationError("응답에서 JSON 을 찾을 수 없다 (```json 블록 하나로 저장했는지 확인)")
        try:
            return json.loads(raw[i:j + 1])
        except json.JSONDecodeError as e:
            raise InterpretationError(f"JSON 문법 오류: {e}")


def _norm_rule(r: str) -> str:
    r = str(r or "").strip()
    return "AVD-" + r if r.startswith("AWS-") else r


def _key(rule: str, resource: str) -> Tuple[str, str]:
    return (_norm_rule(rule), str(resource or "").strip())


def _cis_sections(cis: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for it in cis.get("items") or []:
        s = str(it.get("section", "")).strip()
        if s and s not in out:
            out.append(s)
    return out


def validate_shape(doc: Dict[str, Any]) -> List[str]:
    """등록을 막는 오류 목록 (비어 있으면 통과)."""
    errs: List[str] = []
    if doc.get("schema") != SCHEMA:
        errs.append(f"schema 가 '{SCHEMA}' 가 아니다: {doc.get('schema')!r}")
    fs = doc.get("findings")
    if not isinstance(fs, list) or not fs:
        errs.append("findings 가 비어 있거나 리스트가 아니다")
        return errs
    for i, f in enumerate(fs, 1):
        if not isinstance(f, dict):
            errs.append(f"findings[{i}] 가 객체가 아니다")
            continue
        for k in REQUIRED_FINDING_FIELDS:
            if not str(f.get(k) or "").strip():
                errs.append(f"findings[{i}] ({f.get('rule_id')}@{f.get('resource')}): '{k}' 없음")
        fr = str(f.get("fix_risk") or "").upper()
        if fr and fr not in FIX_RISK:
            errs.append(f"findings[{i}]: fix_risk 는 LOW/MEDIUM/HIGH 중 하나 ({fr!r})")
        io = str(f.get("intended_or_incidental") or "").lower()
        if io and io.split()[0] not in INTENDED:
            errs.append(f"findings[{i}]: intended_or_incidental 은 intended/incidental/unknown 중 하나 ({io!r})")
    return errs


def cross_check(doc: Dict[str, Any], scan: Dict[str, Any], mapping: Dict[str, Any]) -> Dict[str, Any]:
    """응답 ↔ 실제 스캔 대조. 응답은 바꾸지 않고 판정만 덧붙인다."""
    actual: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for r in scan.get("findings") or []:
        actual.setdefault(_key(r["rule_id"], r["resource"]), []).append(r)
    seen: set = set()
    per: List[Dict[str, Any]] = []
    for f in doc.get("findings") or []:
        k = _key(f.get("rule_id"), f.get("resource"))
        rows = actual.get(k) or []
        entry: Dict[str, Any] = {"rule_id": k[0], "resource": k[1], "exists": bool(rows)}
        if rows:
            seen.add(k)
            ln = f.get("line")
            try:
                ln_i = int(ln) if ln is not None else None
            except (TypeError, ValueError):
                ln_i = None
            entry["line_ok"] = (ln_i is None) or any(abs(ln_i - int(r["line"])) <= 2 for r in rows)
            entry["actual_lines"] = sorted({int(r["line"]) for r in rows})
            entry["file_ok"] = (not f.get("file")) or any(str(f.get("file")) == r["file"] for r in rows)
            cis = (rows[0].get("cis") or {})
            table = _cis_sections(cis)
            claim = f.get("cis_section")
            claim_s = str(claim).strip() if claim not in (None, "", "null") else ""
            if not claim_s:
                entry["cis"] = "AI 미기재" if table else ("AI 미기재 (매핑표도 없음)" if cis.get("in_table") else "AI 미기재 (매핑표에 룰 없음)")
            elif not cis.get("in_table"):
                entry["cis"] = f"AI 주장 {claim_s} — 매핑표에 룰 없음 (사람 확인 필요)"
            elif not table:
                entry["cis"] = f"AI 주장 {claim_s} — 매핑표는 'CIS 항목 없음' (불일치, 사람 확인 필요)"
            else:
                nums = re.findall(r"\d+(?:\.\d+)+", claim_s)
                hit = any(n in table for n in nums)
                entry["cis"] = f"일치 ({claim_s} ∈ 매핑표 {table})" if hit else f"**불일치** (AI {claim_s} / 매핑표 {table})"
        per.append(entry)
    missing = [{"rule_id": k[0], "resource": k[1], "lines": sorted({int(r['line']) for r in rows})}
               for k, rows in actual.items() if k not in seen]
    fabricated = [e for e in per if not e["exists"]]
    return {"checked": per, "missing": missing, "fabricated": fabricated,
            "coverage": f"{len(actual) - len(missing)}/{len(actual)}",
            "cis_mismatch": sum(1 for e in per if "불일치" in str(e.get("cis", "")))}


def register(scan_dir: Path, response_path: Path, mapping: Dict[str, Any], note: str = "", source: str = "claude-code-manual") -> Dict[str, Any]:
    scan_dir = Path(scan_dir)
    summary_p = scan_dir / "summary.json"
    if not summary_p.exists():
        raise InterpretationError(f"스캔 폴더에 summary.json 이 없다: {scan_dir}")
    scan = json.loads(summary_p.read_text(encoding="utf-8"))
    doc = extract_json(Path(response_path).read_text(encoding="utf-8"))
    errs = validate_shape(doc)
    if errs:
        raise InterpretationError("응답 형식 오류:\n  - " + "\n  - ".join(errs))
    if doc.get("scan_id") and doc.get("scan_id") != scan.get("scan_id"):
        errs.append(f"scan_id 가 다르다: 응답 {doc.get('scan_id')!r} / 스캔 {scan.get('scan_id')!r}")
    checks = cross_check(doc, scan, mapping)
    record = {
        "schema": SCHEMA + "+registered", "scan_id": scan.get("scan_id"), "registered_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "source": source, "note": note, "model": doc.get("model"),
        "provenance": "사람이 Claude Code(또는 Claude 앱) 새 세션에 interpret_prompt.md 를 붙여 넣어 받은 응답. 자동 호출 아님. 등록 시 실제 Trivy 결과와 기계 대조.",
        "warnings": errs, "checks": checks, "response": doc,
    }
    (scan_dir / "interpretation.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    md = render_interpretation_md(record, scan)
    (scan_dir / "interpretation.md").write_text(md, encoding="utf-8")
    fp = scan_dir / "findings.md"
    if fp.exists():
        text = fp.read_text(encoding="utf-8")
        head = text.split("\n## AI 해석", 1)[0].rstrip("\n")     # 이전 'AI 해석' 절(또는 '아직 없음' 안내)을 새 것으로 바꾼다
        fp.write_text(head + "\n\n" + md + "\n", encoding="utf-8")
    return record


def render_interpretation_md(rec: Dict[str, Any], scan: Dict[str, Any]) -> str:
    doc = rec["response"]
    ch = rec["checks"]
    L: List[str] = []
    L.append("## AI 해석")
    L.append("")
    L.append(f"- 출처: {rec['source']} (모델 표시: {doc.get('model') or '미기재'}) · 등록 {rec['registered_at']}" + (f" · {rec['note']}" if rec.get("note") else ""))
    L.append(f"- {rec['provenance']}")
    L.append(f"- 대조: 실제 finding 중 해석된 것 {ch['coverage']} · 지어낸 finding {len(ch['fabricated'])}건 · CIS 번호 불일치 {ch['cis_mismatch']}건")
    for w in rec.get("warnings") or []:
        L.append(f"- 경고: {w}")
    L.append("")
    if ch["fabricated"]:
        L.append("**실제 스캔에 없는 finding 을 해석함 (지어냄 — 신뢰하지 말 것):**")
        for e in ch["fabricated"]:
            L.append(f"- `{e['rule_id']}` @ `{e['resource']}`")
        L.append("")
    if ch["missing"]:
        L.append("**해석에서 빠진 실제 finding:**")
        for e in ch["missing"]:
            L.append(f"- `{e['rule_id']}` @ `{e['resource']}` (줄 {e['lines']})")
        L.append("")
    actual_by = {}
    for r in scan.get("findings") or []:
        actual_by.setdefault(_key(r["rule_id"], r["resource"]), r)
    L.append("| 룰 | 리소스 | 실제 finding | 의도/부수 | 고치는 법(요지) | 고칠 때 위험 | CIS 대조 |")
    L.append("|---|---|---|---|---|---|---|")
    chk = {(e["rule_id"], e["resource"]): e for e in ch["checked"]}
    for f in doc.get("findings") or []:
        k = _key(f.get("rule_id"), f.get("resource"))
        e = chk.get(k, {})
        fix = str(f.get("fix") or "").replace("|", "\\|").replace("\n", " ")
        L.append(f"| `{k[0]}` | `{k[1]}` | {'있음' if e.get('exists') else '**없음**'}"
                 f"{'' if e.get('line_ok', True) else ' (줄 번호 불일치)'} | {f.get('intended_or_incidental') or '—'} | "
                 f"{fix[:120]} | {str(f.get('fix_risk') or '—').upper()} | {e.get('cis', '—')} |")
    L.append("")
    for f in doc.get("findings") or []:
        k = _key(f.get("rule_id"), f.get("resource"))
        e = chk.get(k, {})
        L.append(f"### `{k[0]}` — `{k[1]}`" + ("" if e.get("exists") else " — **실제 스캔에 없음**"))
        L.append("")
        L.append(f"- 무엇이 잘못됐나: {f.get('what')}")
        L.append(f"- 왜 위험한가: {f.get('why_risky')}")
        if f.get("attack_path"):
            L.append(f"- 공격 경로: {f.get('attack_path')}")
        L.append(f"- 고치는 법: {f.get('fix')}")
        if f.get("confidence_note"):
            L.append(f"- 근거가 약한 부분(AI 스스로 표시): {f.get('confidence_note')}")
        L.append("")
    nf = doc.get("not_flagged_but_risky") or []
    if nf:
        L.append("### Trivy 가 잡지 않았지만 AI 가 위험하다고 본 것 (사람 확인 필요)")
        L.append("")
        for x in nf:
            L.append(f"- `{x.get('resource')}` ({x.get('file')}:{x.get('line')}) — {x.get('what')}")
        L.append("")
    sm = doc.get("summary") or {}
    if sm:
        L.append("### 총평 (AI)")
        L.append("")
        if sm.get("fix_order"):
            L.append("- 고칠 순서: " + " → ".join(str(x) for x in sm["fix_order"]))
        if sm.get("overall"):
            L.append(f"- {sm['overall']}")
        L.append("")
    return "\n".join(L)
