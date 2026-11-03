"""검증 도구 사전 점검 — 검사 직전에, 정답이 정해진 시료로 이 PC 의 도구가 기대대로 판정하는지 확인한다.
(시료 기준 동작 확인이며 전체 탐지 정확도를 증명하지 않는다.)

왜: '도구가 그렇게 표시했다' 가 아니라 '이 도구가 지금 이 PC 에서, 위험한 시료는 잡고 안전한 시료는 통과시킨다' 를 먼저 보이고
검사에 들어가기 위해. 알려진 한계(대역을 나눠 적으면 Trivy 가 못 잡음)도 같은 자리에서 보여 준다.

항목 (도구가 없으면 그 항목은 '미실행' — 통과로 채우지 않는다)
  rule     이 PC 의 trivy 바이너리 안에 들어 있는 규칙 정의(AVD-AWS-0107 의 제목·심각도·CIS 태그)를 직접 읽는다
  trivy    시료 3개를 trivy config 로 검사: 전체 개방(잡아야 함) · 허용 목록(통과해야 함) · 대역 나누기(알려진 한계)
  cidr     대역 나누기 시료의 합집합을 두 방식으로 계산 + 무작위 대역 목록으로 오라클과 별도 구현 대조
  validate 없는 속성 이름을 쓴 시료를 terraform validate 가 실패로 잡는지
  probe    V8 이 쓰는 TCP 접속 시험이 열림 / 거부 / 응답 없음을 구분하는지 (이 PC 안에서만)

결과: data/calibration/<시각>/calibration.json + 시료 파일 + trivy 출력 원본. AWS·LLM·네트워크(로컬 제외) 사용 없음.
"""
from __future__ import annotations

import json
import re
import socket
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..config import Settings
from ..evidence_log import CommandLog, now_iso, sha256_file
from ..tools.trivy import TrivyAdapter
from . import plain, recheck, standards

SAMPLE_TF = """resource "aws_security_group" "sample" {
  name        = "calibration-sample"
  description = "calibration sample"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = %s
  }
}
"""

SAMPLES = [
    {"id": "open", "label": "SSH 22 ← 0.0.0.0/0", "cidrs": ["0.0.0.0/0"], "risky": True,
     "expect": "지적", "meaning": "인터넷 전체에 SSH 가 열림"},
    {"id": "allowlist", "label": "SSH 22 ← 허용 목록 2개", "cidrs": ["203.0.113.0/24", "198.51.100.0/24"], "risky": False,
     "expect": "통과", "meaning": "허용 대역만 열림"},
    {"id": "split", "label": "SSH 22 ← 0.0.0.0/1 + 128.0.0.0/1", "cidrs": ["0.0.0.0/1", "128.0.0.0/1"], "risky": True,
     "expect": "통과(못 잡음)", "meaning": "두 대역을 합치면 인터넷 전체 — 사전 실험 01-cidr-split 과 같은 경우"},
]

_META_RE = re.compile(rb"# METADATA\n((?:#.*\n){3,120}?)package builtin\.aws\.([a-z0-9_.]+)\n")


# ----------------------------------------------------------------------------- 규칙 정의 (trivy 바이너리에서)
def _yaml_scalar(block: str, key: str) -> str:
    m = re.search(r"^#\s*" + re.escape(key) + r":\s*(.+)$", block, re.M)
    return m.group(1).strip().strip('"') if m else ""


def _frameworks(block: str) -> Dict[str, List[str]]:
    """scripts/trivy_check_meta.py 와 같은 규칙으로 읽는다 (들여쓰기 4칸 이상 = frameworks 아래, null 은 버림)."""
    fw: Dict[str, List[str]] = {}
    m = re.search(r"^#\s*frameworks:\s*\n((?:#\s{4,}.*\n)+)", block, re.M)
    if not m:
        return fw
    cur = None
    for line in m.group(1).splitlines():
        t = line.lstrip("#").rstrip()
        mk = re.match(r"^\s+([a-z0-9.-]+):\s*$", t)
        mv = re.match(r"^\s+-\s+(.*)$", t)
        if mk:
            cur = mk.group(1)
            fw[cur] = []
        elif mv and cur:
            v = mv.group(1).strip().strip('"')
            if v != "null":
                fw[cur].append(v)
    return {k: v for k, v in fw.items() if v}


def _related(block: str) -> List[str]:
    m = re.search(r"^#\s*related_resources:\s*\n((?:#\s{2,}-\s+.*\n)+)", block, re.M)
    if not m:
        return []
    return [re.sub(r'^"|"$', "", x.strip()) for x in re.findall(r"-\s+(.*)", m.group(1))]


def trivy_rule_meta(trivy_path: str, rule_ids: List[str], cache_dir: Optional[Path] = None) -> Dict[str, Any]:
    """trivy 바이너리 안의 rego '# METADATA' 블록에서 규칙 정의를 읽는다. 바이너리는 읽기만 한다."""
    p = Path(trivy_path)
    if not p.exists():
        from shutil import which
        w = which(trivy_path)
        if not w:
            return {"ok": False, "reason": f"trivy 를 찾을 수 없다: {trivy_path}"}
        p = Path(w)
    st = p.stat()
    key = f"p2-{st.st_size}-{int(st.st_mtime)}"      # p2 = 읽는 규칙 판 (읽는 방식을 바꾸면 올린다 — 예전 캐시를 쓰지 않게)
    cache = (cache_dir / f"trivy-meta-{key}.json") if cache_dir else None
    if cache is not None and cache.exists():
        try:
            doc = json.loads(cache.read_text(encoding="utf-8"))
            doc["cached"] = True
            doc["rules"] = {r: doc.get("all", {}).get(r) for r in rule_ids}
            return doc
        except (OSError, ValueError):
            pass
    t0 = time.time()
    data = p.read_bytes()
    found: Dict[str, Any] = {}
    for m in _META_RE.finditer(data):
        block = m.group(1).decode("utf-8", errors="replace")
        rid = _yaml_scalar(block, "id")
        avd = _yaml_scalar(block, "avd_id") or (("AVD-" + rid) if rid else "")
        if not avd or avd in found:
            continue
        found[avd] = {"avd_id": avd, "title": _yaml_scalar(block, "title"), "severity": _yaml_scalar(block, "severity"),
                      "deprecated": _yaml_scalar(block, "deprecated") or "false", "frameworks": _frameworks(block),
                      "related_resources": _related(block), "package": "builtin.aws." + m.group(2).decode()}
    doc = {"ok": True, "binary": str(p), "bytes": st.st_size, "elapsed_s": round(time.time() - t0, 2), "count": len(found), "cached": False,
           "all": {r: found.get(r) for r in rule_ids}}
    if cache is not None:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass
    doc["rules"] = {r: found.get(r) for r in rule_ids}
    return doc


def compare_rule_with_reference(meta: Optional[Dict[str, Any]], rule_id: str) -> Dict[str, Any]:
    """바이너리에서 읽은 정의 vs standards.py 에 적어 둔 값 — 다르면 화면이 '기준표를 다시 봐야 함' 으로 표시."""
    ref = (standards.RULES.get(rule_id) or {}).get("trivy") or {}
    if not meta:
        return {"same": None, "reason": "바이너리에서 규칙을 찾지 못함"}
    diffs = []
    if ref.get("title") and meta.get("title") != ref.get("title"):
        diffs.append("title")
    if ref.get("severity") and meta.get("severity") != ref.get("severity"):
        diffs.append("severity")
    if "frameworks" in ref and meta.get("frameworks") != ref.get("frameworks"):
        diffs.append("frameworks")
    return {"same": not diffs, "diffs": diffs}


# ----------------------------------------------------------------------------- 시료 검사
def _rule_records(report: Dict[str, Any], rule_id: str) -> Dict[str, int]:
    out = {"FAIL": 0, "PASS": 0}
    short = rule_id.replace("AVD-", "")
    for r in report.get("Results") or []:
        for m in r.get("Misconfigurations") or []:
            rid = str(m.get("AVDID") or m.get("ID") or "")
            if rid in (rule_id, short):
                st = str(m.get("Status") or "FAIL")
                out[st] = out.get(st, 0) + 1
    return out


def run_trivy_samples(trivy: TrivyAdapter, out_dir: Path, clog: CommandLog, rule_id: str = "AVD-AWS-0107") -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for s in SAMPLES:
        d = out_dir / "samples" / s["id"]
        d.mkdir(parents=True, exist_ok=True)
        code = SAMPLE_TF % json.dumps(s["cidrs"])
        (d / "main.tf").write_text(code, encoding="utf-8")
        outp = out_dir / f"trivy_{s['id']}.json"
        scan = trivy.scan_dir(d, outp)
        clog.add(f"trivy:sample:{s['id']}", "V1", scan.argv, returncode=scan.returncode, started_at=scan.started_at,
                 elapsed=scan.elapsed, stderr=scan.stderr_tail, output=outp, ok=scan.ok, note=scan.error)
        recs = _rule_records(scan.report, rule_id) if scan.ok else {}
        flagged = bool(recs.get("FAIL"))
        result = "지적" if flagged else ("통과" if scan.ok else "실행 실패")
        if not scan.ok:
            verdict = "실행 실패"
        elif s["id"] == "split":
            verdict = "못 잡음 (알려진 한계 — 이전 측정과 같음)" if not flagged else "잡음 (이전 측정과 다름 — 확인 필요)"
        else:
            verdict = "맞음" if (flagged == s["risky"]) else "틀림"
        rows.append({"id": s["id"], "label": s["label"], "cidrs": s["cidrs"], "risky": s["risky"], "meaning": s["meaning"],
                     "code": code, "expect": s["expect"], "result": result, "verdict": verdict, "rule_records": recs,
                     "checks_executed": scan.summary.get("checks_executed") if scan.ok else None,
                     "elapsed_s": scan.elapsed, "output": outp.name, "output_sha256": sha256_file(outp) if outp.exists() else None})
    return rows


# ----------------------------------------------------------------------------- validate 시료
TYPO_FROM = "    cidr_blocks = [\"0.0.0.0/0\"]"
TYPO_TO = "    cidr_block  = [\"0.0.0.0/0\"]"


def run_validate_sample(settings: Settings, tf_dir: Path, out_dir: Path, clog: CommandLog) -> Dict[str, Any]:
    from ..tools.terraform import TerraformAdapter
    tf = TerraformAdapter(settings.terraform_bin, settings.aws_region, template_dir=settings.tf_template_dir(),
                          provider_version=settings.aws_provider_version or None)
    info = tf.info()
    if not info.available:
        return {"ran": False, "reason": "terraform 없음"}
    src = (tf_dir / "security_groups.tf")
    if not src.exists():
        return {"ran": False, "reason": "시료 원본(security_groups.tf)이 없다"}
    text = src.read_text(encoding="utf-8")
    if TYPO_FROM not in text:
        return {"ran": False, "reason": "시료로 바꿀 줄을 찾지 못했다"}
    bad = text.replace(TYPO_FROM, TYPO_TO, 1)
    line = text[: text.index(TYPO_FROM)].count("\n") + 1
    wd = TerraformAdapter.make_workdir(tf_dir, out_dir / "validate_sample", file_overrides={"security_groups.tf": bad})
    tf.add_offline_override(wd)
    init = tf.init(wd)
    clog.add("terraform:sample:init", "V3", init.result.argv if init.result else None, returncode=init.result.returncode if init.result else None,
             started_at=init.started_at, elapsed=init.elapsed, stdout=init.result.stdout if init.result else "", ok=init.ok, note=init.error[:500])
    if not init.ok:
        return {"ran": False, "reason": "init 실패: " + init.error[:300]}
    v = tf.validate(wd)
    (out_dir / "validate_sample.json").write_text((v.result.stdout if v.result else "") or "", encoding="utf-8")
    clog.add("terraform:sample:validate", "V3", v.result.argv if v.result else None, returncode=v.result.returncode if v.result else None,
             started_at=v.started_at, elapsed=v.elapsed, output=out_dir / "validate_sample.json", ok=v.ok, note=v.error[:500])
    diags = (v.data or {}).get("diagnostics") or []
    first = diags[0] if diags else {}
    rng = (first.get("range") or {})
    try:
        import shutil
        shutil.rmtree(wd / ".terraform", ignore_errors=True)
    except OSError:
        pass
    return {"ran": True, "sample": f"security_groups.tf {line}행 cidr_blocks → cidr_block (존재하지 않는 속성 이름)", "line": line,
            "before": TYPO_FROM.strip(), "after": TYPO_TO.strip(), "expect": "실패", "result": "실패" if not v.ok else "통과",
            "verdict": "맞음" if not v.ok else "틀림",
            "diagnostic": {"severity": first.get("severity"), "summary": first.get("summary"), "detail": (first.get("detail") or "")[:300],
                           "file": rng.get("filename"), "line": (rng.get("start") or {}).get("line")},
            "elapsed_s": v.elapsed, "tool": f"{info.kind} {info.version}"}


# ----------------------------------------------------------------------------- V8 접속 시험의 세 결과
def run_probe_semantics() -> List[Dict[str, Any]]:
    from ..postdeploy import _tcp_probe
    rows: List[Dict[str, Any]] = []
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port_open = srv.getsockname()[1]
    stop = threading.Event()

    def accept_loop():
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                c.close()
            except OSError:
                continue

    th = threading.Thread(target=accept_loop, daemon=True)
    th.start()
    tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tmp.bind(("127.0.0.1", 0))
    port_closed = tmp.getsockname()[1]
    tmp.close()
    try:
        r1 = _tcp_probe("127.0.0.1", port_open, 2.0)
        rows.append({"target": f"127.0.0.1:{port_open}", "what": "이 PC 에 열어 둔 포트 (수신 프로그램 있음)", "expect": "open",
                     "result": r1["result"], "ms": int(r1["elapsed"] * 1000), "verdict": "맞음" if r1["result"] == "open" else "틀림"})
        r2 = _tcp_probe("127.0.0.1", port_closed, 5.0)     # Windows 는 거부(RST)를 받아도 두 번 더 시도해서 1~2초 걸린다
        rows.append({"target": f"127.0.0.1:{port_closed}", "what": "이 PC 의 닫힌 포트 (도달 가능, 수신 프로그램 없음)", "expect": "refused",
                     "result": r2["result"], "ms": int(r2["elapsed"] * 1000), "verdict": "맞음" if r2["result"] == "refused" else "틀림"})
        r3 = _tcp_probe("192.0.2.1", 22, 2.0)
        rows.append({"target": "192.0.2.1:22", "what": "무응답 주소 (문서용 예시 대역 — 보안 그룹 차단과 같은 '무응답')",
                     "expect": "timeout", "result": r3["result"], "ms": int(r3["elapsed"] * 1000),
                     "verdict": "맞음" if r3["result"] == "timeout" else "참고 (이 네트워크는 무응답 대신 즉시 오류를 돌려줌)"})
    finally:
        stop.set()
        srv.close()
    return rows


# ----------------------------------------------------------------------------- 전체
def run_calibration(settings: Settings, tf_dir: Optional[Path], log: Callable[[str], None] = print,
                    out_root: Optional[Path] = None) -> Dict[str, Any]:
    root = out_root or settings.path("data/calibration")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_dir = root / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    clog = CommandLog(out_dir / "commands.json")
    t0 = time.time()
    doc: Dict[str, Any] = {"schema": "iacpatch-calibration-v1", "id": stamp, "started_at": now_iso()}
    trivy = TrivyAdapter(settings.trivy_bin)
    if trivy.available():
        log("검증 도구 사전 점검 1/4 · trivy 실행 파일에서 규칙 정의 추출")
        meta = trivy_rule_meta(trivy.binary, ["AVD-AWS-0107"], settings.path(settings.cache_dir) if settings.cache_enabled() else None)
        r0107 = (meta.get("rules") or {}).get("AVD-AWS-0107")
        doc["rule"] = {"source": meta.get("binary"), "bytes": meta.get("bytes"), "elapsed_s": meta.get("elapsed_s"), "cached": meta.get("cached"),
                       "rule": r0107, "reference": compare_rule_with_reference(r0107, "AVD-AWS-0107"), "version": trivy.version()}
        log("검증 도구 사전 점검 2/4 · 점검 시료 3개 trivy config")
        doc["trivy"] = run_trivy_samples(trivy, out_dir, clog)
        for r in doc["trivy"]:
            log(f"  {r['label']:<34} 기대:{'위험' if r['risky'] else '안전'}  Trivy:{plain.cal_result(r['result'])}  → {plain.cal_verdict(r['verdict'])}")
    else:
        doc["rule"] = {"ran": False, "reason": "trivy 없음"}
        doc["trivy"] = []
    log("검증 도구 사전 점검 3/4 · IP 대역 계산 교차 검증 (독립 구현 2개)")
    split = next(s for s in SAMPLES if s["id"] == "split")
    doc["cidr"] = {"split": recheck.compare_with_netset(split["cidrs"], standards.TEAM_REQUIREMENTS["admin_allowlist"]["value"]),
                   "differential": recheck.differential(2000)}
    d = doc["cidr"]["differential"]
    log(f"  무작위 대역 목록 {d['cases']:,}건 · 결과 불일치 {d['mismatches']}건 · {d['elapsed_s']}초")
    if tf_dir is not None:
        log("검증 도구 사전 점검 4/4 · 잘못된 Terraform 구성 탐지 (terraform validate)")
        try:
            doc["validate"] = run_validate_sample(settings, tf_dir, out_dir, clog)
        except Exception as e:  # 점검 실패는 기록하고 계속
            doc["validate"] = {"ran": False, "reason": f"{type(e).__name__}: {e}"}
    else:
        doc["validate"] = {"ran": False, "reason": "대상 폴더 없음"}
    doc["probe"] = run_probe_semantics()
    doc["elapsed_s"] = round(time.time() - t0, 1)
    doc["tools"] = {"trivy": trivy.version() if trivy.available() else None}
    ok_rows = [r for r in doc.get("trivy", []) if r["id"] != "split"]
    doc["summary"] = {
        "trivy_correct": sum(1 for r in ok_rows if r["verdict"] == "맞음"), "trivy_total": len(ok_rows),
        "known_limit_reproduced": any(r["id"] == "split" and r["result"] == "통과" for r in doc.get("trivy", [])),
        "cidr_mismatches": d["mismatches"], "validate_ok": (doc.get("validate") or {}).get("verdict") == "맞음",
        "probe_ok": sum(1 for r in doc["probe"] if r["verdict"] == "맞음"), "probe_total": len(doc["probe"]),
    }
    (out_dir / "calibration.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    log(f"검증 도구 사전 점검 완료 · {doc['elapsed_s']}초 · {out_dir}")
    return doc


def latest(settings: Settings, max_age_s: Optional[float] = None) -> Optional[Dict[str, Any]]:
    root = settings.path("data/calibration")
    if not root.is_dir():
        return None
    for d in sorted(root.iterdir(), reverse=True):
        p = d / "calibration.json"
        if p.exists():
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if max_age_s is not None and time.time() - p.stat().st_mtime > max_age_s:
                return None
            doc["_dir"] = str(d)
            return doc
    return None
