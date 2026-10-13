#!/usr/bin/env python3
"""Trivy 바이너리에 내장된 체크(rego) 메타데이터를 읽어낸다 — Trivy 가 스스로 선언한 CIS/프레임워크 태그·심각도·deprecated 여부.

    python3 scripts/trivy_check_meta.py                      # AWS 체크 전부 → experiments/trivy-check-metadata/trivy-<버전>-aws.json + .md
    python3 scripts/trivy_check_meta.py AVD-AWS-0107 AVD-AWS-0345   # 지정한 룰만 화면에

왜: "Trivy 룰 ↔ CIS AWS Benchmark 매핑표" 를 만들 때, Trivy 가 자기 메타데이터에 적어 둔 태그(예: cis-aws-1.2: 4.1, 4.2)는
**실측 가능한 출발점**이다. 단 그것이 최신 CIS 판의 번호와 같다고 가정하지 않는다 — 원문 대조는 사람이 한다 (docs/TRIVY_CIS_MAPPING.md).
읽는 대상: tools/trivy(.exe) 또는 TRIVY_BIN. 네트워크·모델 호출 없음. 바이너리는 수정하지 않는다.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import json
import os
import platform
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_META_RE = re.compile(rb"# METADATA\n((?:#.*\n){3,120}?)package builtin\.aws\.([a-z0-9_.]+)\n")


def trivy_bin() -> Path:
    win = platform.system() == "Windows"
    p = ROOT / "tools" / ("trivy.exe" if win else "trivy")
    if p.exists():
        return p
    env = os.environ.get("TRIVY_BIN")
    if env and Path(env).exists():
        return Path(env)
    raise SystemExit("trivy 가 없다: tools/trivy(.exe) 또는 TRIVY_BIN")


def trivy_version(b: Path) -> str:
    try:
        out = subprocess.run([str(b), "--version"], capture_output=True, text=True, timeout=30).stdout
        m = re.search(r"Version:\s*(\S+)", out)
        return m.group(1) if m else "?"
    except (OSError, subprocess.TimeoutExpired):
        return "?"


def _yaml_list(block: str, key: str) -> list:
    """`#   key:\n#     - a\n#     - b` 형태만 읽는다 (rego 메타데이터는 YAML 주석)."""
    m = re.search(r"^#\s*" + re.escape(key) + r":\s*\n((?:#\s{2,}-\s+.*\n)+)", block, re.M)
    if not m:
        return []
    return [re.sub(r'^"|"$', "", x.strip()) for x in re.findall(r"-\s+(.*)", m.group(1))]


def parse_block(block: str, pkg: str) -> dict:
    d = {"package": "builtin.aws." + pkg}
    for key in ("title", "id", "long_id", "provider", "service", "severity", "recommended_action", "deprecated", "short_code"):
        m = re.search(r"^#\s*" + key + r":\s*(.+)$", block, re.M)
        d[key] = m.group(1).strip().strip('"') if m else ""
    d["avd_id"] = ("AVD-" + d["id"]) if d["id"] and not d["id"].startswith("AVD-") else d["id"]
    d["deprecated"] = d["deprecated"].lower() == "true"
    fw = {}
    m = re.search(r"^#\s*frameworks:\s*\n((?:#\s{4,}.*\n)+)", block, re.M)
    if m:
        cur = None
        for line in m.group(1).splitlines():
            t = line.lstrip("#").rstrip()
            mk = re.match(r"^\s+([a-z0-9.-]+):\s*$", t)
            mv = re.match(r"^\s+-\s+(.*)$", t)
            if mk:
                cur = mk.group(1); fw[cur] = []
            elif mv and cur:
                v = mv.group(1).strip().strip('"')
                if v != "null":
                    fw[cur].append(v)
    d["frameworks"] = {k: v for k, v in fw.items() if v}
    d["related_resources"] = _yaml_list(block, "related_resources")
    return d


def extract(b: Path) -> dict:
    data = b.read_bytes()
    out = {}
    for m in _META_RE.finditer(data):
        blk = m.group(1).decode("utf-8", "replace")
        d = parse_block(blk, m.group(2).decode("ascii", "replace"))
        if d["avd_id"] and d["avd_id"] not in out:
            out[d["avd_id"]] = d
    return dict(sorted(out.items()))


def to_md(version: str, checks: dict, only_services=("ec2", "iam", "s3")) -> str:
    L = [f"# Trivy {version} 내장 체크 메타데이터 — AWS (자동 추출, 사람이 고치지 않음)", "",
         f"- 출처: trivy 바이너리 안의 rego `# METADATA` 블록 (`scripts/trivy_check_meta.py`). 체크 수: {len(checks)}",
         "- `frameworks` 열은 **Trivy 가 스스로 선언한 태그**다. 최신 CIS 판의 번호와 같다고 가정하지 않는다 → `docs/TRIVY_CIS_MAPPING.md` 에서 원문 대조.",
         "- deprecated=true 인 체크는 규칙 본문이 비어 있을 수 있다 (AVD-AWS-0057 실측, D-8).", ""]
    for svc in only_services:
        rows = [c for c in checks.values() if c["service"] == svc]
        L += [f"## service: {svc} ({len(rows)}개)", "", "| AVD | 제목 | 심각도 | deprecated | Trivy 선언 프레임워크 태그 | 참고 링크 |", "|---|---|---|---|---|---|"]
        for c in rows:
            fw = "; ".join(f"{k}: {', '.join(v)}" for k, v in c["frameworks"].items()) or "-"
            refs = ", ".join(c["related_resources"][:2]) or "-"
            L.append(f"| {c['avd_id']} | {c['title']} | {c['severity']} | {'예' if c['deprecated'] else ''} | {fw} | {refs} |")
        L.append("")
    others = [c for c in checks.values() if c["service"] not in only_services]
    L += [f"## 그 밖의 서비스 ({len(others)}개) — 이 프로젝트 범위 밖, 목록만", "",
          ", ".join(f"{c['avd_id']}({c['service']})" for c in others), ""]
    return "\n".join(L)


def main(argv=None) -> int:
    argv = list(_sys.argv[1:] if argv is None else argv)
    b = trivy_bin()
    ver = trivy_version(b)
    checks = extract(b)
    if argv:
        for a in argv:
            print(json.dumps(checks.get(a, {"error": f"{a} 없음"}), ensure_ascii=False, indent=2))
        return 0
    out_dir = ROOT / "experiments" / "trivy-check-metadata"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"trivy-{ver}-aws.json").write_text(json.dumps({"trivy_version": ver, "binary": str(b), "checks": checks}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    (out_dir / f"trivy-{ver}-aws.md").write_text(to_md(ver, checks), encoding="utf-8")
    with_cis = sum(1 for c in checks.values() if any(k.startswith("cis-") for k in c["frameworks"]))
    print(f"trivy {ver}: AWS 체크 {len(checks)}개, CIS 태그 있는 것 {with_cis}개, deprecated {sum(1 for c in checks.values() if c['deprecated'])}개")
    print(f"→ {out_dir / f'trivy-{ver}-aws.md'}")
    return 0


if __name__ == "__main__":
    _sys.exit(main())
