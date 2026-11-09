#!/usr/bin/env python3
"""워크플로 ③: 상시 환경 반영 전/후 측정(postdeploy 기록)을 비교해 상태를 정하고 댓글용 마크다운을 만든다.

    python scripts/ci_live_compare.py --after data/runs/<id> [--before data/runs/<id>] \
        [--rollback data/runs/<id>] [--plan-check OK|BLOCKED|SKIPPED] [--md out.md] [--github-output $GITHUB_OUTPUT]

상태 (status):
  VERIFIED    반영 후 V7 · V8 이 모두 PASS
  REGRESSION  반영 전에 PASS 였던 검사가 반영 후 FAIL — 되돌려야 한다 (워크플로가 직전 반영본으로 되돌림)
  NOT_CLEAN   나빠진 것은 없지만 FAIL 이 남아 있다 (예: 설정 오류가 아직 고쳐지지 않은 main 을 처음 반영)
  NO_RECORD   반영 후 측정 기록이 없다

비교 단위: V7 은 계층 판정 하나, V8 은 검사(label)마다. 판정은 새로 만들지 않고 기록에 있는 값을 그대로 쓴다.
표준 라이브러리만 쓴다.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Optional


def load_report(run_dir: Optional[str]) -> Optional[dict]:
    if not run_dir:
        return None
    p = Path(run_dir) / "verification_post.json"
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def items(report: Optional[dict]) -> Dict[str, str]:
    """{'V7': 'PASS', 'V8:web-http-open-from-internet': 'PASS', ...}"""
    out: Dict[str, str] = {}
    if not report:
        return out
    for layer in report.get("layers") or []:
        name = str(layer.get("layer"))
        if name == "V8":
            results = ((layer.get("details") or {}).get("results")) or []
            for r in results:
                out[f"V8:{r.get('label', '?')}"] = str(r.get("outcome", "UNKNOWN"))
            if not results:
                out["V8"] = str(layer.get("verdict"))
        else:
            out[name] = str(layer.get("verdict"))
    return out


def layer_verdicts(report: Optional[dict]) -> Dict[str, str]:
    return {str(l.get("layer")): str(l.get("verdict")) for l in (report or {}).get("layers") or []}


def decide(before: Optional[dict], after: Optional[dict]) -> dict:
    if after is None:
        return {"status": "NO_RECORD", "regressions": []}
    b, a = items(before), items(after)
    regressions = sorted(k for k, v in a.items() if v == "FAIL" and b.get(k) == "PASS")
    lv = layer_verdicts(after)
    if regressions:
        status = "REGRESSION"
    elif lv and all(v == "PASS" for v in lv.values()):
        status = "VERIFIED"
    else:
        status = "NOT_CLEAN"
    return {"status": status, "regressions": regressions}


STATUS_KO = {
    "VERIFIED": "반영 후 V7 · V8 모두 PASS",
    "REGRESSION": "반영 전에 되던 것이 반영 후 안 됨 — 직전 반영본으로 되돌림",
    "NOT_CLEAN": "나빠진 것은 없지만 FAIL 이 남아 있음",
    "NO_RECORD": "반영 후 측정 기록 없음",
}


def markdown(before: Optional[dict], after: Optional[dict], rollback: Optional[dict], result: dict, plan_check: str,
             commit: str, prev_commit: str) -> str:
    b, a, r = items(before), items(after), items(rollback)
    keys = sorted(set(b) | set(a) | set(r))
    lines = [
        "## iacpatch 상시 환경 반영 (워크플로 ③)",
        "",
        f"- 결과: **{result['status']}** — {STATUS_KO.get(result['status'], '')}",
        f"- 반영한 커밋: `{commit[:12] or '-'}` · 직전 반영본: `{prev_commit[:12] or '없음 (처음 반영)'}`",
        f"- plan 검사 (교체 · 삭제 차단): **{plan_check}**",
        "",
    ]
    if keys:
        head = "| 검사 | 반영 전 | 반영 후 |" + (" 되돌린 뒤 |" if rollback else "")
        sep = "|---|---|---|" + ("---|" if rollback else "")
        lines += [head, sep]
        for k in keys:
            row = f"| {k} | {b.get(k, '-')} | {a.get(k, '-')} |"
            if rollback:
                row += f" {r.get(k, '-')} |"
            lines.append(row)
        lines.append("")
    if result["regressions"]:
        lines += ["나빠진 검사: " + ", ".join(f"`{x}`" for x in result["regressions"]), ""]
        lines += ["다음 할 일: main 의 해당 변경을 되돌리는 PR(revert)을 사람이 만든다. 상시 환경은 이미 직전 반영본으로 돌아가 있다.", ""]
    if result["status"] == "NOT_CLEAN" and not result["regressions"]:
        lines += ["다음 할 일: 남은 FAIL 은 아직 고쳐지지 않은 설정 오류다. 워크플로 ① 이 만드는 패치 PR 로 고친 뒤 다시 반영한다.", ""]
    lines += ["V7 = 실제 AWS 보안 그룹 설정이 설계(intent)와 같은가, V8 = 인터넷(러너)에서 80 은 열리고 22 · 3389 는 막히는가.", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--before")
    ap.add_argument("--after")
    ap.add_argument("--rollback")
    ap.add_argument("--plan-check", default="SKIPPED")
    ap.add_argument("--commit", default="")
    ap.add_argument("--prev-commit", default="")
    ap.add_argument("--md", help="마크다운을 쓸 파일 (없으면 화면)")
    ap.add_argument("--github-output", help="status=... regression=... 을 덧붙일 파일 ($GITHUB_OUTPUT)")
    a = ap.parse_args()
    before, after, rollback = load_report(a.before), load_report(a.after), load_report(a.rollback)
    result = decide(before, after)
    md = markdown(before, after, rollback, result, a.plan_check, a.commit, a.prev_commit)
    if a.md:
        Path(a.md).write_text(md, encoding="utf-8")
    else:
        print(md)
    if a.github_output:
        with open(a.github_output, "a", encoding="utf-8") as f:
            f.write(f"status={result['status']}\n")
            f.write(f"regression={'true' if result['regressions'] else 'false'}\n")
    print(f"status={result['status']} regressions={result['regressions']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
