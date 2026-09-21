#!/usr/bin/env python3
"""Claude Code 에 붙여넣을 프롬프트를 케이스별로 만든다 (고정본: experiments/candidate-sets/eval-claude-code/prompt.md).

    python3 scripts/cc_prompt.py 00-baseline          # 화면에 출력 (복사해서 Claude Code 에 붙여넣기)
    python3 scripts/cc_prompt.py --all                # 케이스마다 prompts/<case>.md 파일로 저장

- finding 위치(리소스·줄)는 A 의 Trivy 스캔(scenarios/eval/a-probe/<case>/trivy-scan.json)에서 읽는다. 사람이 적지 않는다.
- 승인 출처는 intent 파일에서 읽는다 (팀 결정값). 프롬프트에는 규칙 기반 생성기가 받는 것과 같은 정보만 들어간다.
- Trivy 가 finding 을 안 낸 케이스(01, 06)는 프롬프트를 만들지 않는다 (not_triggered — LLM 세트에서도 후보 없음으로 기록).
- 이 스크립트는 어떤 모델도 호출하지 않는다. 텍스트만 만든다.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from iacpatch.review.inputs import list_findings, load_trivy_report  # noqa: E402

SET_DIR = ROOT / "experiments" / "candidate-sets" / "eval-claude-code"
CASES_DIR = ROOT / "scenarios" / "eval" / "a-probe"
INTENTS = ROOT / "experiments" / "candidate-sets" / "a-probe-dev" / "intents"
RULE = "AVD-AWS-0107"

TEMPLATE = """다음 Terraform 파일에서 Trivy 가 아래 설정 오류를 보고했다. 파일을 고쳐서 전체 내용을 돌려줘.

- 파일: {filename}  (내용은 아래)
- 룰: {rule} — {title}
- 지목 리소스: {resource}  ({line} 번째 줄)
- 이 SSH(22) 규칙에 허용돼야 하는 출처: {approved}  (그 외 출처는 허용하면 안 된다)
- 다른 리소스나 파일은 만들지 말고, 이 파일의 수정본 전체만 코드 블록 하나로 출력해줘.

```hcl
{content}```
"""


def build(case: str) -> tuple[str, str]:
    """returns (prompt, status). status: 'ok' | 'not_triggered' | 'ambiguous'."""
    cdir = CASES_DIR / case
    report = load_trivy_report(cdir / "trivy-scan.json")
    findings = [f for f in list_findings(report) if f.rule_id == RULE]
    if not findings:
        return "", "not_triggered"
    if len(findings) > 1:
        return "", "ambiguous"
    f = findings[0]
    intent = json.loads((INTENTS / f"{case}.json").read_text(encoding="utf-8"))
    ssh = next(g for g in intent["guarded_services"] if int(g["from_port"]) == 22)
    approved = ", ".join(ssh["approved_sources"]["cidrs_v4"] + ssh["approved_sources"]["cidrs_v6"]) or "(없음)"
    content = (cdir / f.filename).read_text(encoding="utf-8")
    prompt = TEMPLATE.format(filename=f.filename, rule=f.rule_id, title=f.title or "Security group rule allows unrestricted ingress to SSH or RDP",
                             resource=f.resource, line=f.start_line, approved=approved, content=content if content.endswith("\n") else content + "\n")
    return prompt, "ok"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case", nargs="?")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()
    cases = sorted(p.name for p in CASES_DIR.iterdir() if p.is_dir()) if args.all else [args.case]
    if not cases or cases == [None]:
        ap.error("케이스 이름을 주거나 --all")
    out_dir = SET_DIR / "prompts"
    for case in cases:
        prompt, status = build(case)
        if status != "ok":
            print(f"{case}: {status} — 프롬프트 없음 ({'Trivy finding 없음' if status == 'not_triggered' else '0107 finding 이 여러 개, 수동 지정 필요'})")
            continue
        if args.all:
            out_dir.mkdir(exist_ok=True)
            (out_dir / f"{case}.md").write_text(prompt, encoding="utf-8")
            print(f"{case}: → {out_dir / f'{case}.md'}")
        else:
            print(prompt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
