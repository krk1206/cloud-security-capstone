#!/usr/bin/env python3
"""Claude Code 가 준 응답을 후보로 등록한다 (eval-claude-code 세트).

    python3 scripts/cc_add.py <case> <응답파일> --rep 1 --expected correct --note "2026-09-17 Claude Code 대화 #3"

- <응답파일>: Claude Code 응답을 그대로 저장한 .md/.txt (코드 블록 하나를 꺼낸다) 또는 이미 꺼낸 .tf
- 저장: experiments/candidate-sets/eval-claude-code/candidates/cc-<case>-r<rep>.tf  (같은 이름이 있으면 거부)
- manifest.json 에 항목 추가. expected 는 **파일을 읽고** 사람이 적는다 — 이 스크립트가 판정하지 않는다.
  등록 전에 원본과의 diff 를 보여주니 라벨이 맞는지 눈으로 확인할 것.
- 이 스크립트는 어떤 모델도 호출하지 않는다.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import argparse
import difflib
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SET_DIR = ROOT / "experiments" / "candidate-sets" / "eval-claude-code"
sys.path.insert(0, str(ROOT / "scripts"))
from cc_cases import resolve  # noqa: E402
EXPECTED = ["correct", "deceptive", "breaks_required", "unapproved", "unknown", "invalid"]
_FENCE_RE = re.compile(r"```(?:hcl|terraform|tf)?[ \t]*\n(.*?)```", re.DOTALL)


def extract_tf(text: str) -> str:
    """마크다운 응답이면 코드 블록(가장 긴 것) 을, 아니면 전체를 돌려준다."""
    blocks = _FENCE_RE.findall(text)
    if blocks:
        return max(blocks, key=len)
    return text


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case")
    ap.add_argument("response")
    ap.add_argument("--rep", type=int, required=True, help="반복 번호 (1, 2, 3 ...)")
    ap.add_argument("--expected", required=True, choices=EXPECTED, help="파일을 읽고 사람이 적는 기대 라벨")
    ap.add_argument("--note", default="", help="날짜·대화 식별·모델 표시 (Claude Code 화면에 보이는 대로)")
    ap.add_argument("--yes", action="store_true", help="diff 확인 질문 없이 등록")
    args = ap.parse_args()
    kind, name, cdir, tf_dir, intent_rel, rule = resolve(args.case)
    if not cdir.is_dir():
        print(f"케이스 없음: {cdir}"); return 2
    src = Path(args.response)
    if not src.exists():
        print(f"응답 파일 없음: {src}"); return 2
    raw = src.read_text(encoding="utf-8")
    tf = extract_tf(raw)
    if not tf.strip():
        print("응답에서 Terraform 내용을 못 찾았다 (코드 블록이 비어 있음). expected=invalid 로 등록하려면 빈 파일을 그대로 넣어라"); return 2
    if not tf.endswith("\n"):
        tf += "\n"
    cid = f"cc-{args.case}-r{args.rep}"
    dst = SET_DIR / "candidates" / f"{cid}.tf"
    if dst.exists():
        print(f"이미 있음: {dst} — 다른 --rep 번호를 써라 (덮어쓰지 않는다)"); return 2
    original = (cdir / "main.tf").read_text(encoding="utf-8")
    diff = list(difflib.unified_diff(original.splitlines(), tf.splitlines(), "original/main.tf", f"{cid}.tf", lineterm=""))
    print("\n".join(diff) if diff else "(원본과 동일 — expected 는 invalid 여야 한다)")
    print()
    print(f"expected={args.expected}  source=claude-code  sha256={hashlib.sha256(tf.encode('utf-8')).hexdigest()[:12]}")
    if not args.yes:
        ans = input("이 diff 를 보고 적은 라벨이 맞나? 등록하려면 y: ").strip().lower()
        if ans != "y":
            print("등록 안 함"); return 1
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(tf, encoding="utf-8")
    man = SET_DIR / "manifest.json"
    m = json.loads(man.read_text(encoding="utf-8"))
    if any(c["id"] == cid for c in m["candidates"]):
        print(f"manifest 에 이미 {cid} 가 있다"); return 2
    m["candidates"].append({
        "id": cid, "tf_dir": tf_dir, "trivy_json": f"{tf_dir}/trivy-scan.json", "intent": intent_rel, "rule": rule,
        "candidate": f"manual:candidates/{cid}.tf", "source": "claude-code", "expected": args.expected, "kind": kind,
        "note": (args.note or "Claude Code 응답을 사람이 저장") + f" | 원본 응답: {src.name}",
    })
    man.write_text(json.dumps(m, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # 원본 응답도 보관 (나중에 "정말 모델이 이렇게 답했나" 확인용)
    keep = SET_DIR / "responses"; keep.mkdir(exist_ok=True)
    (keep / f"{cid}{src.suffix or '.txt'}").write_text(raw, encoding="utf-8")
    print(f"등록: {dst.relative_to(ROOT)}  (manifest {len(m['candidates'])}건). 실행: scripts/run_experiments.sh 또는 run_candidate_set.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
