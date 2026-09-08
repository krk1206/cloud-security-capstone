#!/usr/bin/env python3
"""
검증 A — 0 FAIL 이 '룰을 돌리고 통과' 인지 '파일을 안 읽음' 인지 구분한다.

핵심: Successes > 0 이면 Trivy 가 그 파일을 파싱하고 룰을 적용했다는 뜻이다.
      Results 자체가 없으면 스캔이 일어나지 않은 것이므로 실험 오류다.
"""
import json
import glob
import os
import sys

TARGET_RULE = "AVD-AWS-0107"

def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        return {"_error": str(e)}

def summarize(path):
    d = load(path)
    name = os.path.basename(path).replace(".json", "")

    if "_error" in d:
        return name, None, None, [], "READ_ERROR", d["_error"]

    results = d.get("Results") or []
    if not results:
        return name, None, None, [], "NO_RESULTS", "Results 비어있음"

    succ = fail = 0
    fired = []
    target_status = None
    has_summary = False

    for r in results:
        s = r.get("MisconfSummary")
        if isinstance(s, dict):
            has_summary = True
            succ += s.get("Successes", 0) or 0
            fail += s.get("Failures", 0) or 0
        for m in (r.get("Misconfigurations") or []):
            rid = m.get("AVDID") or m.get("ID") or "?"
            st = m.get("Status", "FAIL")
            if st == "FAIL":
                fired.append(rid)
            if rid == TARGET_RULE:
                target_status = st

    if not has_summary:
        # 구버전/포맷 차이 대비 — 직접 센다
        fail = len(fired)
        succ = None

    return name, succ, fail, fired, "OK", target_status

def main():
    pattern = sys.argv[1] if len(sys.argv) > 1 else "results/*.json"
    files = sorted(glob.glob(pattern))
    if not files:
        print(f"[!] {pattern} 에 파일이 없다. 경로 확인.")
        sys.exit(1)

    print(f"{'케이스':<20} {'통과룰':>7} {'실패룰':>7}  {TARGET_RULE:<14} 발화한 룰")
    print("-" * 92)

    suspicious = []
    for f in files:
        name, succ, fail, fired, state, extra = summarize(f)

        if state != "OK":
            print(f"{name:<20} {'--':>7} {'--':>7}  {'??':<14} !! {state}: {extra}")
            suspicious.append((name, state))
            continue

        succ_s = "?" if succ is None else str(succ)
        tgt = extra if extra else "-"
        fired_s = ", ".join(sorted(set(fired))) if fired else "(없음)"
        print(f"{name:<20} {succ_s:>7} {fail:>7}  {tgt:<14} {fired_s}")

        if fail == 0:
            if succ is None:
                suspicious.append((name, "SUMMARY_없음_확인필요"))
            elif succ == 0:
                suspicious.append((name, "룰이_전혀_안돌았음"))

    print("-" * 92)
    print()
    print("[판정]")
    if suspicious:
        for n, why in suspicious:
            print(f"  ⚠  {n}: {why} — 우회로 판정하면 안 됨")
    else:
        print("  ✅ 모든 케이스에서 룰이 실제로 실행됐다.")
        print("     FAIL 0 인 케이스는 '검사했으나 통과' = 진짜 우회.")
    print()
    print(f"  ※ {TARGET_RULE} 열이 PASS 면 결정적 증거다.")
    print("     (해당 룰이 그 파일을 검사했고 명시적으로 통과시켰다는 뜻)")

if __name__ == "__main__":
    main()
