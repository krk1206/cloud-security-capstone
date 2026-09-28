#!/usr/bin/env python3
"""V2 - 패치 전후 Trivy finding 비교 (회귀 확인)

질문: 패치가 새로운 경고를 만들지 않았는가.
사용법: python3 v2_finding_diff.py before.json after.json
종료코드: 0 = PASS (새 finding 없음), 1 = FAIL (새 finding 있음), 2 = 입력 오류
"""
import json
import sys


def fail_input(msg):
    """입력이 잘못됐을 때: 절대 PASS 로 넘어가지 않고 2 로 끝낸다."""
    print(f"[V2] 입력 오류: {msg}", file=sys.stderr)
    sys.exit(2)


def load_findings(path):
    """Trivy JSON 한 개를 읽어 FAIL 인 finding 을 {(룰ID, 리소스), ...} 집합으로 만든다."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        fail_input(f"{path} 읽기 실패: {e}")

    results = data.get("Results") if isinstance(data, dict) else None
    if not results:
        fail_input(f"{path} 에 Results 가 없음 (스캔이 안 된 파일)")

    found = set()
    for r in results:                                   # 파일(Target) 단위
        for m in r.get("Misconfigurations") or []:      # 그 파일의 룰 결과들
            if m.get("Status", "FAIL") != "FAIL":       # PASS 는 finding 이 아니다
                continue
            rule = m.get("AVDID") or m.get("ID") or "?"
            resource = (m.get("CauseMetadata") or {}).get("Resource") or "?"
            found.add((rule, resource))                 # 줄 번호는 일부러 안 쓴다
    return found


def main():
    if len(sys.argv) != 3:
        fail_input("사용법: v2_finding_diff.py before.json after.json")

    before = load_findings(sys.argv[1])
    after = load_findings(sys.argv[2])

    added = sorted(after - before)      # 패치 후에만 있는 것 = 새로 생긴 경고
    removed = sorted(before - after)    # 패치 전에만 있던 것 = 사라진 경고
    verdict = "PASS" if not added else "FAIL"

    report = {
        "before_count": len(before),
        "after_count": len(after),
        "removed": [list(x) for x in removed],
        "added": [list(x) for x in added],
        "verdict": verdict,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if verdict == "PASS" else 1)


if __name__ == "__main__":
    main()
