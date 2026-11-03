#!/usr/bin/env bash
# ============================================================
#  Trivy SG 우회 실험 — 검증 스크립트
#  trivy-sg-probe/ 디렉터리 안에서 실행할 것
#
#  A. 0 FAIL 이 '검사 후 통과' 인지 '스캔 실패' 인지 구분
#  B. CIDR 한 줄만 다른 대조군(01b)과 비교
#  C. 우회 케이스가 문법적으로 유효한지 확인
# ============================================================
set -uo pipefail

RESULTS_DIR="results-verify"
mkdir -p "$RESULTS_DIR"

hr() { printf '%*s\n' 70 '' | tr ' ' '='; }

hr
echo " 환경"
hr
trivy --version 2>/dev/null | head -3 || { echo "[!] trivy 없음"; exit 1; }
echo
if command -v terraform >/dev/null 2>&1; then
  terraform version | head -1
else
  echo "terraform 없음 — 검증 C 는 건너뛴다"
fi
echo

hr
echo " 검증 B — 최소 쌍 대조군 생성"
hr
python3 make_control.py || echo "[!] 대조군 생성 실패 — 수동으로 만들어야 한다"
echo

hr
echo " 재스캔 (--include-non-failures 로 PASS 기록까지 확보)"
hr
for d in cases/*/; do
  name=$(basename "$d")
  trivy config "$d" \
    --format json \
    --include-non-failures \
    --output "$RESULTS_DIR/${name}.json" \
    --quiet 2>/dev/null
  printf '  scanned  %s\n' "$name"
done
echo

hr
echo " 검증 A — 룰이 실제로 실행됐는가"
hr
python3 inspect_results.py "$RESULTS_DIR/*.json"
echo

hr
echo " 검증 B 결과 — 01 vs 01b"
hr
python3 - <<'PY'
import json, os
def read(p):
    if not os.path.exists(p): return None
    d = json.load(open(p, encoding="utf-8"))
    out = {"succ":0, "fail":0, "s0107":None}
    for r in (d.get("Results") or []):
        s = r.get("MisconfSummary") or {}
        out["succ"] += s.get("Successes", 0) or 0
        out["fail"] += s.get("Failures", 0) or 0
        for m in (r.get("Misconfigurations") or []):
            if (m.get("AVDID") or m.get("ID")) == "AVD-AWS-0107":
                out["s0107"] = m.get("Status", "FAIL")
    return out

a = read("results-verify/01-cidr-split.json")
b = read("results-verify/01b-control.json")

if not a or not b:
    print("  [!] 결과 파일이 없다. 위 재스캔 단계를 확인해라.")
else:
    print(f"  01-cidr-split  [0.0.0.0/1 + 128.0.0.0/1]  실패={a['fail']}  0107={a['s0107']}")
    print(f"  01b-control    [0.0.0.0/0]                실패={b['fail']}  0107={b['s0107']}")
    print()
    if b["fail"] > 0 and a["fail"] == 0:
        print("  ✅ 확정: CIDR 값 하나 차이로 결과가 갈렸다.")
        print("     파일 구조·리소스명·문법이 동일하므로 원인은 CIDR 이다. 진짜 우회.")
    elif b["fail"] == 0:
        print("  ❌ 대조군(0.0.0.0/0)도 FAIL 이 안 났다.")
        print("     01 파일 자체에 문제가 있다. 00-baseline 과 비교해봐라.")
    else:
        print("  ⚠  둘 다 FAIL — 우회가 아니다. 결과를 다시 봐라.")
PY
echo

if command -v terraform >/dev/null 2>&1; then
  hr
  echo " 검증 C — 문법 유효성 (배포 가능한 코드인가)"
  hr
  for c in 01-cidr-split 01b-control 06-prefix-list; do
    [ -d "cases/$c" ] || continue
    printf '  %-16s ' "$c"
    ( cd "cases/$c" \
      && terraform init -backend=false -input=false >/dev/null 2>&1 \
      && terraform validate >/dev/null 2>&1 ) \
      && echo "valid ✅" || echo "INVALID ❌  ← 우회가 아니라 그냥 깨진 코드일 수 있음"
  done
  echo
fi

hr
echo " 판정 기준"
hr
cat <<'TXT'
  진짜 우회로 인정하려면 3개 모두 만족해야 한다.

    A. 통과룰 > 0  (또는 0107 이 PASS)   → 룰이 실제로 실행됐다
    B. 01b 는 FAIL, 01 은 0 FAIL         → 원인이 CIDR 이다
    C. terraform validate 통과           → 배포 가능한 코드다

  하나라도 어긋나면 실험 오류로 보고 우회 주장을 하지 않는다.
TXT
