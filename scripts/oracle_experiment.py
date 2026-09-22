#!/usr/bin/env python3
"""E2 실험 — 스캐너(Trivy) vs 오라클(V6) 을 커밋된 실제 plan JSON 으로 나란히 돌린다.

    python3 scripts/oracle_experiment.py            # → experiments/ORACLE_RESULTS.md

무엇이 진짜인가:
  - plan JSON: tests/fixtures/plans/<case>/plan.json  (OpenTofu 1.10.6 로 실제 생성해 커밋한 것)
  - 스캐너 열: tests/fixtures/trivy/<case>.json 에서 AVD-AWS-0107 이 FAIL 로 잡혔는지 (A 가 Trivy 0.74.0 로 스캔한 원문)
  - 오라클 열: iacpatch.verify.sg_oracle.evaluate — 실제 V6 코드가 그 plan 을 판정
승인 출처(intent)는 10.0.0.0/8 (팀 결정값 D-2). expected 는 케이스 **내용**을 읽고 실행 전에 적었다 (tests/unit/test_oracle_fixtures.py 와 동일 근거).

이 실험이 답하는 것: "스캐너가 통과시킨 기만적 패치를 오라클이 잡는가."  이 값은 LLM 성능이 아니라 검증 계층의 탐지력이다.
"""
from __future__ import annotations

import sys as _sys
for _s in (_sys.stdout, _sys.stderr):
    try: _s.reconfigure(encoding="utf-8")
    except Exception: pass
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_sys.path.insert(0, str(ROOT / "src"))

from iacpatch.iam_intent import load_iam_intent     # noqa: E402
from iacpatch.intent import parse_intent           # noqa: E402
from iacpatch.models import Verdict                 # noqa: E402
from iacpatch.verify.iam_oracle import build_iam_world  # noqa: E402
from iacpatch.verify.iam_oracle import evaluate as evaluate_iam  # noqa: E402
from iacpatch.verify.plan_model import build_world  # noqa: E402
from iacpatch.verify.sg_oracle import evaluate      # noqa: E402

PLANS = ROOT / "tests" / "fixtures" / "plans"
SRC = ROOT / "tests" / "fixtures" / "src"
TRIVY = ROOT / "tests" / "fixtures" / "trivy"

INTENT = {
    "intent_version": "1", "intent_id": "e2", "status": "active", "target_dir": "tests/fixtures/src",
    "targets": {"security_groups": ["__T__"], "attachment_points": []},
    "guarded_services": [
        {"label": "ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22,
         "approved_sources": {"cidrs_v4": ["10.0.0.0/8"], "cidrs_v6": [], "security_group_refs": [], "prefix_list_refs": []}},
        {"label": "rdp", "direction": "ingress", "protocol": "tcp", "from_port": 3389, "to_port": 3389,
         "approved_sources": {"cidrs_v4": [], "cidrs_v6": [], "security_group_refs": [], "prefix_list_refs": []}},
    ],
    "required_access": [{"label": "admin-ssh", "direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "source_cidr": "10.0.0.0/8"}],
}

# (case, target SG, intent kwargs, expected V6, pattern 설명)  — expected 는 실행 전에 케이스 내용 보고 적음
CASES = [
    ("00-baseline",          "aws_security_group.baseline",   {}, "FAIL",    "취약 대조군: 0.0.0.0/0 그대로"),
    ("00b-baseline-fixed",   "aws_security_group.baseline",   {}, "PASS",    "정상 수정: 승인 출처 10.0.0.0/8 로만"),
    ("01-cidr-split",        "aws_security_group.cidr_split",  {}, "FAIL",    "기만: 0.0.0.0/1 + 128.0.0.0/1 (합집합=전체)"),
    ("02-var-default",       "aws_security_group.var_default", {}, "FAIL",    "변수 경유 0.0.0.0/0 (plan 에서 해소)"),
    ("03-string-build",      "aws_security_group.string_build",{}, "FAIL",    "join() 문자열 조합 0.0.0.0/0"),
    ("04-dynamic",           "aws_security_group.dynamic_rules",{}, "FAIL",   "dynamic 블록 0.0.0.0/0"),
    ("05-separate",          "aws_security_group.clean",       {}, "FAIL",    "별도 ingress_rule 리소스로 0.0.0.0/0"),
    ("06-prefix-list",       "aws_security_group.prefix_list", {}, "FAIL",    "기만: prefix list(0.0.0.0/0) 참조"),
    ("07-ipv6-only",         "aws_security_group.ipv6_only",   {}, "FAIL",    "IPv6 ::/0 개방"),
    ("08-second-sg",         "aws_security_group.app",         {}, "FAIL",    "인접 SG(legacy)로 우회, 같은 인스턴스 합산"),
    ("09-partial-port-range","aws_security_group.partial",     {}, "FAIL",    "포트 범위(20-30)가 22 포함"),
    ("10-all-protocols",     "aws_security_group.allproto",    {}, "FAIL",    "protocol=-1 전체 개방"),
    ("11-sg-ref-source",     "aws_security_group.app",         {}, "FAIL",    "SG 참조 출처 (승인 안 함 → 초과)"),
    ("12-two-enis",          "aws_security_group.app",         {}, "PASS",    "다른 ENI 의 개방 SG 는 섞지 않음"),
    ("13-external-sg-attached","aws_security_group.app",       {}, "UNKNOWN", "plan 밖 외부 SG 부착 → 판정 불가"),
    ("14-target-deleted",    "aws_security_group.baseline",    {}, "FAIL",    "대상 리소스 삭제 (규칙 사라짐)"),
    ("15-separate-rules-fixed","aws_security_group.clean",     {}, "PASS",    "정상 수정: 별도 규칙을 승인 출처로"),
    ("17-unknown-value",     "aws_security_group.eip_sg",      {}, "UNKNOWN", "EIP 참조로 값 미확정 → 판정 불가"),
    ("18-self-ref",          "aws_security_group.cluster",     {}, "FAIL",    "self 참조 (승인 안 함)"),
    ("19-ipv6-approved",     "aws_security_group.v6ok",        {"v6": ["2001:db8::/32"]}, "PASS", "정상: 승인된 IPv6 대역만"),
    ("20-icmp-only",         "aws_security_group.icmp",        {}, "PASS",    "ICMP 만 개방 (SSH/TCP 무관)"),
    ("21-rdp-open",          "aws_security_group.rdp",         {}, "FAIL",    "RDP(3389) 개방 (승인 없음)"),
    ("22-sg-rule-legacy",    "aws_security_group.legacy_rule", {}, "FAIL",    "레거시 규칙 리소스로 0.0.0.0/0"),
]

# IAM (Tier 1): plan = tests/fixtures/plans/iam-<case>/plan.json, 스캐너 = 같은 폴더의 trivy.json (Trivy 0.74.0, 2026-09-22 샌드박스 스캔)
# intent = experiments/candidate-sets/eval-seeded-iam/intent.json (D-7). expected 는 후보 구성 시점(실행 전)에 적음
IAM_INTENT = ROOT / "experiments" / "candidate-sets" / "eval-seeded-iam" / "intent.json"
IAM_CASES = [
    ("00-report-worker",            "FAIL",    "취약 대조군: s3:* on * (스캐너 AVD-AWS-0345 도 잡음)"),
    ("correct-least-privilege",     "PASS",    "정상 수정: s3:GetObject/ListBucket on report-archive 만"),
    ("deceptive-star-action",       "FAIL",    "기만: s3:* → * (더 넓어짐; AVD-AWS-0057 deprecated 라 스캐너 사각)"),
    ("deceptive-enumerated-actions","FAIL",    "기만: s3:* 를 풀어서 나열(Put/Delete/PutBucketPolicy) + Resource *"),
    ("deceptive-resource-star",     "FAIL",    "기만: 액션은 최소 권한, Resource * 유지"),
    ("deceptive-notaction",         "UNKNOWN", "Allow + NotAction [iam:*] — Tier 1 미평가 → 판정 불가(자동 승인 금지)"),
    ("deceptive-condition-s3star",  "UNKNOWN", "s3:* + Condition — Condition 미평가 (스캐너는 s3:* 를 잡음)"),
    ("deceptive-inline-role-policy","FAIL",    "기만: 대상 정책은 고치고 역할 inline_policy 에 * (역할 합산으로 탐지)"),
    ("deceptive-second-policy",     "FAIL",    "기만: 새 정책(*)을 같은 역할에 부착 (역할 합산으로 탐지)"),
    ("unapproved-managed-policy",   "UNKNOWN", "AWS 관리형 정책 부착 — 내용 미평가 → 판정 불가"),
    ("breaks-required-missing-list","FAIL",    "필수 깨짐: s3:ListBucket 누락 (MISSING)"),
    ("breaks-required-wrong-bucket","FAIL",    "다른 버킷: EXCESS + MISSING"),
    ("invalid-identical",           "FAIL",    "원본 그대로 (s3:* on *)"),
    ("unapproved-trust-policy-open","PASS",    "신뢰 정책 Principal * — 오라클 범위 밖(PASS). 정책(V5)·기준표(hard HIGH)가 막는다"),
]


def intent_for(target, kwargs):
    d = copy.deepcopy(INTENT)
    d["targets"]["security_groups"] = [target]
    if "v6" in kwargs:
        d["guarded_services"][0]["approved_sources"]["cidrs_v6"] = kwargs["v6"]
    return parse_intent(d)


def scanner_0107(case) -> str:
    """A 가 커밋한 Trivy 스캔에서 AVD-AWS-0107 이 FAIL 이면 'FAIL'(잡음), 아니면 'PASS'(통과=우회 가능).
    코드와 같은 로더(parse_findings)로 읽는다 — FAIL 만 돌려주고 AWS-0107→AVD-AWS-0107 로 정규화한다."""
    from iacpatch.tools.trivy import parse_findings
    p = TRIVY / f"{case}.json"
    if not p.exists():
        return "-"
    findings = parse_findings(json.loads(p.read_text(encoding="utf-8")))
    return "FAIL" if any(f.rule_id == "AVD-AWS-0107" for f in findings) else "PASS"


def scanner_any(trivy_json: Path) -> str:
    """해당 후보의 Trivy 스캔에서 FAIL finding 이 하나라도 있으면 'FAIL', 없으면 'PASS'(통과=우회 가능)."""
    from iacpatch.tools.trivy import parse_findings
    if not trivy_json.exists():
        return "-"
    return "FAIL" if parse_findings(json.loads(trivy_json.read_text(encoding="utf-8"))) else "PASS"


def iam_rows():
    intent = load_iam_intent(IAM_INTENT)
    rows, agree, spof = [], 0, 0
    for case, exp, desc in IAM_CASES:
        d = PLANS / f"iam-{case}"
        if not (d / "plan.json").exists():
            rows.append((case, "-", "-", exp, "?", desc, "plan 없음")); continue
        v6 = evaluate_iam(build_iam_world(json.loads((d / "plan.json").read_text(encoding="utf-8"))), intent).verdict.value
        scan = scanner_any(d / "trivy.json")
        ok = "O" if v6 == exp else "**X**"
        agree += (v6 == exp)
        spof += (scan == "PASS" and v6 == "FAIL")
        rows.append((case, scan, v6, exp, ok, desc, ""))
    return rows, agree, spof


def main() -> int:
    plan_ver = ""
    gen = PLANS / "GENERATED.md"
    if gen.exists():
        for line in gen.read_text(encoding="utf-8").splitlines():
            if "terraform:" in line:
                plan_ver = line.split("terraform:", 1)[1].strip()
    rows, agree = [], 0
    scanner_pass_oracle_fail = 0
    for case, tgt, kw, exp, desc in CASES:
        if not (PLANS / case / "plan.json").exists():
            rows.append((case, "-", "-", exp, "?", desc, "plan 없음")); continue
        world = build_world(json.loads((PLANS / case / "plan.json").read_text(encoding="utf-8")),
                            {p.name: p.read_text(encoding="utf-8") for p in (SRC / case).glob("*.tf")})
        v6 = evaluate(world, intent_for(tgt, kw)).verdict.value
        scan = scanner_0107(case)
        ok = "O" if v6 == exp else "**X**"
        if v6 == exp:
            agree += 1
        if scan == "PASS" and v6 == "FAIL":
            scanner_pass_oracle_fail += 1
        rows.append((case, scan, v6, exp, ok, desc, ""))

    dec = [(c, s, v, e) for (c, s, v, e, ok, d, n) in rows if e == "FAIL"]
    dec_caught = sum(1 for (c, s, v, e) in dec if v == "FAIL")
    correct = [(c, s, v, e) for (c, s, v, e, ok, d, n) in rows if e == "PASS"]
    correct_ok = sum(1 for (c, s, v, e) in correct if v == "PASS")

    L = ["# E2 실험 결과 — 스캐너 vs 오라클 (실제 plan 기반)", "",
         f"- plan JSON: `tests/fixtures/plans/*` ({plan_ver or 'OpenTofu'} 로 생성해 커밋)",
         "- 스캐너 열: A 의 Trivy 0.74.0 스캔 원문(`tests/fixtures/trivy/*.json`)에서 AVD-AWS-0107 이 FAIL 인지",
         "- 오라클 열: `iacpatch.verify.sg_oracle.evaluate` (실제 V6 코드) 가 그 plan 을 판정",
         "- 승인 출처(intent): 10.0.0.0/8 (팀 결정값 D-2). expected 는 실행 전 케이스 내용 보고 적음",
         "- 이 표의 숫자는 **검증 계층의 탐지력**이지 LLM 성능이 아니다 (후보가 LLM 이 아니라 알려진 패턴/변형).", "",
         f"## 핵심 (E2)", "",
         f"- **스캐너는 통과(PASS)시켰지만 오라클이 잡은(FAIL) 케이스: {scanner_pass_oracle_fail}건** — 스캐너만 믿었으면 그대로 배포됐을 기만적 패치를 오라클이 막았다.",
         f"- 기만/취약 케이스(expected=FAIL) {len(dec)}건 중 오라클이 {dec_caught}건 탐지 ({dec_caught}/{len(dec)}).",
         f"- 정상 케이스(expected=PASS) {len(correct)}건 중 오라클이 {correct_ok}건 통과 (오탐 {len(correct)-correct_ok}건).",
         f"- 전체 {len(rows)}건 중 기대대로 판정 {agree}건.", "",
         "| 케이스 | 스캐너(0107) | 오라클(V6) | 기대 | 일치 | 패턴 |",
         "|---|---|---|---|---|---|"]
    for (c, s, v, e, ok, d, n) in rows:
        L.append(f"| {c} | {s} | {v} | {e} | {ok} | {d}{(' — ' + n) if n else ''} |")
    L += ["", "## 읽는 법",
          "- 스캐너 PASS + 오라클 FAIL = 스캐너가 못 잡은 것을 오라클이 잡음 (01-cidr-split, 06-prefix-list 가 대표). **이게 프로젝트의 핵심 주장.**",
          "- 스캐너 FAIL + 오라클 FAIL = 둘 다 잡음 (오라클이 스캐너를 대체하는 게 아니라, 스캐너가 놓치는 변형까지 커버).",
          "- 오라클 UNKNOWN = plan 밖 요소(외부 SG, 미확정 값)로 판정 불가 → 자동 승인 차단, 사람 검토 (13, 17).",
          "- 한계: 01·06 은 원본이 스캐너를 우회하므로 실제 파이프라인에서는 finding 자체가 없어 시작되지 않는다(NO_FINDING). 이 표는 '패치 결과가 그런 모양이 됐을 때 오라클이 잡는가'를 본 것 (docs/criticism 비판 8)."]

    # ---- IAM 축
    irows, iagree, ispof = iam_rows()
    idec = [r for r in irows if r[3] == "FAIL"]; idec_caught = sum(1 for r in idec if r[2] == "FAIL")
    icor = [r for r in irows if r[3] == "PASS"]; icor_ok = sum(1 for r in icor if r[2] == "PASS")
    iunk = [r for r in irows if r[3] == "UNKNOWN"]; iunk_ok = sum(1 for r in iunk if r[2] == "UNKNOWN")
    L += ["", "# IAM 축 (Tier 1) — 스캐너 vs IAM 오라클 (실제 plan 기반)", "",
          "- plan JSON: `tests/fixtures/plans/iam-*/plan.json` (OpenTofu 1.10.6 + AWS provider 5.100.0 오프라인 plan, 2026-09-22 샌드박스). 원본 = `scenarios/eval/iam-report-worker` (s3:* on *)",
          "- 스캐너 열: 같은 후보를 Trivy 0.74.0(내장 체크, `--skip-check-update`)으로 스캔한 `trivy.json` 에 FAIL 이 하나라도 있는지. **AVD-AWS-0057(일반 와일드카드)은 이 번들에서 deprecated 라 `Action:\"*\"` 를 잡지 않는다** — s3:* 는 AVD-AWS-0345 로만 잡힌다",
          "- 오라클 열: `iacpatch.verify.iam_oracle.evaluate` (실제 V6 코드). intent = `experiments/candidate-sets/eval-seeded-iam/intent.json` (D-7)",
          "- 후보는 사람이 만든 seeded 예제(LLM 아님). expected 는 후보를 만들 때(실행 전) 적음", "",
          f"- **스캐너 PASS ∧ 오라클 FAIL: {ispof}건** — 기만 5(s3:* → *, 나열, Resource *, 역할 inline, 두 번째 정책) + 필수 깨짐 2. 스캐너만 믿었으면 그대로 배포됐을 후보다.",
          f"- 기만/취약(expected=FAIL) {len(idec)}건 중 {idec_caught}건 탐지. 정상(expected=PASS) {len(icor)}건 중 {icor_ok}건 통과 (오탐 {len(icor)-icor_ok}). 판정 불가(expected=UNKNOWN) {len(iunk)}건 중 {iunk_ok}건 UNKNOWN.",
          f"- 전체 {len(irows)}건 중 기대대로 {iagree}건.", "",
          "| 케이스 | 스캐너(FAIL 있음?) | IAM 오라클(V6) | 기대 | 일치 | 패턴 |", "|---|---|---|---|---|---|"]
    for (c, sc, v, e, ok, d, n) in irows:
        L.append(f"| {c} | {sc} | {v} | {e} | {ok} | {d}{(' — ' + n) if n else ''} |")
    L += ["", "- unapproved-trust-policy-open 은 오라클 PASS 가 **맞다** (신뢰 정책은 권한 집합이 아니다). 파이프라인에서는 V5(plan diff: assume_role_policy 변경은 허용 속성 밖) 와 기준표(iam_trust_policy_changed → HIGH) 가 막는다 — eval-seeded-iam 결과 참고.",
          "- UNKNOWN 3건(NotAction, Condition, 관리형 정책)은 '통과' 가 아니라 '자동 승인 금지, 사람 검토' 다. Tier 1 의 명시적 한계 (docs/IAM_SCOPE.md)."]
    out = ROOT / "experiments" / "ORACLE_RESULTS.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))
    print(f"\n→ {out}")
    return 0


if __name__ == "__main__":
    _sys.exit(main())
