"""CLI.  `python -m iacpatch <command> ...`

  predeploy   스캔 → 패치 후보 → V1~V6 → 위험도 → 게이트 → PR 본문 (apply/push/PR 생성은 하지 않음)
  oracle      plan JSON + intent 로 V6 만 실행 (디버깅/실험용)
  scan        Trivy 스캔만
  pr          run record 로부터 브랜치/커밋/PR 준비. --execute 없으면 명령만 출력
  postdeploy  V7(AWS 실측) + V8(통신 확인). --execute 없으면 실행할 명령만 출력
  recover     배포 후 실패 복구 절차 (revert → plan → apply(승인) → V7 재확인)
  selfcheck   도구 존재/버전 확인

B·C 3~4주차 (외부 도구·API 없이 파일 입력만으로):
  findings    Trivy JSON 의 finding 목록 조회 (대상 선택 조건 확인용)
  review      원본 + Trivy JSON + 후보(mock/manual) → 기록·검증 연결·위험도·review.md/pr_body.md
  metrics     data/reviews (또는 data/runs) 기록을 집계해 수치 표 출력
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .config import load_settings


def _settings(args: argparse.Namespace):
    ov = {}
    for k in ("terraform_bin", "trivy_bin", "aws_bin", "aws_profile", "aws_region", "llm_provider", "llm_model", "llm_base_url",
              "llm_mock_fixture", "prompt_version", "data_dir", "tf_var_file"):
        v = getattr(args, k, None)
        if v:
            ov[k] = v
    if getattr(args, "offline", None) is not None:
        ov["offline_plan"] = args.offline
    if getattr(args, "max_attempts", None):
        ov["max_attempts"] = args.max_attempts
    return load_settings(getattr(args, "repo_root", None), ov)


def cmd_selfcheck(args: argparse.Namespace) -> int:
    from .tools.terraform import TerraformAdapter
    from .tools.trivy import TrivyAdapter
    from .tools.runner import which
    s = _settings(args)
    tf = TerraformAdapter(s.terraform_bin, s.aws_region).info()
    tv = TrivyAdapter(s.trivy_bin)
    print(f"repo_root      : {s.repo_root}")
    print(f"terraform      : {'OK' if tf.available else 'MISSING'} {tf.kind} {tf.version} ({s.terraform_bin})")
    print(f"trivy          : {'OK ' + tv.version() if tv.available() else 'MISSING'} ({s.trivy_bin})")
    print(f"aws cli        : {'OK' if which(s.aws_bin) else 'MISSING'} ({s.aws_bin}); profile={s.aws_profile or '-'} region={s.aws_region}")
    print(f"llm provider   : {s.llm_provider} model={s.llm_model or '-'} (key from env: {'set' if any(os.environ.get(k) for k in ('LLM_API_KEY','ANTHROPIC_API_KEY','OPENAI_API_KEY')) else 'not set'})")
    print(f"offline plan   : {s.offline_plan}")
    print(f"policy         : {s.policy_file} / {s.rubric_file}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    from .tools.trivy import TrivyAdapter
    s = _settings(args)
    tv = TrivyAdapter(s.trivy_bin)
    out = args.output or None
    res = tv.scan_dir(s.path(args.target_dir), out, tf_vars=(str(s.path(args.target_dir) / s.tf_var_file) if s.tf_var_file else None))
    if not res.ok:
        print("scan failed:", res.error)
        return 2
    print(f"trivy {res.version}: {res.summary}")
    for f in res.findings:
        print(f"  {f.rule_id} {f.severity:8s} {f.filename}:{f.start_line} {f.resource}  {f.title[:70]}")
    return 0


def cmd_predeploy(args: argparse.Namespace) -> int:
    from .pipeline import run_predeploy
    s = _settings(args)
    res = run_predeploy(s, args.target_dir, args.intent, args.scenario, generator_kind=args.generator,
                        target_resource=args.resource, workspace=args.workspace, keep_workspace=args.keep_workspace)
    print(res.console())
    print(f"  record: {res.run_dir}")
    return 0 if res.status in ("DONE",) else 1


def cmd_oracle(args: argparse.Namespace) -> int:
    from .intent import try_load_intent
    from .verify.plan_model import load_plan
    from .verify.v6 import v6_intent_oracle
    intent, err = try_load_intent(args.intent)
    plan = load_plan(args.plan)
    sources = {}
    if args.src_dir:
        for p in Path(args.src_dir).glob("*.tf"):
            sources[p.name] = p.read_text(encoding="utf-8")
    ext = json.loads(Path(args.prefix_lists).read_text()) if args.prefix_lists else None
    lr = v6_intent_oracle(plan, sources, intent, err, ext)
    print(f"V6 {lr.verdict.value}: {lr.summary}")
    if args.json:
        print(json.dumps(lr.to_dict(), ensure_ascii=False, indent=2))
    return 0 if lr.verdict.value == "PASS" else 1


def cmd_pr(args: argparse.Namespace) -> int:
    from .tools.github import prepare_pr
    s = _settings(args)
    return prepare_pr(s, args.run, execute=args.execute, base_branch=args.base, remote=args.remote, draft=args.draft)


def cmd_postdeploy(args: argparse.Namespace) -> int:
    from .postdeploy import run_postdeploy
    s = _settings(args)
    res = run_postdeploy(s, args.intent, args.sg_ids, args.v8_checks, execute=args.execute, run_id=args.run,
                         tf_dir=args.tf_dir)
    print(res)
    return 0


def cmd_recover(args: argparse.Namespace) -> int:
    from .postdeploy import run_recover
    s = _settings(args)
    return run_recover(s, args.run, execute=args.execute, tf_dir=args.tf_dir)


def cmd_findings(args: argparse.Namespace) -> int:
    from .review.inputs import FindingSelector, TrivyInputError, list_findings, load_trivy_report, select_findings
    s = _settings(args)
    try:
        report = load_trivy_report(s.path(args.trivy_json))
    except TrivyInputError as e:
        print(f"입력 오류: {e}")
        return 2
    findings = list_findings(report)
    sel = FindingSelector(args.rule, args.file, args.resource, args.line)
    matches = select_findings(findings, sel)
    print(f"Trivy {(report.get('Trivy') or {}).get('Version', '?')} · 스캔 시각 {report.get('CreatedAt', '?')} · FAIL finding {len(findings)}건, 조건({sel.describe()}) 일치 {len(matches)}건")
    for f in findings:
        mark = "→" if f in matches else " "
        print(f" {mark} {f.rule_id:14s} {f.severity:8s} {f.filename}:{f.start_line:<4d} {f.resource:45s} {f.title[:60]}")
    if len(matches) > 1:
        print("여러 개가 일치한다. review 에서는 --resource / --line 으로 하나를 지정해야 한다.")
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    from .review.flow import ReviewOptions, run_review
    s = _settings(args)
    opt = ReviewOptions(tf_dir=args.tf_dir, trivy_json=args.trivy_json, candidate=args.candidate, scenario=args.scenario,
                        rule=args.rule, filename=args.file, resource=args.resource, line=args.line, candidate_note=args.candidate_note or "",
                        verification=args.verification, baseline_plan=args.baseline_plan, candidate_plan=args.candidate_plan,
                        intent=args.intent, out_dir=args.out, mock_dir=args.mock_dir)
    res = run_review(s, opt)
    print(res.console())
    return 0 if res.state.value in ("REVIEW_REQUIRED",) else 1


def cmd_metrics(args: argparse.Namespace) -> int:
    from .metrics import collect, load_labels, render_table
    s = _settings(args)
    rows = collect([s.path(d) for d in (args.dirs or ["data/reviews"])])
    labels = load_labels(str(s.path(args.labels))) if args.labels else None
    table = render_table(rows, title=args.title, labels=labels)
    print(table)
    if args.out:
        from pathlib import Path as _P
        _P(args.out).write_text(table, encoding="utf-8")
        print(f"→ {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="iacpatch", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo-root", dest="repo_root", help="저장소 루트 (기본: 현재 위치에서 탐색)")
    common = argparse.ArgumentParser(add_help=False)
    for k in ("terraform_bin", "trivy_bin", "aws_bin", "aws_profile", "aws_region", "llm_provider", "llm_model", "llm_base_url",
              "llm_mock_fixture", "prompt_version", "data_dir", "tf_var_file"):
        common.add_argument("--" + k.replace("_", "-"), dest=k)
    common.add_argument("--offline", dest="offline", action="store_true", default=None, help="자격증명 없이 plan (provider override)")
    common.add_argument("--online", dest="offline", action="store_false", help="실제 AWS 상태 기준 plan (프로필 필요)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("selfcheck", parents=[common]); sp.set_defaults(fn=cmd_selfcheck)

    sp = sub.add_parser("scan", parents=[common]); sp.add_argument("target_dir"); sp.add_argument("--output"); sp.set_defaults(fn=cmd_scan)

    sp = sub.add_parser("predeploy", parents=[common])
    sp.add_argument("--target-dir", required=True, help="예: infrastructure/sg-baseline")
    sp.add_argument("--intent", required=True, help="예: policy/intent/sg-baseline.json")
    sp.add_argument("--scenario", required=True, help="시나리오 ID (기록용)")
    sp.add_argument("--generator", choices=["llm", "rule_based"], default="llm")
    sp.add_argument("--resource", help="대상 리소스 주소 (같은 룰이 여러 개일 때)")
    sp.add_argument("--max-attempts", dest="max_attempts", type=int)
    sp.add_argument("--workspace", help="작업 디렉터리 (기본: 임시)")
    sp.add_argument("--keep-workspace", action="store_true")
    sp.set_defaults(fn=cmd_predeploy)

    sp = sub.add_parser("oracle", parents=[common])
    sp.add_argument("--plan", required=True); sp.add_argument("--intent", required=True); sp.add_argument("--src-dir")
    sp.add_argument("--prefix-lists", help="외부 prefix list 전개 JSON {pl-id: [cidr]}"); sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_oracle)

    sp = sub.add_parser("pr", parents=[common])
    sp.add_argument("--run", required=True); sp.add_argument("--base", default="main"); sp.add_argument("--remote", default="origin")
    sp.add_argument("--draft", action="store_true"); sp.add_argument("--execute", action="store_true", help="실제 브랜치 push + PR 생성 (GITHUB_TOKEN 필요)")
    sp.set_defaults(fn=cmd_pr)

    sp = sub.add_parser("postdeploy", parents=[common])
    sp.add_argument("--intent", required=True); sp.add_argument("--sg-ids", nargs="*", default=[], help="대상 SG ID (없으면 --tf-dir 의 state/output 에서)")
    sp.add_argument("--tf-dir", help="apply 된 Terraform 디렉터리 (terraform show -json 으로 주소↔ID 매핑)")
    sp.add_argument("--v8-checks", help="V8 체크 정의 JSON"); sp.add_argument("--run", help="연결할 run id")
    sp.add_argument("--execute", action="store_true", help="실제 AWS 조회/통신 시도 실행")
    sp.set_defaults(fn=cmd_postdeploy)

    sp = sub.add_parser("findings", parents=[common], help="Trivy JSON 의 finding 목록")
    sp.add_argument("--trivy-json", required=True); sp.add_argument("--rule"); sp.add_argument("--file"); sp.add_argument("--resource"); sp.add_argument("--line", type=int)
    sp.set_defaults(fn=cmd_findings)

    sp = sub.add_parser("review", parents=[common], help="B·C 로컬 검토 흐름 (도구/API 없이)")
    sp.add_argument("--tf-dir", required=True, help="원본 Terraform 디렉터리 (예: infrastructure/sg-baseline)")
    sp.add_argument("--trivy-json", required=True, help="A 의 Trivy JSON (예: infrastructure/sg-baseline/baseline-scan.json)")
    sp.add_argument("--candidate", required=True, help="mock:<fixture> | manual:<path(.json|.tf|dir)> | rule_based (intent 필요)")
    sp.add_argument("--scenario", required=True)
    sp.add_argument("--rule", default="AVD-AWS-0107"); sp.add_argument("--file"); sp.add_argument("--resource"); sp.add_argument("--line", type=int)
    sp.add_argument("--candidate-note", dest="candidate_note", help="후보 출처 설명 (예: '팀원 B 가 수동 작성', '개발 중 작성한 예제')")
    sp.add_argument("--verification", help="A 의 검증 결과 JSON (verification-v1). 없으면 NOT_RUN")
    sp.add_argument("--baseline-plan", dest="baseline_plan", help="원본 plan JSON (있으면 V5 로컬 계산)")
    sp.add_argument("--candidate-plan", dest="candidate_plan", help="후보 plan JSON (있으면 V5/V6 로컬 계산)")
    sp.add_argument("--intent", help="intent JSON (후보 plan 과 함께 주면 V6 로컬 계산)")
    sp.add_argument("--out", help="기록 루트 (기본 data/reviews)"); sp.add_argument("--mock-dir", dest="mock_dir")
    sp.set_defaults(fn=cmd_review)

    sp = sub.add_parser("metrics", parents=[common], help="기록 집계")
    sp.add_argument("--dirs", nargs="*", help="집계할 기록 루트 (기본 data/reviews)"); sp.add_argument("--out"); sp.add_argument("--title", default="집계")
    sp.add_argument("--labels", help="라벨 JSON {scenario: {expected, source}} — 있을 때만 기대 대비 일치율을 계산")
    sp.set_defaults(fn=cmd_metrics)

    sp = sub.add_parser("recover", parents=[common])
    sp.add_argument("--run", required=True); sp.add_argument("--tf-dir", required=True); sp.add_argument("--execute", action="store_true")
    sp.set_defaults(fn=cmd_recover)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
