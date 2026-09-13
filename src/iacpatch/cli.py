"""CLI.  `python -m iacpatch <command> ...`

  predeploy   스캔 → 패치 후보 → V1~V6 → 위험도 → 게이트 → PR 본문 (apply/push/PR 생성은 하지 않음)
  oracle      plan JSON + intent 로 V6 만 실행 (디버깅/실험용)
  scan        Trivy 스캔만
  pr          run record 로부터 브랜치/커밋/PR 준비. --execute 없으면 명령만 출력
  postdeploy  V7(AWS 실측) + V8(통신 확인). --execute 없으면 실행할 명령만 출력
  recover     배포 후 실패 복구 절차 (revert → plan → apply(승인) → V7 재확인)
  selfcheck   도구 존재/버전 확인
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

    sp = sub.add_parser("recover", parents=[common])
    sp.add_argument("--run", required=True); sp.add_argument("--tf-dir", required=True); sp.add_argument("--execute", action="store_true")
    sp.set_defaults(fn=cmd_recover)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
