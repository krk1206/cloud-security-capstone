"""Terraform CLI 어댑터 (fmt / validate / plan / show -json).

- 바이너리는 환경변수 TERRAFORM_BIN 으로 바꿀 수 있다 (기본 "terraform"; OpenTofu 면 "tofu").
  ※ 이 저장소의 샌드박스 테스트는 hashicorp 릴리스 서버가 차단돼 OpenTofu 1.10.6 으로 수행했다.
    plan JSON 포맷(format_version 1.2)은 동일하지만, 팀 환경(Terraform 1.16.1)에서 재실행해 확인해야 한다.
- 작업은 항상 **복사본 디렉터리**에서 한다. 원본 Terraform 디렉터리에 .terraform/, plan 파일을 남기지 않는다.
- offline 모드: AWS 자격증명이 없는 환경(CI, 샌드박스)에서 plan 을 만들기 위해 provider override 파일을
  복사본에만 추가한다 (skip_credentials_validation 등). 이 plan 은 "상태 없음 → 전부 create" 이므로
  V5 는 planned_values 구조 비교로 동작하고, 실제 배포 경로에서는 상태가 있는 plan 을 써야 한다.
"""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .runner import CmdResult, ToolNotFound, run, which

OFFLINE_OVERRIDE_FILENAME = "zz_iacpatch_offline_override.tf"
OFFLINE_OVERRIDE = """# iacpatch: offline plan override (auto-generated in the working copy only; never committed)
provider "aws" {
  region                      = "%(region)s"
  profile                     = null
  access_key                  = "offline-plan-fake"
  secret_key                  = "offline-plan-fake"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}
"""

COPY_IGNORE = shutil.ignore_patterns(".terraform", "*.tfstate", "*.tfstate.*", "*.tfplan", "plan.bin", "plan.json", ".git")


@dataclass
class TerraformInfo:
    binary: str
    available: bool
    version: str = ""
    kind: str = ""          # "terraform" | "opentofu" | ""


@dataclass
class StepOutput:
    ok: bool
    result: Optional[CmdResult]
    error: str = ""
    data: Dict[str, Any] = field(default_factory=dict)


class TerraformAdapter:
    def __init__(self, binary: Optional[str] = None, region: str = "ap-northeast-2"):
        self.binary = binary or os.environ.get("TERRAFORM_BIN") or "terraform"
        self.region = region

    # -- 환경 ------------------------------------------------------------
    def info(self) -> TerraformInfo:
        path = which(self.binary) or (self.binary if os.path.exists(self.binary) else None)
        if not path:
            return TerraformInfo(self.binary, False)
        r = run([path, "version", "-json"], timeout=60)
        version, kind = "", ""
        if r.ok:
            try:
                d = json.loads(r.stdout)
                version = str(d.get("terraform_version", ""))
                kind = "opentofu" if "tofu" in os.path.basename(path).lower() else "terraform"
            except json.JSONDecodeError:
                pass
        if not version:
            r2 = run([path, "version"], timeout=60)
            version = (r2.stdout.splitlines() or [""])[0].strip()
            kind = "opentofu" if "OpenTofu" in version else "terraform"
        return TerraformInfo(path, True, version, kind)

    # -- 작업 복사본 --------------------------------------------------------
    @staticmethod
    def make_workdir(src_dir: str | Path, dst_dir: str | Path, file_overrides: Optional[Dict[str, str]] = None) -> Path:
        """원본을 복사하고 file_overrides(파일명→내용)를 덮어쓴 작업 디렉터리를 만든다. 원본은 건드리지 않는다."""
        src, dst = Path(src_dir), Path(dst_dir)
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, ignore=COPY_IGNORE)
        for rel, content in (file_overrides or {}).items():
            target = dst / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return dst

    def add_offline_override(self, workdir: str | Path) -> Path:
        p = Path(workdir) / OFFLINE_OVERRIDE_FILENAME
        p.write_text(OFFLINE_OVERRIDE % {"region": self.region}, encoding="utf-8")
        return p

    # -- 명령 --------------------------------------------------------------
    def _run(self, args: List[str], cwd: str | Path, timeout: int = 600) -> StepOutput:
        try:
            r = run([self.binary] + args, cwd=str(cwd), timeout=timeout)
        except ToolNotFound as e:
            return StepOutput(False, None, str(e))
        if r.timed_out:
            return StepOutput(False, r, f"timeout after {timeout}s: {' '.join(args)}")
        return StepOutput(r.ok, r, "" if r.ok else (r.stderr.strip() or r.stdout.strip())[:4000])

    def init(self, workdir: str | Path, timeout: int = 900) -> StepOutput:
        return self._run(["init", "-backend=false", "-input=false", "-no-color"], workdir, timeout)

    def fmt_check(self, workdir: str | Path) -> StepOutput:
        out = self._run(["fmt", "-check", "-diff", "-no-color"], workdir, 120)
        # fmt -check: exit 3 = 포맷 차이 있음 (오류 아님). 실패로 취급하지 않되 diff 를 남긴다.
        if out.result is not None and out.result.returncode == 3:
            out.ok = True
            out.error = ""
            out.data["needs_format"] = True
            out.data["diff"] = out.result.stdout[:4000]
        return out

    def validate(self, workdir: str | Path) -> StepOutput:
        out = self._run(["validate", "-json", "-no-color"], workdir, 300)
        if out.result is not None:
            try:
                out.data = json.loads(out.result.stdout or "{}")
                out.ok = bool(out.data.get("valid")) and out.result.returncode == 0
                if not out.ok:
                    diags = out.data.get("diagnostics") or []
                    out.error = "; ".join(f"{d.get('severity')}: {d.get('summary')} {(d.get('detail') or '')[:200]}" for d in diags) or out.error or "validate failed"
            except json.JSONDecodeError:
                out.ok = False
                out.error = (out.result.stderr or out.result.stdout)[:2000]
        return out

    def plan(self, workdir: str | Path, plan_file: str = "plan.bin", var_file: Optional[str] = None,
             timeout: int = 900) -> StepOutput:
        args = ["plan", "-input=false", "-no-color", "-lock=false", f"-out={plan_file}"]
        if var_file:
            args.append(f"-var-file={var_file}")
        return self._run(args, workdir, timeout)

    def show_json(self, workdir: str | Path, plan_file: str = "plan.bin") -> StepOutput:
        out = self._run(["show", "-json", plan_file], workdir, 300)
        if out.ok and out.result is not None:
            try:
                out.data = json.loads(out.result.stdout)
            except json.JSONDecodeError as e:
                out.ok = False
                out.error = f"plan json parse error: {e}"
        return out

    def apply(self, workdir: str | Path, plan_file: str = "plan.bin", timeout: int = 1800) -> StepOutput:
        """실제 반영. 파이프라인 코드가 이 함수를 자동으로 부르는 경로는 없다 (사람 승인 후 CLI 로만 호출)."""
        return self._run(["apply", "-input=false", "-no-color", "-auto-approve", plan_file], workdir, timeout)

    def output_json(self, workdir: str | Path) -> StepOutput:
        out = self._run(["output", "-json", "-no-color"], workdir, 120)
        if out.ok and out.result is not None:
            try:
                out.data = json.loads(out.result.stdout or "{}")
            except json.JSONDecodeError as e:
                out.ok = False
                out.error = f"output json parse error: {e}"
        return out

    def state_show_json(self, workdir: str | Path) -> StepOutput:
        out = self._run(["show", "-json"], workdir, 300)
        if out.ok and out.result is not None:
            try:
                out.data = json.loads(out.result.stdout or "{}")
            except json.JSONDecodeError as e:
                out.ok = False
                out.error = f"state json parse error: {e}"
        return out

    # -- 한 번에: init → validate → plan → show ------------------------------
    def plan_pipeline(self, workdir: str | Path, offline: bool, var_file: Optional[str] = None,
                      write_plan_json_to: Optional[str | Path] = None) -> Dict[str, StepOutput]:
        steps: Dict[str, StepOutput] = {}
        if offline:
            self.add_offline_override(workdir)
        steps["init"] = self.init(workdir)
        if not steps["init"].ok:
            return steps
        steps["fmt"] = self.fmt_check(workdir)
        steps["validate"] = self.validate(workdir)
        if not steps["validate"].ok:
            return steps
        steps["plan"] = self.plan(workdir, var_file=var_file)
        if not steps["plan"].ok:
            return steps
        steps["show"] = self.show_json(workdir)
        if steps["show"].ok and write_plan_json_to:
            Path(write_plan_json_to).write_text(json.dumps(steps["show"].data, ensure_ascii=False), encoding="utf-8")
        return steps
