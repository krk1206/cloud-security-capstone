"""Terraform CLI 어댑터 (fmt / validate / plan / show -json).

- 바이너리는 환경변수 TERRAFORM_BIN 으로 바꿀 수 있다 (기본 "terraform"; OpenTofu 면 "tofu").
  ※ 이 저장소의 샌드박스 테스트는 hashicorp 릴리스 서버가 차단돼 OpenTofu 1.10.6 으로 수행했다.
    plan JSON 포맷(format_version 1.2)은 동일하지만, 팀 환경(Terraform 1.16.1)에서 재실행해 확인해야 한다.
- 작업은 항상 **복사본 디렉터리**에서 한다. 원본 Terraform 디렉터리에 .terraform/, plan 파일을 남기지 않는다.
- offline 모드: AWS 자격증명이 없는 환경(CI, 샌드박스)에서 plan 을 만들기 위해 provider override 파일을
  복사본에만 추가한다 (skip_credentials_validation 등). 이 plan 은 "상태 없음 → 전부 create" 이므로
  V5 는 planned_values 구조 비교로 동작하고, 실제 배포 경로에서는 상태가 있는 plan 을 써야 한다.
- provider 템플릿(template_dir): `terraform init` 은 작업 복사본마다 provider 바이너리(AWS 는 수백 MB)를 `.terraform/providers/`
  에 설치한다. 리눅스는 플러그인 캐시로 심볼릭 링크를 걸어 빠르지만 Windows 는 **복사**라 후보마다 수 분이 걸렸다(팀 PC 실측:
  후보당 3~4분). 그래서 처음 성공한 init 의 `.terraform/providers/` + lock 파일을 템플릿으로 남기고, 다음 작업 복사본에는
  init 전에 하드링크(같은 볼륨, 권한 불필요)로 되살린다. init 은 "이미 설치됨" 을 확인만 하므로 복사가 없다.
  판정 논리와는 무관하다 (같은 바이너리, 같은 plan).
"""
from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .runner import CmdResult, ToolNotFound, run, which

OFFLINE_OVERRIDE_FILENAME = "zz_iacpatch_offline_override.tf"
# AWS provider 버전 고정. 이유(팀 PC 실측 2026-09-29): 시나리오 .tf 에 버전 제약이 없으면 terraform init 이 '그때의 최신'(6.66.0)을 받는다.
# 같은 PC 에서 아침 실험은 5.100.0(infrastructure/ 의 lock 이 템플릿을 만듦), 저녁 화면 실행은 6.66.0 이 되어 원본 plan 과 후보 plan 의
# provider 가 달라졌고, 6.x 가 리소스마다 넣는 `region` 속성을 V5 가 "허용 목록 밖 변경" 으로 잡았다 (V5 FAIL — 패치와 무관한 오탐).
# 검증 결과가 실행 시각·순서에 따라 달라지면 안 되므로 offline plan 의 override 파일에 버전을 못 박는다 (D-13).
# 5.100.0 = 샌드박스 fixture(tests/fixtures/plans)·팀 PC lock·9/22 실측이 전부 쓴 버전. 바꾸려면 Settings.aws_provider_version.
DEFAULT_AWS_PROVIDER_VERSION = "5.100.0"
PROVIDER_PIN = """terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "%(version)s"
    }
  }
}

"""
OFFLINE_OVERRIDE = """# iacpatch: offline plan override (auto-generated in the working copy only; never committed)
%(provider_pin)sprovider "aws" {
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
LOCK_FILENAME = ".terraform.lock.hcl"
_LOCK_MISMATCH_HINTS = ("lock file", "Inconsistent dependency", "does not match configured version constraint", "locked provider")


def _link_or_copy(src: str, dst: str) -> None:
    """하드링크(즉시, 같은 볼륨) → 안 되면 복사. Windows 에서 심볼릭 링크는 권한이 필요하지만 하드링크는 아니다."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


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
    def __init__(self, binary: Optional[str] = None, region: str = "ap-northeast-2", template_dir: Optional[str | Path] = None,
                 provider_version: Optional[str] = DEFAULT_AWS_PROVIDER_VERSION):
        self.binary = binary or os.environ.get("TERRAFORM_BIN") or "terraform"
        self.region = region
        self.provider_version = provider_version   # None 이면 고정하지 않음 (config 의 제약/lock 대로)
        self.template_dir = Path(template_dir) if template_dir else None
        self.last_template_action = ""      # "restored" | "saved" | "" (기록용)

    # -- provider 템플릿 (init 의 provider 복사를 없앤다) ---------------------------
    def restore_provider_template(self, workdir: str | Path) -> bool:
        """템플릿의 .terraform/providers/ 와 lock 파일을 작업 복사본에 하드링크로 되살린다. 실패하면 False (init 이 평소대로 설치)."""
        if not self.template_dir:
            return False
        src = self.template_dir / ".terraform" / "providers"
        if not src.is_dir():
            return False
        try:
            wd = Path(workdir)
            dst = wd / ".terraform" / "providers"
            if dst.exists():
                shutil.rmtree(dst)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src, dst, symlinks=True, copy_function=_link_or_copy)
            tlock, wlock = self.template_dir / LOCK_FILENAME, wd / LOCK_FILENAME
            if tlock.exists() and not wlock.exists():
                shutil.copy2(tlock, wlock)
            self.last_template_action = "restored"
            return True
        except OSError:
            return False

    def save_provider_template(self, workdir: str | Path) -> bool:
        """init 성공 뒤 호출. 템플릿이 없거나 lock 파일이 달라졌으면(새 provider/버전) 이 복사본의 providers/ 를 템플릿으로 남긴다."""
        if not self.template_dir:
            return False
        wd = Path(workdir)
        wsrc, wlock = wd / ".terraform" / "providers", wd / LOCK_FILENAME
        if not wsrc.is_dir():
            return False
        tlock = self.template_dir / LOCK_FILENAME
        same_lock = tlock.exists() and wlock.exists() and tlock.read_bytes() == wlock.read_bytes()
        if (self.template_dir / ".terraform" / "providers").is_dir() and same_lock:
            return False
        try:
            tmp = self.template_dir.parent / (self.template_dir.name + ".tmp")
            if tmp.exists():
                shutil.rmtree(tmp)
            (tmp / ".terraform").mkdir(parents=True)
            shutil.copytree(wsrc, tmp / ".terraform" / "providers", symlinks=True, copy_function=_link_or_copy)
            if wlock.exists():
                shutil.copy2(wlock, tmp / LOCK_FILENAME)
            if self.template_dir.exists():
                shutil.rmtree(self.template_dir)
            os.replace(tmp, self.template_dir)
            self.last_template_action = "saved"
            return True
        except OSError:
            return False

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

    def offline_override_text(self) -> str:
        pin = PROVIDER_PIN % {"version": self.provider_version} if self.provider_version else ""
        return OFFLINE_OVERRIDE % {"region": self.region, "provider_pin": pin}

    def add_offline_override(self, workdir: str | Path) -> Path:
        """`*_override.tf` 는 Terraform 이 같은 이름의 블록을 덮어쓰는 파일이다: provider "aws" 의 자격증명 무시 설정과, required_providers 의 aws 버전 고정."""
        p = Path(workdir) / OFFLINE_OVERRIDE_FILENAME
        p.write_text(self.offline_override_text(), encoding="utf-8")
        return p

    @staticmethod
    def locked_provider_version(workdir: str | Path, provider: str = "hashicorp/aws") -> Optional[str]:
        """init 뒤 .terraform.lock.hcl 에 적힌 provider 버전 (실제로 plan 에 쓰인 버전의 증거). 없으면 None."""
        lock = Path(workdir) / LOCK_FILENAME
        if not lock.exists():
            return None
        # registry.terraform.io/… (Terraform) 과 registry.opentofu.org/… (OpenTofu) 둘 다
        m = re.search(r'provider\s+"[^"]*/' + re.escape(provider) + r'"\s*\{[^}]*?version\s*=\s*"([^"]+)"', lock.read_text(encoding="utf-8", errors="replace"), re.S)
        return m.group(1) if m else None

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
        """init. 템플릿이 있으면 provider 를 먼저 되살리고(복사 없음), 성공하면 템플릿을 갱신한다.
        되살린 lock 파일이 이 구성의 버전 제약과 안 맞으면 lock 파일을 지우고 한 번 더 init 한다."""
        restored = self.restore_provider_template(workdir)
        out = self._run(["init", "-backend=false", "-input=false", "-no-color"], workdir, timeout)
        if not out.ok and restored and any(h in (out.error or "") for h in _LOCK_MISMATCH_HINTS):
            try:
                (Path(workdir) / LOCK_FILENAME).unlink(missing_ok=True)
            except OSError:
                pass
            out = self._run(["init", "-backend=false", "-input=false", "-no-color"], workdir, timeout)
        if out.ok:
            self.save_provider_template(workdir)
        return out

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
