"""로컬 도구로 V1~V4 실행 (`iacpatch review --local-tools`).

A 가 따로 결과 파일을 만들지 않아도, 실행 환경에 trivy / terraform 이 있으면 지난 세션의 V1~V4 코드
(verify/layers.py, tools/trivy.py, tools/terraform.py — predeploy 경로와 같은 함수) 를 후보에 대해 돌리고
verification-v1 JSON 으로 남긴다. 도구가 없으면 그 계층은 NOT_RUN 이다 (PASS 로 채우지 않는다).

  V1/V2 : trivy 가 있으면 원본·후보를 **같은 환경에서** 다시 스캔해 비교한다. (--trivy-json 으로 받은 A 의 스캔은
          대상 선택에만 쓰고, V1/V2 의 before 로는 로컬 재스캔을 쓴다 — 체크 번들이 다를 수 있어서.)
          입력 스캔과 로컬 재스캔의 FAIL 키 집합이 다르면 notes 에 남긴다.
  V3/V4 : terraform(또는 OpenTofu) 이 있으면 오프라인 plan (provider override, AWS 접속 없음).
          init 이 provider 를 못 받으면 ERROR 로 기록된다 (실패를 숨기지 않음).
          성공하면 plan_baseline.json / plan_candidate.json 을 남겨 V5/V6 계산에 쓴다.

결과물 (run 폴더 안):
  local_verify/verification.json   verification-v1 (source="local tools: ...", candidate_sha256 포함)
  local_verify/trivy_before.json, trivy_after.json
  local_verify/plan_baseline.json, plan_candidate.json  (terraform 성공 시)
  local_verify/tools.json          도구 경로·버전

원본(baseline) 캐시: 같은 세트의 후보들은 원본(tf_dir)이 같으므로 원본 trivy 스캔과 원본 plan 은 한 번만 만들면 된다.
  키 = 원본 파일 내용 + var 파일 + 도구 버전 + 오프라인 override 텍스트. 캐시는 data/cache/baseline/<키>/ 에 두고,
  적중하면 run 폴더에 복사해 기록은 그대로 자기완결적으로 남긴다 (notes 에 '캐시 재사용' 표시). IACPATCH_NO_CACHE=1 로 끈다.
  후보 쪽(trivy_after, plan_candidate)은 캐시하지 않는다 — 후보마다 다르고, 그게 검증 대상이다.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import Settings
from ..fingerprint import tree_digest
from ..models import Finding, LayerResult, Verdict
from ..tools.terraform import OFFLINE_OVERRIDE, TerraformAdapter
from ..tools.trivy import TrivyAdapter, TrivyScan, parse_findings, scan_summary
from ..verify.layers import v1_target_finding, v2_finding_diff, v3_validate, v4_plan
from .verification_input import candidate_digest


@dataclass
class LocalVerifyResult:
    verification_path: Path
    baseline_plan: Optional[Path] = None
    candidate_plan: Optional[Path] = None
    notes: List[str] = field(default_factory=list)
    tools: Dict[str, Any] = field(default_factory=dict)


def _not_run(layer: str, name: str, why: str) -> LayerResult:
    return LayerResult(layer, name, Verdict.NOT_RUN, why, {}, False, "")


def _scan_from_report(report: Dict[str, Any]) -> TrivyScan:
    return TrivyScan(True, report, parse_findings(report), scan_summary(report), str((report.get("Trivy") or {}).get("Version") or ""))


def _baseline_key(tf_dir: Path, var_file: Optional[str], tools: Dict[str, Any], region: str) -> str:
    h = hashlib.sha256()
    h.update(tree_digest(tf_dir).encode())
    h.update(json.dumps({"var_file": var_file, "tools": tools, "region": region, "override": OFFLINE_OVERRIDE}, sort_keys=True).encode("utf-8"))
    return h.hexdigest()[:24]


def run_local_verification(settings: Settings, tf_dir: Path, candidate_files: Dict[str, str], target: Finding,
                           policy: Dict[str, Any], out_dir: Path, input_report: Optional[Dict[str, Any]] = None) -> LocalVerifyResult:
    out_dir.mkdir(parents=True, exist_ok=True)
    notes: List[str] = []
    layers: List[LayerResult] = []
    tools: Dict[str, Any] = {}

    # 작업 복사본 (원본은 건드리지 않는다). make_workdir 는 terraform 없이도 동작한다
    ws = out_dir / "work"
    base_wd = TerraformAdapter.make_workdir(tf_dir, ws / "baseline")
    cand_wd = TerraformAdapter.make_workdir(tf_dir, ws / "candidate", file_overrides=candidate_files)
    var_file = None
    if (tf_dir / "terraform.tfvars").exists():
        var_file = "terraform.tfvars"

    # ---------------------------------------------------------------- 원본(baseline) 캐시 준비
    trivy = TrivyAdapter(settings.trivy_bin)
    tf = TerraformAdapter(settings.terraform_bin, settings.aws_region, template_dir=settings.tf_template_dir())
    info = tf.info()
    cache_root = settings.baseline_cache_dir()
    cache: Optional[Path] = None
    if cache_root is not None:
        key_tools = {"trivy": trivy.version() if trivy.available() else None, "trivy_skip_check_update": bool(trivy.skip_check_update),
                     "terraform": (info.kind, info.version) if info.available else None}
        cache = cache_root / _baseline_key(Path(tf_dir), var_file, key_tools, settings.aws_region)
        cache.mkdir(parents=True, exist_ok=True)

    def _cache_hit(name: str) -> Optional[Path]:
        if cache is not None and (cache / name).exists():
            return cache / name
        return None

    def _cache_put(name: str, src: Path) -> None:
        if cache is not None and src.exists():
            try:
                shutil.copy2(src, cache / name)
                (cache / "meta.json").write_text(json.dumps({"tf_dir": str(tf_dir), "created_at": _dt.datetime.now().isoformat(timespec="seconds"),
                                                              "tools": tools}, ensure_ascii=False, indent=2), encoding="utf-8")
            except OSError:
                pass

    def _cache_note(name: str) -> str:
        meta = {}
        try:
            meta = json.loads((cache / "meta.json").read_text(encoding="utf-8")) if cache is not None else {}
        except (OSError, ValueError):
            pass
        return f"원본(baseline) {name}: 캐시 재사용 ({cache.name if cache else ''}, 최초 생성 {meta.get('created_at', '?')}) — 원본·도구가 같을 때만 적중"

    # ---------------------------------------------------------------- V1 / V2 (trivy)
    if trivy.available():
        tools["trivy"] = {"binary": trivy.binary, "version": trivy.version(), "skip_check_update": trivy.skip_check_update}
        hit = _cache_hit("trivy_before.json") if trivy.skip_check_update else None    # 체크 번들을 갱신하는 설정이면 캐시 안 씀
        if hit is not None:
            shutil.copy2(hit, out_dir / "trivy_before.json")
            before = _scan_from_report(json.loads(hit.read_text(encoding="utf-8")))
            notes.append(_cache_note("trivy 스캔"))
        else:
            before = trivy.scan_dir(base_wd, out_dir / "trivy_before.json", tf_vars=(str(base_wd / var_file) if var_file else None))
            if before.ok and trivy.skip_check_update:
                _cache_put("trivy_before.json", out_dir / "trivy_before.json")
        after = trivy.scan_dir(cand_wd, out_dir / "trivy_after.json", tf_vars=(str(cand_wd / var_file) if var_file else None))
        layers.append(v1_target_finding(target, before, after))
        layers.append(v2_finding_diff(before, after, policy.get("v2_block_severities", ["CRITICAL", "HIGH"]), policy.get("v2_ignore_rules", [])))
        if input_report is not None and before.ok:
            given = _scan_from_report(input_report)
            gk = {f.key for f in given.findings}
            lk = {f.key for f in before.findings}
            if gk != lk:
                notes.append(f"입력 스캔(--trivy-json, trivy {given.version or '?'})과 로컬 재스캔(trivy {before.version}) 의 FAIL 키 집합이 다르다: "
                             f"입력에만 {sorted(gk - lk)} / 로컬에만 {sorted(lk - gk)}")
            else:
                notes.append(f"입력 스캔과 로컬 재스캔의 FAIL 키 집합 동일 ({len(lk)}건, trivy {before.version})")
    else:
        tools["trivy"] = {"binary": trivy.binary, "available": False}
        why = f"trivy 없음 ({trivy.binary}) — 로컬 재스캔 불가"
        layers.append(_not_run("V1", "대상 finding 제거 (Trivy 재스캔)", why))
        layers.append(_not_run("V2", "새 finding 발생 여부 (Trivy 전후 비교)", why))

    # ---------------------------------------------------------------- V3 / V4 (terraform, offline plan)
    baseline_plan: Optional[Path] = None
    candidate_plan: Optional[Path] = None
    if info.available:
        label = f"{info.kind or 'terraform'} {info.version}".strip()
        tools["terraform"] = {"binary": info.binary, "version": info.version, "kind": info.kind, "offline_plan": True}
        hit = _cache_hit("plan_baseline.json")
        if hit is not None:
            shutil.copy2(hit, out_dir / "plan_baseline.json")
            baseline_plan = out_dir / "plan_baseline.json"
            notes.append(_cache_note("plan"))
        else:
            base_steps = tf.plan_pipeline(base_wd, True, var_file=var_file, write_plan_json_to=out_dir / "plan_baseline.json")
            if (out_dir / "plan_baseline.json").exists() and base_steps.get("show") and base_steps["show"].ok:
                baseline_plan = out_dir / "plan_baseline.json"
                _cache_put("plan_baseline.json", baseline_plan)
            else:
                notes.append("원본 plan 생성 실패: " + _first_error(base_steps))
        cand_steps = tf.plan_pipeline(cand_wd, True, var_file=var_file, write_plan_json_to=out_dir / "plan_candidate.json")
        if tf.last_template_action:
            tools["terraform"]["provider_template"] = tf.last_template_action
        layers.append(v3_validate(cand_steps, label))
        layers.append(v4_plan(cand_steps, label, True))
        if (out_dir / "plan_candidate.json").exists() and cand_steps.get("show") and cand_steps["show"].ok:
            candidate_plan = out_dir / "plan_candidate.json"
        if info.kind == "opentofu":
            notes.append("V3/V4 는 OpenTofu 로 실행했다 (팀 환경 Terraform 1.16.1 과 다름). plan JSON 구조는 같다")
        # provider 바이너리(수백 MB)가 작업 복사본마다 남지 않게 정리한다. plan JSON·결과는 이미 out_dir 에 있다
        for wd in (base_wd, cand_wd):
            shutil.rmtree(wd / ".terraform", ignore_errors=True)
            for junk in ("plan.bin", "terraform.tfstate"):
                (wd / junk).unlink(missing_ok=True)
    else:
        tools["terraform"] = {"binary": tf.binary, "available": False}
        why = f"terraform 없음 ({tf.binary}) — validate/plan 불가"
        layers.append(_not_run("V3", "terraform validate", why))
        layers.append(_not_run("V4", "terraform plan", why))

    src = "local tools (iacpatch review --local-tools): " + ", ".join(
        f"{v.get('kind') or k} {v.get('version')}" if v.get("version") else f"{k} 없음" for k, v in tools.items())
    doc = {"schema": "iacpatch-verification-v1", "source": src, "candidate_sha256": candidate_digest(candidate_files),
           "tools": tools, "notes": notes, "layers": [l.to_dict() for l in layers]}
    vpath = out_dir / "verification.json"
    vpath.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "tools.json").write_text(json.dumps(tools, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return LocalVerifyResult(vpath, baseline_plan, candidate_plan, notes, tools)


def _first_error(steps: Dict[str, Any]) -> str:
    for name in ("init", "validate", "plan", "show"):
        s = steps.get(name)
        if s is not None and not s.ok:
            return f"{name}: {(s.error or '')[:300]}"
    return "알 수 없음"
