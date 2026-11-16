#!/usr/bin/env python3
"""워크플로 ① — LLM(Claude Code 구독) 생성기 경로.

B 의 src/iacpatch/llmfix.py 는 '후보 세트(--set)' 단위로만 돌고, 세트는 웹 사례(web/cases.py) 또는
연결한 프로젝트(data/projects/<id>/)에 묶여 있다. CI 에서 임의의 Terraform 폴더(infrastructure/sg-baseline)에
AI 수정을 돌리려면 그 폴더를 '연결한 프로젝트' 모양으로 임시로 꾸미면 된다 — 화면 코드를 고치지 않고,
B 의 run_fix 를 그대로 호출한다 (D-32 의 프로젝트 연결 규칙과 같은 파일 배치).

입력: --target-dir <폴더> --intent <intent.json> --trivy <① 이 만든 trivy JSON> [--max-attempts N] [--timeout 초]
출력(표준 출력 마지막 줄들): review_id=<data/reviews 기록 id> status=<PASSED|GAVE_UP|…> exit=<코드>
 - review_id 는 `python -m iacpatch pr --review <id> --execute --base <브랜치>` 에 그대로 넣는다 (규칙 기반 경로의 --run 과 같은 자리).
 - 기록 폴더: data/llm_runs/<run_id>/ (프롬프트·응답·시도별 후보) + data/reviews/<review_id>/ (8개 관문 검사 기록)
안전: AI 는 파일 내용만 돌려준다. 자식 프로세스에서 API 키·AWS 자격증명이 제거되고(llmfix.UNSET_ENV) 도구가 전부 꺼진다(--tools "").
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-dir", required=True, help="저장소 기준 Terraform 폴더 (예: infrastructure/sg-baseline)")
    ap.add_argument("--intent", required=True, help="policy/intent/<이름>.json")
    ap.add_argument("--trivy", required=True, help="① 이 만든 Trivy JSON (scan-results/<이름>.json)")
    ap.add_argument("--rule", default=None, help="대상 룰 (없으면 FAIL finding 중 보안 그룹 첫 항목)")
    ap.add_argument("--resource", default=None)
    ap.add_argument("--max-attempts", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--root", default=".")
    a = ap.parse_args()

    root = Path(a.root).resolve()
    sys.path.insert(0, str(root / "src"))
    from iacpatch import llmfix  # noqa: E402
    from iacpatch.review.inputs import list_findings, load_trivy_report  # noqa: E402

    tf_dir = str(a.target_dir).strip("/")
    tf_abs = root / tf_dir
    if not tf_abs.is_dir():
        print(f"::error::폴더 없음: {tf_dir}"); return 3
    intent_abs = (root / a.intent).resolve()
    if not intent_abs.exists():
        print(f"::error::intent 없음: {a.intent}"); return 3
    trivy_abs = (root / a.trivy).resolve()
    if not trivy_abs.exists():
        print(f"::error::Trivy JSON 없음: {a.trivy}"); return 3

    # 대상 finding: 규칙 기반 경로(predeploy)와 같은 룰 — settings.target_rule (기본 AVD-AWS-0107, 환경변수 IACPATCH_TARGET_RULE).
    # 그 룰의 FAIL 이 없으면 종료 (predeploy 의 NO_FINDING 과 같은 뜻). --rule/--resource 로 바꿀 수 있다.
    from iacpatch.config import load_settings  # noqa: E402
    rule = a.rule or load_settings(str(root)).target_rule
    fails = [f for f in list_findings(load_trivy_report(trivy_abs)) if f.status == "FAIL" and f.rule_id == rule]
    if a.resource:
        fails = [f for f in fails if f.resource == a.resource]
    if not fails:
        print(f"::warning::Trivy 결과에 {rule} FAIL finding 없음 — LLM 패치 생략"); return 3
    fails.sort(key=lambda f: (f.filename, f.start_line))
    f = fails[0]
    if "/" in str(f.filename).replace("\\", "/").strip("/"):
        print(f"::error::하위 폴더(모듈) 파일은 지원 범위 밖: {f.filename}"); return 4

    # 임시 '연결한 프로젝트' — web/cases.user_projects() 가 읽는 파일 배치 그대로 (project.json + sets/<pid>.<이름>/manifest.json)
    pid = "ci-" + hashlib.sha256(tf_dir.encode()).hexdigest()[:8]
    projects_dir = Path(tempfile.mkdtemp(prefix="iacpatch-ci-projects-"))
    os.environ["IACPATCH_PROJECTS_DIR"] = str(projects_dir)
    d = projects_dir / pid
    (d / "scan").mkdir(parents=True)
    shutil.copy2(trivy_abs, d / "scan" / "trivy.json")
    (d / "project.json").write_text(json.dumps({
        "id": pid, "name": f"CI {tf_dir}", "path": str(tf_abs), "folder": tf_abs.name, "kind": "user",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "summary": f"워크플로 ① LLM 경로 — {tf_dir}"}, ensure_ascii=False, indent=2), encoding="utf-8")
    set_id = f"{pid}.t{hashlib.sha256(f'{f.rule_id}|{f.resource}'.encode()).hexdigest()[:8]}"
    sd = d / "sets" / set_id
    sd.mkdir(parents=True)
    (sd / "manifest.json").write_text(json.dumps({
        "set_id": set_id, "project": pid, "tf_dir": tf_dir, "trivy_json": str(d / "scan" / "trivy.json"),
        "rule": f.rule_id, "resource": f.resource, "file": Path(f.filename).name, "line": int(f.start_line),
        "intent": str(intent_abs), "label": f"{f.rule_id} — {f.resource}", "candidates": []}, ensure_ascii=False, indent=2), encoding="utf-8")

    # 설계도 확정 기록 (D-38): 앱에서는 담당자가 화면에서 설계도를 '확정' 해야 검사 통과를 '고객 요구 충족' 으로 본다.
    # CI 가 쓰는 policy/intent/<이름>.json 은 저장소에 PR 검토를 거쳐 들어간 팀 결정값이므로, 그 파일을 임시 프로젝트의
    # 설계도 v1 로 등록하고 확정 기록을 남긴다. 기록이 없으면 8개 관문을 다 통과해도 '초안' 으로 UNDECIDABLE 이 된다.
    designs_dir = Path(tempfile.mkdtemp(prefix="iacpatch-ci-designs-"))
    os.environ["IACPATCH_DESIGNS_DIR"] = str(designs_dir)
    (designs_dir / pid).mkdir(parents=True)
    shutil.copy2(intent_abs, designs_dir / pid / "v1.json")
    from iacpatch.web import designs  # noqa: E402
    conf = designs.confirm(set_id, 1, by="workflow ① (저장소 policy/intent — PR 검토를 거친 팀 결정값)",
                           note=f"CI 기준 설계도 = {a.intent}")
    if not conf.get("ok"):
        print(f"::error::설계도 확정 기록 실패: {conf.get('errors')}"); return 3
    print(f"설계도 확정 기록: {a.intent} (basis={conf.get('confirmation', {}).get('basis')})")
 
    st = llmfix.claude_status(refresh=True)
    print(f"claude: found={st.get('found')} version={st.get('version')} logged_in={st.get('logged_in')} auth={st.get('auth_method')} {st.get('note') or ''}")
    if not st.get("found"):
        print("::error::Claude Code 없음"); return 2

    rec = llmfix.run_fix(root, set_id, context="trivy", max_attempts=a.max_attempts, timeout=a.timeout, intent_path=str(intent_abs))
    print(llmfix.summary_markdown(rec))
    print(f"run_id={rec.get('run_id')}")
    print(f"review_id={rec.get('final_record_id') or ''}")
    print(f"status={rec.get('status')}")
    print(f"exit={rec.get('exit_code')}")
    for n, att in enumerate(rec.get("attempts") or [], 1):
        print(f"attempt{n}: status={att.get('status')} seconds={att.get('seconds')} model={att.get('model')} cost_usd={att.get('cost_usd')}")
    return int(rec.get("exit_code") or 0)


if __name__ == "__main__":
    raise SystemExit(main())
