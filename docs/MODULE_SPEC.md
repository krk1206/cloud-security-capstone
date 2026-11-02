# 모듈별 입출력 명세

모든 구조체는 `src/iacpatch/models.py` 의 dataclass 이며 `to_dict()` 로 JSON 이 된다.

## tools/trivy.py

| 함수 | 입력 | 출력 |
|---|---|---|
| `TrivyAdapter.scan_dir(dir, output_json, tf_vars)` | Terraform 디렉터리 | `TrivyScan{ok, report(원문), findings[Finding], summary{successes,failures,checks_executed}, version, error}` |
| `parse_findings(report, include_pass)` | Trivy JSON | `[Finding{rule_id(AVD-AWS-xxxx), severity, resource, filename, start_line, end_line, title, message, resolution, status}]` |

`Finding.key = rule_id|filename|resource` (라인 제외) — V1/V2 비교 키.

## tools/terraform.py

| 함수 | 입력 | 출력 |
|---|---|---|
| `TerraformAdapter.make_workdir(src, dst, file_overrides)` | 원본 디렉터리, 덮어쓸 파일 dict | 복사본 경로 (원본 불변) |
| `plan_pipeline(workdir, offline, var_file, write_plan_json_to)` | 작업 디렉터리 | `{"init","fmt","validate","plan","show": StepOutput{ok, result, error, data}}` — `show.data` 가 plan JSON |
| `apply(workdir, plan_file)` | — | 파이프라인은 호출하지 않음 (recover --execute 에서만) |

오프라인 모드는 `zz_iacpatch_offline_override.tf` 를 복사본에만 추가한다. 환경변수 `TERRAFORM_BIN` 으로 `tofu` 사용 가능.

## intent.py

| 함수 | 입력 | 출력 |
|---|---|---|
| `load_intent(path)` / `parse_intent(dict)` | Intent JSON | `IntentSpec{intent_id, target_security_groups[], attachment_points[], guarded_services[GuardedService{service: ServiceSpec, approved: ApprovedSources}], required_access[RequiredAccess]}`. 문제 시 `IntentError` |
| `try_load_intent(path)` | — | `(spec, None)` 또는 `(None, 이유)` |

거부 조건: 플레이스홀더(`__FILL_ME__`, `<...>`, TODO, REPLACE), `status != active`, 승인 출처가 인터넷 전체, CIDR 형식 오류, 빈 대상/서비스.

## evidence.py

`build_bundle(scenario_id, target_dir, finding, all_findings, files, intent_raw, policy, cis_mapping, tool_versions)` → `EvidenceBundle{bundle_version, finding, related_findings, files{name:text}, editable_files, intent, constraints, cis_mapping, tool_versions, created_at}`.

## generator/

| 구성 | 입력 | 출력 |
|---|---|---|
| `LLMProvider.complete(system, user, max_tokens, temperature)` | 프롬프트 | `LLMResponse{text, model, provider, truncated, stop_reason, usage, error}` |
| `parse_llm_output(resp, editable_files)` | LLMResponse | `{status, files{path:content}, rationale, proposed_autonomy, assumptions}`; 실패 시 `GenerationError` (잘림·비JSON·스키마) |
| `LLMPatchGenerator.generate(bundle, feedback, attempt)` | Evidence Bundle | `PatchCandidate{candidate_id, origin(llm/mock), generator, status(PATCH/INSUFFICIENT_INFO/ABSTAIN/GENERATION_FAILED), files, rationale, proposed_autonomy, assumptions, error, prompt_version, prompt_sha256, model, attempt}` |
| `RuleBasedGenerator.generate(bundle)` | Evidence Bundle | `PatchCandidate{origin=rule_based, status PATCH/NOT_SUPPORTED/INSUFFICIENT_INFO}` |

LLM 응답 계약은 `generator/base.py` 상단과 `prompts/sg_v1.md` 에 있다. 제공자 선택: 환경변수 `LLM_PROVIDER` (mock/anthropic/openai/openai_compatible), `LLM_MODEL`, `LLM_BASE_URL`, 키는 `LLM_API_KEY`(또는 `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`).

## policy/validator.py

`validate_candidate(candidate, baseline_files, policy, target_dir)` → `PolicyResult{ok, violations[], checks[{check, ok, note}], policy_version}`. `checks` 에 `diff_stats{added_lines, removed_lines, files}` 포함 (Risk 입력).

## verify/

| 계층 | 함수 | 입력 | 출력 (`LayerResult{layer, name, verdict, summary, details, executed, tool}`) |
|---|---|---|---|
| V1 | `v1_target_finding(target, before, after, candidate_resource_present)` | Finding, TrivyScan×2 | PASS(제거) / FAIL(잔존) / ERROR(0 checks) |
| V2 | `v2_finding_diff(before, after, block_severities, ignore_rules)` | TrivyScan×2 | PASS / WARN(비차단 신규) / FAIL(신규 CRITICAL·HIGH); details.new/resolved/possibly_moved |
| V3 | `v3_validate(steps, tool)` | terraform steps | PASS / FAIL(diagnostics) / SKIPPED(도구 없음) |
| V4 | `v4_plan(steps, tool, offline)` | terraform steps | PASS / FAIL / ERROR / SKIPPED |
| V5 | `v5_plan_diff(baseline_plan, candidate_plan, policy)` | plan JSON×2 | PASS / WARN(변경 없음) / FAIL(삭제·교체·허용 밖 타입·속성·개수·provider) / SKIPPED; details.removed/added/changed/plan_actions_* |
| V6 | `v6_intent_oracle(candidate_plan, sources, intent, intent_error, external_prefix_lists)` | plan JSON, HCL, IntentSpec | PASS / FAIL / UNKNOWN / SKIPPED; details = `OracleReport.to_dict()` (targets→scopes→services{effective/approved/excess/unknown_reasons}, required) |
| 종합 | `combine(phase, layers)` | LayerResult[] | `ValidityReport{validity PASS/FAIL/INCOMPLETE, summary}` |

`verify/plan_model.build_world(plan, sources, external_prefix_lists)` → `SGWorld{security_groups{addr: SecurityGroupModel{rules[Rule{direction, protocol, from_port, to_port, sources[Source{kind,value,resolved_cidrs,note}], origin, unknown_fields}], inline_unknown, caveats}}, prefix_lists, attachments[AttachmentPoint{address, sg_refs, external_sg_ids, unknown}], notes}`.

`verify/sg_oracle.evaluate(world, intent, aliases)` → `OracleReport{verdict, targets[TargetEval{target, verdict, scopes[ScopeEval{scope_id, scope_kind, security_groups, services[ServiceEval], required[RequiredEval], caveats}], reason}], summary}`.

## policy/risk.py · policy/gate.py

`score_risk(rubric, v5_details, world, diff_stats, v6_details)` → `RiskDecision{risk_level, autonomy_cap, score, factors[{factor,value,points,note}], rubric_version}`.
`decide(validity, policy, risk, llm_proposed)` → `GateDecision{action, validity, policy_ok, risk_level, autonomy_cap, llm_proposed_autonomy, final_autonomy, reasons[]}`.

## pipeline.py · postdeploy.py

`run_predeploy(settings, target_dir, intent_path, scenario_id, generator_kind, target_resource, ...)` → `PipelineResult{run_id, run_dir, status(DONE/NO_FINDING/INSUFFICIENT_INFO/GENERATION_FAILED/ABSTAIN/NOT_SUPPORTED/TOOL_ERROR/UNSUPPORTED_RULE), gate, validity, candidate, note}`.
`run_postdeploy(settings, intent_path, sg_ids, v8_checks_path, execute, run_id, tf_dir)` → 문자열 요약 + `data/runs/<id>/verification_post.json`.
`run_recover(settings, run_id, execute, tf_dir)` → 종료 코드; 기록 상태 RECOVERY_PENDING / RECOVERY_INCOMPLETE / RECOVERED.

## V8 체크 정의 (JSON)

```json
{"checks": [
  {"label": "ssh from approved", "host": "<instance public ip>", "port": 22, "expect": "open",
   "vantage": "local", "source_class": "approved", "service_label": "ssh", "timeout_s": 5},
  {"label": "ssh from unapproved", "host": "<instance public ip>", "port": 22, "expect": "closed",
   "vantage": "hotspot", "source_class": "unapproved", "service_label": "ssh", "observed": "timeout"}
]}
```
`vantage != local` 인 검사는 그 지점에서 사람이 실행하고 결과를 `observed` 에 적는다. 보호 서비스마다 `unapproved` 의 `closed` 검사가 없으면 V8 은 PASS 가 아니라 UNKNOWN 이다.
