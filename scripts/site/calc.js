// 위험도 기준표 계산기 — src/iacpatch/policy/risk.py score_risk() 와 src/iacpatch/rubric_demo.py calc_risk() 의 JS 이식.
// 공유 사이트(정적 페이지)에서 서버 없이 돌리기 위한 것. 원본은 Python 이고, scripts/build_site.py 가 무작위 입력으로 두 구현을 대조한다.
(function (root) {
  'use strict';
  const CAP = { LOW: 'HIGH', MEDIUM: 'MEDIUM', HIGH: 'LOW' };
  const ORDER = { LOW: 0, MEDIUM: 1, HIGH: 2 };

  function rtypeOf(addr) { const p = addr.split('.'); return p.length >= 2 ? p[p.length - 2] : addr; }
  function typeOf(addr) { return addr.startsWith('module.') ? addr.split('.').slice(-2)[0] : addr.split('.')[0]; }

  function scoreRisk(rubric, details, world, stats, v6, targetType) {
    const pts = rubric.points || {}, th = rubric.thresholds || { low_max: 2, medium_max: 5 }, hard = rubric.hard_high_conditions || {};
    const iamPrefixes = rubric.iam_type_prefixes || ['aws_iam_'];
    const networkTypes = new Set(rubric.network_types || []);
    const isIam = t => iamPrefixes.some(p => String(t).startsWith(p));
    const familyName = (targetType && isIam(targetType)) ? 'iam' : 'network';
    const inFamily = familyName === 'iam' ? isIam : (t => networkTypes.has(t));
    const factors = []; let score = 0; const hardHit = [];
    const add = (factor, value, points, note) => { score += points; factors.push({ factor, value, points, note: note || '' }); };
    const removed = details.removed || [], added = details.added || [], changed = details.changed || {};
    const deletes = details.plan_actions_delete || [], replaces = details.plan_actions_replace || [], pdiff = details.provider_config_diff || [];
    const touched = [];
    for (const a of added) touched.push(String(typeof a === 'object' ? a.type : a));
    for (const addr of [...Object.keys(changed), ...removed]) touched.push(world != null ? typeOf(addr) : addr.split('.')[0]);
    const iamTouched = touched.some(isIam);
    if (hard.iam_resource_touched && iamTouched) hardHit.push('iam_resource_touched');
    const trustChanged = Object.entries(changed).filter(([a, attrs]) => rtypeOf(a) === 'aws_iam_role' && (attrs || []).includes('assume_role_policy'));
    const trustAdded = added.filter(a => (typeof a === 'object' ? String(a.type) : rtypeOf(String(a))) === 'aws_iam_role');
    if (hard.iam_trust_policy_changed && (trustChanged.length || trustAdded.length)) hardHit.push('iam_trust_policy_changed');
    if (hard.resource_deleted && (removed.length || deletes.length)) hardHit.push('resource_deleted');
    if (hard.resource_replaced && replaces.length) hardHit.push('resource_replaced');
    if (hard.provider_config_changed && pdiff.length) hardHit.push('provider_config_changed');
    for (const h of hardHit) factors.push({ factor: h, value: true, points: 0, note: 'hard condition → HIGH risk regardless of score' });
    const outside = [...new Set(touched.filter(t => !inFamily(t)))].sort();
    add('outside_target_family_touched', outside, outside.length ? (pts.outside_target_family_touched ?? pts.non_network_resource_touched ?? 2) : 0, outside.length ? `target family=${familyName}` : '');
    const nTouched = removed.length + added.length + Object.keys(changed).length;
    if (nTouched > 3) add('resources_touched', nTouched, pts.resources_touched_over_3 ?? 3);
    else if (nTouched >= 2) add('resources_touched', nTouched, pts.resources_touched_2_to_3 ?? 1);
    else add('resources_touched', nTouched, 0);
    const nNew = added.length;
    add('new_resources_created', nNew, Math.min(nNew * (pts.new_resource_created_each ?? 1), pts.new_resource_created_cap ?? 2));
    let apCount = 0, ext = false;
    if (world != null) {
      const changedSgs = [...Object.keys(changed), ...added.map(x => typeof x === 'object' ? x.address : x)].filter(a => String(a).startsWith('aws_security_group.'));
      for (const sg of Object.values(world.security_groups || {})) for (const r of (sg.rules || [])) {
        if ((r.origin in changed) || added.some(x => r.origin === (typeof x === 'object' ? x.address : x))) changedSgs.push(sg.address);
      }
      const seen = new Set();
      for (const sgAddr of changedSgs) for (const ap of world.attachments_of(sgAddr)) {
        if (seen.has(ap.address)) continue;
        seen.add(ap.address); apCount += 1;
        if ((ap.external_sg_ids && ap.external_sg_ids.length) || ap.unknown) ext = true;
      }
    }
    if (apCount >= 2) add('attachment_points', apCount, pts.attachment_points_2_or_more ?? 2);
    else if (apCount === 1) add('attachment_points', apCount, pts.attachment_points_1 ?? 1);
    else add('attachment_points', apCount, 0, 'no attachment in plan (standalone SG)');
    add('attachment_has_external_or_unknown_sg', ext, ext ? (pts.attachment_has_external_or_unknown_sg ?? 2) : 0);
    const egress = Object.values(changed).some(attrs => (attrs || []).includes('egress'));
    add('egress_changed', egress, egress ? (pts.egress_changed ?? 1) : 0);
    const nonCore = [];
    for (const [addr, attrs] of Object.entries(changed)) {
      const rt = typeOf(addr);
      const ca = (rubric.core_attributes || {})[rt];
      const core = Array.isArray(ca) ? new Set(ca) : (rt === 'aws_security_group' ? new Set(['ingress', 'egress']) : new Set());
      for (const a of (attrs || [])) if (!core.has(a) && !['tags', 'tags_all', 'description'].includes(a)) nonCore.push(`${addr}.${a}`);
    }
    add('non_core_attribute_changed', nonCore, nonCore.length ? (pts.non_core_attribute_changed ?? pts.non_rule_attribute_changed ?? 1) : 0);
    let partial = false;
    if (v6) for (const t of (v6.targets || [])) for (const sc of (t.scopes || [])) {
      if ((sc.services || []).some(s => s.partial_rules)) partial = true;
      if ((sc.caveats || []).some(c => String(c).includes('ingress'))) partial = true;
    }
    add('oracle_partial_rules_or_caveats', partial, partial ? (pts.oracle_partial_rules_or_caveats ?? 1) : 0);
    const lines = (stats.added_lines | 0) + (stats.removed_lines | 0);
    add('patch_lines', lines, lines > 40 ? (pts.patch_lines_over_40 ?? 1) : 0);
    const files = stats.files == null ? 1 : (stats.files | 0);
    add('files_changed', files, files > 1 ? (pts.multiple_files_changed ?? 1) : 0);
    let level;
    if (hardHit.length) level = 'HIGH';
    else if (score <= (th.low_max ?? 2)) level = 'LOW';
    else if (score <= (th.medium_max ?? 5)) level = 'MEDIUM';
    else level = 'HIGH';
    const floor = rubric.medium_floor_conditions || {};
    if (floor.iam_resource_touched && iamTouched) {
      const raised = level === 'LOW';
      if (raised) level = 'MEDIUM';
      factors.push({ factor: 'iam_resource_touched', value: true, points: 0, note: 'medium floor → at least MEDIUM (human approval required)' + (raised ? '' : ' (score already above LOW)') });
    }
    return { level, cap: CAP[level], score, factors };
  }

  function fakeWorld(nAp, external) {
    const aps = []; for (let i = 0; i < nAp; i++) aps.push({ address: `aws_instance.demo${i}`, external_sg_ids: (external && i === 0) ? ['sg-external'] : [], unknown: false });
    return { security_groups: {}, attachments_of: () => aps.slice() };
  }

  function calcRisk(inputs, rubric) {
    const g = (k, d) => (inputs[k] === undefined || inputs[k] === null) ? d : inputs[k];
    const kind = String(g('target_kind', 'SG')).toUpperCase();
    const targetType = kind === 'IAM' ? 'aws_iam_policy' : 'aws_security_group';
    const addr = kind === 'IAM' ? 'aws_iam_policy.demo' : 'aws_security_group.demo';
    const attrs = String(g('changed_attrs', kind === 'SG' ? 'ingress' : 'policy')).split(',').map(s => s.trim()).filter(Boolean);
    const nTouched = Math.max(parseInt(g('resources_touched', 1), 10) || 1, 1);
    const changed = {}; changed[addr] = attrs;
    for (let i = 1; i < nTouched; i++) {
      const extra = g('outside_family', false) ? 'aws_instance' : (kind === 'SG' ? 'aws_security_group_rule' : 'aws_iam_role_policy');
      changed[`${extra}.extra${i}`] = extra !== 'aws_instance' ? ['description'] : ['tags'];
    }
    const added = []; const nNew = parseInt(g('new_resources', 0), 10) || 0;
    for (let i = 0; i < nNew; i++) added.push({ address: `aws_security_group_rule.new${i}`, type: 'aws_security_group_rule' });
    if (g('trust_policy', false)) changed['aws_iam_role.demo'] = ['assume_role_policy'];
    const details = { removed: g('deleted', false) ? ['aws_security_group.gone'] : [], added, changed, plan_actions_delete: [],
      plan_actions_replace: g('replaced', false) ? [addr] : [], provider_config_diff: g('provider_changed', false) ? ['region'] : [] };
    const world = kind === 'SG' ? fakeWorld(parseInt(g('attachment_points', 0), 10) || 0, !!g('external_sg', false)) : null;
    const v6 = g('oracle_partial', false) ? { targets: [{ scopes: [{ services: [{ partial_rules: true }], caveats: [] }] }] } : null;
    const stats = { added_lines: parseInt(g('lines', 2), 10) || 0, removed_lines: 0, files: parseInt(g('files', 1), 10) || 1 };
    return scoreRisk(rubric, details, world, stats, v6, targetType);
  }

  function gateDecide(riskLevel, proposal, validity, policyOk) {
    const cap = CAP[riskLevel]; const reasons = [];
    if (!policyOk) return { cap, final: null, action: 'BLOCK', reasons: ['policy violation: demo policy violation'] };
    if (validity === 'FAIL') return { cap, final: null, action: 'BLOCK', reasons: ['verification failed: demo FAIL'] };
    if (validity === 'INCOMPLETE') return { cap, final: null, action: 'HOLD_FOR_HUMAN', reasons: ['verification incomplete: demo INCOMPLETE'] };
    let fin = cap;
    if (proposal) {
      if (ORDER[proposal] < ORDER[fin]) { fin = proposal; reasons.push(`llm proposed lower autonomy ${proposal}; applied (cap was ${cap})`); }
      else if (ORDER[proposal] > ORDER[fin]) reasons.push(`llm proposed ${proposal} above cap ${cap}; ignored (cap enforced)`);
      else reasons.push(`llm proposal equals cap (${fin})`);
    }
    reasons.push(`risk ${riskLevel} → autonomy cap ${cap}`);
    const action = { HIGH: 'CREATE_PR_AUTO', MEDIUM: 'CREATE_PR_APPROVAL', LOW: 'REPORT_ONLY' }[fin];
    return { cap, final: fin, action, reasons, forced_down: !!(proposal && ORDER[proposal] > ORDER[fin]) };
  }

  const api = { scoreRisk, calcRisk, gateDecide, CAP, ORDER };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.IaCPatchCalc = api;
})(typeof window !== 'undefined' ? window : globalThis);
