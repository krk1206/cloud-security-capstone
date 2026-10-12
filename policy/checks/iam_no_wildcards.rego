# METADATA
# title: IAM policy allows all actions or all resources (wildcard)
# description: |
#   Trivy built-in check AWS-0057 (aws-iam-no-policy-wildcards) was removed in trivy-checks on 2024-12-18 and
#   only a deprecated metadata stub remains, so Trivy no longer flags "Action": "*" or "Resource": "*".
#   This custom check restores that detection for the capstone pipeline (scenario 3, IAM over-privilege).
#   Scope: inline role policies (aws_iam_role_policy), standalone policies (aws_iam_policy), user and group policies.
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: CAPSTONE-IAM-0001
#   avd_id: CAPSTONE-IAM-0001
#   severity: HIGH
#   short_code: iam-no-wildcards
#   recommended_action: Replace "*" with the exact actions and resource ARNs listed in policy/required_permissions.yaml
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package user.aws.iam.capstone0001

import rego.v1

to_list(x) := x if is_array(x)

to_list(x) := [x] if not is_array(x)

wildcard_statement(statement, field) if {
	lower(statement.Effect) == "allow"
	some v in to_list(statement[field])
	v == "*"
}

policy_wildcards(document) := {field |
	doc := json.unmarshal(document)
	some statement in doc.Statement
	some field in {"Action", "Resource"}
	wildcard_statement(statement, field)
}

deny contains res if {
	some role in input.aws.iam.roles
	some policy in role.policies
	some field in policy_wildcards(policy.document.value)
	res := result.new(sprintf("IAM role policy '%s' allows %s \"*\"", [policy.name.value, field]), policy.document)
}

deny contains res if {
	some policy in input.aws.iam.policies
	some field in policy_wildcards(policy.document.value)
	res := result.new(sprintf("IAM policy '%s' allows %s \"*\"", [policy.name.value, field]), policy.document)
}

deny contains res if {
	some user in input.aws.iam.users
	some policy in user.policies
	some field in policy_wildcards(policy.document.value)
	res := result.new(sprintf("IAM user policy '%s' allows %s \"*\"", [policy.name.value, field]), policy.document)
}

deny contains res if {
	some group in input.aws.iam.groups
	some policy in group.policies
	some field in policy_wildcards(policy.document.value)
	res := result.new(sprintf("IAM group policy '%s' allows %s \"*\"", [policy.name.value, field]), policy.document)
}
