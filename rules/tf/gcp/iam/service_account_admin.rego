# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_project_iam_member_service_account_has_admin_role

package vulnetix.rules.kics_tf_gcp_iam_sa_admin

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-031",
	"name": "Service account has admin role",
	"description": "Service accounts should not be assigned owner, editor, or admin roles. Use more granular roles instead.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"tags": ["terraform", "gcp", "iam", "privilege"],
}

findings contains finding if {
	some r in terraform.resources("google_project_iam_member")
	member := terraform.string_attr(r.block, "member")
	contains(member, "@")
	role := terraform.string_attr(r.block, "role")
	_is_admin_role(role)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM member %q has admin role %q", [member, role]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_project_iam_member.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_project_iam_binding")
	role := terraform.string_attr(r.block, "role")
	_is_admin_role(role)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM binding %q has admin role %q", [r.name, role]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_project_iam_binding.%s", [r.name]),
	}
}

_is_admin_role(role) if contains(lower(role), "admin")
_is_admin_role(role) if role == "roles/owner"
_is_admin_role(role) if role == "roles/editor"
