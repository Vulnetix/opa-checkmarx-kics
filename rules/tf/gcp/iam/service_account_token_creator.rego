# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_project_iam_member_service_account_has_token_creator_or_account_user_role

package vulnetix.rules.kics_tf_gcp_iam_sa_token_creator

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-032",
	"name": "Service account has token creator or account user role",
	"description": "Service accounts should not have roles/iam.serviceAccountTokenCreator or roles/iam.serviceAccountUser which allow impersonation.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"tags": ["terraform", "gcp", "iam", "impersonation"],
}

findings contains finding if {
	some r in terraform.resources("google_project_iam_member")
	member := terraform.string_attr(r.block, "member")
	role := terraform.string_attr(r.block, "role")
	role in terraform.impersonation_roles
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM member %q has impersonation role %q", [member, role]),
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
	role in terraform.impersonation_roles
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM binding %q has impersonation role %q", [r.name, role]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_project_iam_binding.%s", [r.name]),
	}
}
