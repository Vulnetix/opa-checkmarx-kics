# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_project_iam_binding_service_account_has_token_creator_or_account_user_role

package vulnetix.rules.kics_tf_gcp_iam_sa_binding_token

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-061",
	"name": "IAM binding grants service account token creator to service account",
	"description": "IAM bindings should not grant service accounts the ability to create tokens for other service accounts.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"tags": ["terraform", "gcp", "iam", "service-account", "impersonation"],
}

findings contains finding if {
	some r in terraform.resources("google_project_iam_binding")
	role := terraform.string_attr(r.block, "role")
	contains(role, "roles/iam.serviceAccountTokenCreator")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM binding %q grants serviceAccountTokenCreator role", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_project_iam_binding.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_project_iam_binding")
	role := terraform.string_attr(r.block, "role")
	contains(role, "roles/iam.serviceAccountUser")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM binding %q grants serviceAccountUser role", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_project_iam_binding.%s", [r.name]),
	}
}
