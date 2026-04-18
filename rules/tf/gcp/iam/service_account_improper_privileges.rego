# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/service_account_with_improper_privileges

package vulnetix.rules.kics_tf_gcp_sa_improper_privileges

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-063",
	"name": "Service account has improper privileges",
	"description": "Service accounts should not have owner or editor roles. Apply principle of least privilege.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"tags": ["terraform", "gcp", "iam", "service-account", "privilege"],
}

findings contains finding if {
	some r in terraform.resources("google_service_account_iam_member")
	member := terraform.string_attr(r.block, "member")
	role := terraform.string_attr(r.block, "role")
	role in {"roles/owner", "roles/editor"}
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Service account IAM member %q has improper privilege %q", [member, role]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_service_account_iam_member.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_service_account_iam_binding")
	role := terraform.string_attr(r.block, "role")
	role in {"roles/owner", "roles/editor"}
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Service account IAM binding %q has improper privilege %q", [r.name, role]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_service_account_iam_binding.%s", [r.name]),
	}
}
