# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/using_default_service_account

package vulnetix.rules.kics_tf_gcp_iam_default_service_account

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-033",
	"name": "Using default service account",
	"description": "Resources should use dedicated service accounts instead of default service accounts for better security and auditability.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"tags": ["terraform", "gcp", "iam", "service-account"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_instance")
	some block in terraform.sub_blocks(r.block, "service_account")
	email := terraform.string_attr(block, "email")
	regex.match(terraform.service_accounts, email)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Compute instance %q uses default service account %q", [r.name, email]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_instance.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_cloudfunctions_function")
	some block in terraform.sub_blocks(r.block, "event_trigger")
	service_account := terraform.string_attr(block, "service_account_email")
	regex.match(terraform.service_accounts, service_account)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cloud Function %q uses default service account", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_cloudfunctions_function.%s", [r.name]),
	}
}
