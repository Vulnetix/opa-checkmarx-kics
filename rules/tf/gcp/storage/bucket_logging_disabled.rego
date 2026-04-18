# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/cloud_storage_bucket_logging_not_enabled

package vulnetix.rules.kics_tf_gcp_storage_logging_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-004",
	"name": "Cloud Storage bucket logging is not enabled",
	"description": "Cloud Storage bucket should have access logging enabled for security monitoring and audit purposes.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["terraform", "gcp", "storage", "logging"],
}

findings contains finding if {
	some r in terraform.resources("google_storage_bucket")
	not terraform.has_sub_block(r.block, "logging")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage bucket %q does not have access logging enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_storage_bucket.%s", [r.name]),
	}
}
