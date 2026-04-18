# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_storage_bucket_level_access_disabled

package vulnetix.rules.kics_tf_gcp_storage_uniform_access_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-005",
	"name": "Cloud Storage bucket uniform bucket-level access is disabled",
	"description": "Cloud Storage bucket should have uniform bucket-level access enabled to simplify permissions management and prevent unintended access.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "storage", "access-control"],
}

findings contains finding if {
	some r in terraform.resources("google_storage_bucket")
	not terraform.has_key(r.block, "uniform_bucket_level_access")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage bucket %q does not have uniform_bucket_level_access configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_storage_bucket.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_storage_bucket")
	terraform.is_false(r.block, "uniform_bucket_level_access")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage bucket %q has uniform_bucket_level_access disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_storage_bucket.%s", [r.name]),
	}
}
