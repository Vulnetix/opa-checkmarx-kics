# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/cloud_storage_bucket_versioning_disabled

package vulnetix.rules.kics_tf_gcp_storage_versioning_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-003",
	"name": "Cloud Storage bucket versioning is disabled",
	"description": "Cloud Storage bucket should have versioning enabled to protect against accidental deletion and enable recovery.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"tags": ["terraform", "gcp", "storage", "versioning"],
}

findings contains finding if {
	some r in terraform.resources("google_storage_bucket")
	not terraform.has_sub_block(r.block, "versioning")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage bucket %q does not have versioning configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_storage_bucket.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_storage_bucket")
	subs := terraform.sub_blocks(r.block, "versioning")
	count(subs) > 0
	some sub in subs
	not terraform.not_existing_or_true(sub, "enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage bucket %q has versioning disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_storage_bucket.%s", [r.name]),
	}
}
