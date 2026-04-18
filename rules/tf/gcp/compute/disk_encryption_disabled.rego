# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/disk_encryption_disabled

package vulnetix.rules.kics_tf_gcp_disk_encryption_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-006",
	"name": "Compute disk encryption is disabled",
	"description": "Compute Engine disk should have encryption enabled using either raw_key or kms_key_self_link.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"tags": ["terraform", "gcp", "compute", "encryption"],
}

# Check if disk_encryption_key is missing
findings contains finding if {
	some r in terraform.resources("google_compute_disk")
	not terraform.has_sub_block(r.block, "disk_encryption_key")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Compute disk %q does not have disk_encryption_key configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_compute_disk.%s", [r.name]),
	}
}

# Check if both raw_key and kms_key_self_link are missing in disk_encryption_key
findings contains finding if {
	some r in terraform.resources("google_compute_disk")
	subs := terraform.sub_blocks(r.block, "disk_encryption_key")
	count(subs) > 0
	some sub in subs
	not terraform.has_key(sub, "raw_key")
	not terraform.has_key(sub, "kms_key_self_link")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Compute disk %q disk_encryption_key does not have raw_key or kms_key_self_link", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_compute_disk.%s", [r.name]),
	}
}
