# Ported from checkmarx-kics: disk_encryption_disabled.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_gcp_compute_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-GCP-COMPUTE-01",
	"name": "GCP Compute Disk should have encryption enabled",
	"description": "GCP Compute Disk should have disk_encryption_key defined with either raw_key or kms_key_self_link to ensure data at rest is encrypted.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-311"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "compute", "disk", "encryption", "security"],
}

findings contains finding if {
	some r in tf.resources("google_compute_disk")
	not tf.has_sub_block(r.block, "disk_encryption_key")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_disk %q is missing disk_encryption_key block.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}

findings contains finding if {
	some r in tf.resources("google_compute_disk")
	tf.has_sub_block(r.block, "disk_encryption_key")
	key_blocks := tf.sub_blocks(r.block, "disk_encryption_key")
	count(key_blocks) > 0
	key_block := key_blocks[0]
	not tf.has_key(key_block, "raw_key")
	not tf.has_key(key_block, "kms_key_self_link")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_compute_disk %q disk_encryption_key is missing raw_key or kms_key_self_link.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 5),
	}
}
