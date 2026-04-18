# Ported from checkmarx-kics: cloud_storage_bucket_versioning_disabled.
# Simplified: uses regex-based parsing on input.file_contents.

package vulnetix.rules.kics_tf_gcp_storage_01

import rego.v1

import data.vulnetix.kics.tf

metadata := {
	"id": "KICS-TF-GCP-STORAGE-01",
	"name": "GCS Bucket should have versioning enabled",
	"description": "Google Cloud Storage buckets should have versioning enabled. Versioning allows recovery from accidental deletion or overwriting of objects.",
	"help_uri": "https://github.com/Checkmarx/kics",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["terraform", "gcp", "storage", "gcs", "versioning", "security"],
}

findings contains finding if {
	some r in tf.resources("google_storage_bucket")
	not tf.has_sub_block(r.block, "versioning")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_storage_bucket %q is missing versioning configuration.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 3),
	}
}

findings contains finding if {
	some r in tf.resources("google_storage_bucket")
	tf.has_sub_block(r.block, "versioning")
	sub := tf.sub_blocks(r.block, "versioning")
	count(sub) > 0
	not regex.match(`(?s)enabled(?i)\s*=\s*true`, sub[0])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("google_storage_bucket %q has versioning.enabled = false.", [r.name]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": tf.block_snippet(r.block, 5),
	}
}
