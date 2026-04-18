# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/high_google_kms_crypto_key_rotation_period

package vulnetix.rules.kics_tf_gcp_kms_key_rotation

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-025",
	"name": "KMS crypto key rotation period is too long",
	"description": "KMS crypto keys should have an automatic rotation period of 90 days or less.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-310"],
	"tags": ["terraform", "gcp", "kms", "rotation"],
}

# One day in seconds
day_in_seconds := 24 * 60 * 60

# 90 days in seconds
max_rotation_seconds := 90 * day_in_seconds

findings contains finding if {
	some r in terraform.resources("google_kms_crypto_key")
	rotation := terraform.string_attr(r.block, "rotation_period")
	rotation != ""
	# Parse rotation period like "7776000s"
	not _rotation_is_valid(rotation)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS crypto key %q has rotation period %q which exceeds 90 days", [r.name, rotation]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_kms_crypto_key.%s", [r.name]),
	}
}

_rotation_is_valid(rotation) if {
	# Extract number from format like "7776000s"
	digits := regex.find_all_string_submatch_n(`^([0-9]+)s$`, rotation, 1)
	count(digits) > 0
	count(digits[0]) > 1
	seconds := to_number(digits[0][1])
	seconds <= max_rotation_seconds
}

# Check if rotation_period is not set
findings contains finding if {
	some r in terraform.resources("google_kms_crypto_key")
	not terraform.has_key(r.block, "rotation_period")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS crypto key %q does not have automatic rotation configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_kms_crypto_key.%s", [r.name]),
	}
}
