# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/kms_crypto_key_publicly_accessible

package vulnetix.rules.kics_tf_gcp_kms_key_public

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-024",
	"name": "KMS crypto key is publicly accessible",
	"description": "KMS crypto keys should not be publicly accessible via IAM policies.",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "kms", "public-access"],
}

findings contains finding if {
	some r in terraform.resources("google_kms_crypto_key_iam_member")
	member := terraform.string_attr(r.block, "member")
	member in terraform.public_users
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS crypto key IAM member %q grants public access to %q", [r.name, member]),
		"artifact_uri": r.path,
		"severity": "critical",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_kms_crypto_key_iam_member.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_kms_crypto_key_iam_binding")
	members := terraform.string_list_attr(r.block, "members")
	some m in members
	m in terraform.public_users
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS crypto key IAM binding %q grants public access to %q", [r.name, m]),
		"artifact_uri": r.path,
		"severity": "critical",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_kms_crypto_key_iam_binding.%s", [r.name]),
	}
}
