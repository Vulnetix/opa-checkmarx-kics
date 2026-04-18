# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/kms_admin_and_crypto_key_roles_in_use

package vulnetix.rules.kics_tf_gcp_kms_admin_roles

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-053",
	"name": "KMS key has overly permissive roles",
	"description": "KMS keys should not have owner or editor roles assigned. Use more granular kms_admin or kms_encrypter/decrypter roles instead.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"tags": ["terraform", "gcp", "kms", "iam"],
}

findings contains finding if {
	some r in terraform.resources("google_kms_crypto_key_iam_member")
	member := terraform.string_attr(r.block, "member")
	role := terraform.string_attr(r.block, "role")
	role in {"roles/owner", "roles/editor"}
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS key IAM member %q has overly permissive role %q", [member, role]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_kms_crypto_key_iam_member.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_kms_key_ring_iam_member")
	member := terraform.string_attr(r.block, "member")
	role := terraform.string_attr(r.block, "role")
	role in {"roles/owner", "roles/editor"}
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("KMS key ring IAM member %q has overly permissive role %q", [member, role]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_kms_key_ring_iam_member.%s", [r.name]),
	}
}
