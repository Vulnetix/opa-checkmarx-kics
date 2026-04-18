# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/cloud_storage_bucket_is_publicly_accessible

package vulnetix.rules.kics_tf_gcp_storage_public_access

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-001",
	"name": "Cloud Storage bucket is publicly accessible",
	"description": "Cloud Storage bucket should not be publicly accessible. Allowing public access can expose sensitive data.",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "storage", "public-access"],
}

# Check google_storage_bucket_iam_member with single member
findings contains finding if {
	some r in terraform.resources("google_storage_bucket_iam_member")
	member := terraform.string_attr(r.block, "member")
	member in terraform.public_users
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage bucket IAM member %q grants public access to %q", [r.name, member]),
		"artifact_uri": r.path,
		"severity": "critical",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_storage_bucket_iam_member.%s", [r.name]),
	}
}

# Check google_storage_bucket_iam_binding with members list
findings contains finding if {
	some r in terraform.resources("google_storage_bucket_iam_binding")
	members := terraform.string_list_attr(r.block, "members")
	some m in members
	m in terraform.public_users
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage bucket IAM binding %q grants public access to %q", [r.name, m]),
		"artifact_uri": r.path,
		"severity": "critical",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_storage_bucket_iam_binding.%s", [r.name]),
	}
}
