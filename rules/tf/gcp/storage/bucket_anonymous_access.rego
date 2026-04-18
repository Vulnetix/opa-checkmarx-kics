# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/cloud_storage_anonymous_or_publicly_accessible

package vulnetix.rules.kics_tf_gcp_storage_anonymous_access

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-002",
	"name": "Cloud Storage bucket allows anonymous or public access",
	"description": "Cloud Storage bucket ACLs or IAM bindings should not allow anonymous or public access.",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "storage", "anonymous-access"],
}

# Check google_storage_bucket_access_control for public access
findings contains finding if {
	some r in terraform.resources("google_storage_bucket_access_control")
	entity := terraform.string_attr(r.block, "entity")
	entity in {"allUsers", "allAuthenticatedUsers"}
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage bucket access control %q allows anonymous access via %q", [r.name, entity]),
		"artifact_uri": r.path,
		"severity": "critical",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_storage_bucket_access_control.%s", [r.name]),
	}
}

# Check google_storage_default_object_access_control for public access
findings contains finding if {
	some r in terraform.resources("google_storage_default_object_access_control")
	entity := terraform.string_attr(r.block, "entity")
	entity in {"allUsers", "allAuthenticatedUsers"}
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Storage default object access control %q allows anonymous access via %q", [r.name, entity]),
		"artifact_uri": r.path,
		"severity": "critical",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_storage_default_object_access_control.%s", [r.name]),
	}
}
