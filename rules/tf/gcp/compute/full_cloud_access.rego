# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/vm_with_full_cloud_access

package vulnetix.rules.kics_tf_gcp_vm_full_cloud_access

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-009",
	"name": "VM instance has full cloud access",
	"description": "VM instances should not have cloud-platform scope which grants full access to all Google Cloud resources.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"tags": ["terraform", "gcp", "compute", "iam", "privilege"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_instance")
	some block in terraform.sub_blocks(r.block, "service_account")
	scopes := terraform.string_list_attr(block, "scopes")
	some scope in scopes
	scope == "cloud-platform"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM instance %q has service_account with full cloud-platform scope", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_compute_instance.%s", [r.name]),
	}
}
