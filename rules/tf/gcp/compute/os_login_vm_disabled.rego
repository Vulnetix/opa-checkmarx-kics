# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/os_login_is_disabled_for_vm_instance

package vulnetix.rules.kics_tf_gcp_vm_os_login_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-062",
	"name": "OS Login is disabled for VM instance",
	"description": "VM instances should have OS Login enabled to manage SSH access using IAM roles instead of SSH keys.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "compute", "ssh", "os-login"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_instance")
	some block in terraform.sub_blocks(r.block, "metadata")
	val := terraform.string_attr(block, "enable-oslogin")
	val == "FALSE"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM instance %q has OS Login disabled via metadata", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_instance.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_compute_instance")
	some block in terraform.sub_blocks(r.block, "metadata")
	val := terraform.string_attr(block, "enable-oslogin")
	val == "false"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM instance %q has OS Login disabled via metadata", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_instance.%s", [r.name]),
	}
}
