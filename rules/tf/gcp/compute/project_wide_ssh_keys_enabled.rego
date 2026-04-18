# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/project_wide_ssh_keys_are_enabled_in_vm_instances

package vulnetix.rules.kics_tf_gcp_project_wide_ssh_keys

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-043",
	"name": "VM instance has project-wide SSH keys enabled",
	"description": "VM instances should block project-wide SSH keys and use instance-level keys only for better access control.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "compute", "ssh"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_instance")
	some block in terraform.sub_blocks(r.block, "metadata")
	val := terraform.string_attr(block, "block-project-ssh-keys")
	val == "FALSE"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM instance %q does not block project-wide SSH keys", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_instance.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_compute_instance")
	not terraform.has_sub_block(r.block, "metadata")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM instance %q does not have metadata to block project-wide SSH keys", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_instance.%s", [r.name]),
	}
}
