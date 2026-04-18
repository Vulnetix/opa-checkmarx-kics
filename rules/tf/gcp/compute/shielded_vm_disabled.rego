# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/shielded_vm_disabled

package vulnetix.rules.kics_tf_gcp_shielded_vm_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-008",
	"name": "VM instance shielded VM is disabled",
	"description": "VM instances should have Shielded VM features enabled (Secure Boot, vTPM, Integrity Monitoring) for enhanced protection against rootkits and bootkits.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"tags": ["terraform", "gcp", "compute", "shielded-vm"],
}

# Check if shielded_instance_config is missing
findings contains finding if {
	some r in terraform.resources("google_compute_instance")
	not terraform.has_sub_block(r.block, "shielded_instance_config")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM instance %q does not have shielded_instance_config configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_instance.%s", [r.name]),
	}
}

# Check if shielded features are disabled
findings contains finding if {
	some r in terraform.resources("google_compute_instance")
	subs := terraform.sub_blocks(r.block, "shielded_instance_config")
	count(subs) > 0
	some sub in subs
	terraform.is_false(sub, "enable_secure_boot")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM instance %q has shielded_instance_config enable_secure_boot disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_instance.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_compute_instance")
	subs := terraform.sub_blocks(r.block, "shielded_instance_config")
	count(subs) > 0
	some sub in subs
	terraform.is_false(sub, "enable_vtpm")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM instance %q has shielded_instance_config enable_vtpm disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_instance.%s", [r.name]),
	}
}
