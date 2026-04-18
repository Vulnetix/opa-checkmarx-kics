# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/vm_serial_ports_are_enabled_for_vm_instances

package vulnetix.rules.kics_tf_gcp_vm_serial_port_enabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-010",
	"name": "VM instance serial port is enabled",
	"description": "VM instances should have serial port access disabled to prevent unauthorized console access.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "compute", "console"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_instance")
	metadata_block := terraform.sub_blocks(r.block, "metadata")
	count(metadata_block) > 0
	some mb in metadata_block
	val := terraform.string_attr(mb, "serial-port-enable")
	val == "true"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM instance %q has serial port enabled via metadata", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_instance.%s", [r.name]),
	}
}
