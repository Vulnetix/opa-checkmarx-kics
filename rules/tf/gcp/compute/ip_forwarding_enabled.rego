# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/ip_forwarding_enabled

package vulnetix.rules.kics_tf_gcp_ip_forwarding_enabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-007",
	"name": "VM instance has IP forwarding enabled",
	"description": "VM instances should not have IP forwarding enabled unless explicitly required. IP forwarding allows instances to send and receive packets with non-matching source or destination IP addresses.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "compute", "networking"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_instance")
	terraform.bool_attr(r.block, "can_ip_forward") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VM instance %q has IP forwarding (can_ip_forward) enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_instance.%s", [r.name]),
	}
}
