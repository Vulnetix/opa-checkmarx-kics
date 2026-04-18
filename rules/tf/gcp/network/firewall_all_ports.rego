# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_compute_network_using_firewall_rule_allows_all_ports

package vulnetix.rules.kics_tf_gcp_firewall_all_ports

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-030",
	"name": "Firewall rule allows access to all ports",
	"description": "VPC firewall rules should not allow access to all ports (0-65535) from the internet.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "network", "firewall"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_firewall")
	direction := terraform.string_attr(r.block, "direction")
	direction in {"INGRESS", "ingress", ""}
	sources := terraform.string_list_attr(r.block, "source_ranges")
	some src in sources
	allows_block := terraform.sub_blocks(r.block, "allow")
	count(allows_block) > 0
	some allow in allows_block
	ports := terraform.string_list_attr(allow, "ports")
	some port in ports
	port == "0-65535"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Firewall rule %q allows access to all ports (0-65535) from %q", [r.name, src]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_compute_firewall.%s", [r.name]),
	}
}
