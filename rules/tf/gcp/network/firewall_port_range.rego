# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_compute_network_using_firewall_rule_allows_port_range

package vulnetix.rules.kics_tf_gcp_firewall_port_range

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-050",
	"name": "Firewall rule allows overly broad port range",
	"description": "VPC firewall rules should not allow access to port ranges that are too broad.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "network", "firewall"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_firewall")
	allow_blocks := terraform.sub_blocks(r.block, "allow")
	count(allow_blocks) > 0
	some allow in allow_blocks
	ports := terraform.string_list_attr(allow, "ports")
	some port in ports
	contains(port, "-")
	port != "0-65535"
	parts := split(port, "-")
	low := to_number(parts[0])
	high := to_number(parts[1])
	(high - low) > 1000
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Firewall rule %q allows overly broad port range %q", [r.name, port]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "info",
		"start_line": 1,
		"snippet": sprintf("google_compute_firewall.%s", [r.name]),
	}
}
