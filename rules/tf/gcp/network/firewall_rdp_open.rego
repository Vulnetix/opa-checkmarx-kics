# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/rdp_access_is_not_restricted

package vulnetix.rules.kics_tf_gcp_firewall_rdp_open

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-029",
	"name": "Firewall rule allows unrestricted RDP access",
	"description": "VPC firewall rules should not allow unrestricted RDP access (port 3389) from the internet (0.0.0.0/0).",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "network", "firewall", "rdp"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_firewall")
	direction := terraform.string_attr(r.block, "direction")
	direction in {"INGRESS", "ingress", ""}
	sources := terraform.string_list_attr(r.block, "source_ranges")
	some src in sources
	src in {"0.0.0.0/0", "::/0"}
	allows_block := terraform.sub_blocks(r.block, "allow")
	count(allows_block) > 0
	some allow in allows_block
	protocol := terraform.string_attr(allow, "protocol")
	protocol in {"tcp", "TCP", "all", "ALL"}
	ports := terraform.string_list_attr(allow, "ports")
	_is_rdp_open(ports, protocol)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Firewall rule %q allows unrestricted RDP access (port 3389) from %q", [r.name, src]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_compute_firewall.%s", [r.name]),
	}
}

_is_rdp_open(ports, protocol) if {
	protocol in {"all", "ALL"}
}

_is_rdp_open(ports, protocol) if {
	count(ports) == 0
}

_is_rdp_open(ports, protocol) if {
	some port in ports
	port in {"3389", "0-65535"}
}

_is_rdp_open(ports, protocol) if {
	some port in ports
	contains(port, "-")
	parts := split(port, "-")
	to_number(parts[0]) <= 3389
	to_number(parts[1]) >= 3389
}
