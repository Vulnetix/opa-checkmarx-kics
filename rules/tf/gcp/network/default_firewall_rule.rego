# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_compute_network_using_default_firewall_rule

package vulnetix.rules.kics_tf_gcp_default_firewall_rule

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-045",
	"name": "Network uses default firewall rule",
	"description": "VPC networks should not rely on the default firewall rule which allows internal traffic. Custom rules should be defined.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "network", "firewall"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_network")
	firewall_rules := terraform.resources("google_compute_firewall")
	some fw in firewall_rules
	_network_matches(fw, r.name)
	_default_source_range(fw)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VPC network %q uses default firewall rule from %q", [r.name, fw.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_compute_network.%s", [r.name]),
	}
}

# Helper to check if firewall rule applies to the network
_network_matches(fw, network_name) if {
	network_attr := terraform.string_attr(fw.block, "network")
	contains(network_attr, network_name)
}

# Helper to check for default source range
_default_source_range(fw) if {
	sources := terraform.string_list_attr(fw.block, "source_ranges")
	some src in sources
	contains(src, "0.0.0.0/0")
}

_default_source_range(fw) if {
	sources := terraform.string_list_attr(fw.block, "source_ranges")
	count(sources) == 0
}
