# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/legacy_networks_do_not_exist_for_older_google_projects

package vulnetix.rules.kics_tf_gcp_legacy_network

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-055",
	"name": "VPC network uses legacy mode",
	"description": "VPC networks should not use legacy mode. Use auto or custom subnet mode instead.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"tags": ["terraform", "gcp", "network", "vpc", "legacy"],
}

findings contains finding if {
	some r in terraform.resources("google_compute_network")
	auto := terraform.bool_attr(r.block, "auto_create_subnetworks")
	auto == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("VPC network %q may be using legacy mode (auto_create_subnetworks = false)", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_compute_network.%s", [r.name]),
	}
}
