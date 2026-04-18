# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/network_policy_disabled

package vulnetix.rules.kics_tf_gcp_gke_network_policy_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-012",
	"name": "GKE cluster network policy is disabled",
	"description": "GKE clusters should have network policy enabled to control traffic between pods.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "network-policy"],
}

# Check if network_policy is missing
findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	not terraform.has_sub_block(r.block, "network_policy")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q does not have network_policy configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}

# Check if network_policy is disabled
findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	subs := terraform.sub_blocks(r.block, "network_policy")
	count(subs) > 0
	some sub in subs
	terraform.is_false(sub, "enabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has network_policy disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
