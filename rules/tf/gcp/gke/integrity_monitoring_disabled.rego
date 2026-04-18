# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/shielded_gke_node_do_not_have_integrity_monitoring_enabled

package vulnetix.rules.kics_tf_gcp_gke_integrity_monitoring_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-041",
	"name": "GKE node pool integrity monitoring is disabled",
	"description": "GKE node pools should have integrity monitoring enabled to detect changes to the boot disk.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "integrity"],
}

findings contains finding if {
	some r in terraform.resources("google_container_node_pool")
	some node_block in terraform.sub_blocks(r.block, "node_config")
	some shield_block in terraform.sub_blocks(node_block, "shielded_instance_config")
	terraform.bool_attr(shield_block, "enable_integrity_monitoring") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE node pool %q has integrity monitoring disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_node_pool.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	some node_block in terraform.sub_blocks(r.block, "node_config")
	some shield_block in terraform.sub_blocks(node_block, "shielded_instance_config")
	terraform.bool_attr(shield_block, "enable_integrity_monitoring") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q node config has integrity monitoring disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
