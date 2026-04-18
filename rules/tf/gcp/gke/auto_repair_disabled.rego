# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_container_node_pool_auto_repair_disabled

package vulnetix.rules.kics_tf_gcp_gke_auto_repair_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-019",
	"name": "GKE node pool auto-repair is disabled",
	"description": "GKE node pools should have auto-repair enabled to automatically repair unhealthy nodes.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "auto-repair"],
}

# Check if management block is missing
findings contains finding if {
	some r in terraform.resources("google_container_node_pool")
	not terraform.has_sub_block(r.block, "management")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE node pool %q does not have management block configured for auto_repair", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_node_pool.%s", [r.name]),
	}
}

# Check if auto_repair is explicitly false
findings contains finding if {
	some r in terraform.resources("google_container_node_pool")
	subs := terraform.sub_blocks(r.block, "management")
	count(subs) > 0
	some sub in subs
	terraform.bool_attr(sub, "auto_repair") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE node pool %q has auto_repair disabled in management block", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_node_pool.%s", [r.name]),
	}
}
