# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/node_auto_upgrade_disabled

package vulnetix.rules.kics_tf_gcp_gke_node_auto_upgrade_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-018",
	"name": "GKE node pool auto-upgrade is disabled",
	"description": "GKE node pools should have auto-upgrade enabled to ensure nodes receive security patches automatically.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "auto-upgrade"],
}

# Check if management block is missing
findings contains finding if {
	some r in terraform.resources("google_container_node_pool")
	not terraform.has_sub_block(r.block, "management")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE node pool %q does not have management block configured for auto_upgrade", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_container_node_pool.%s", [r.name]),
	}
}

# Check if auto_upgrade is explicitly false
findings contains finding if {
	some r in terraform.resources("google_container_node_pool")
	subs := terraform.sub_blocks(r.block, "management")
	count(subs) > 0
	some sub in subs
	terraform.bool_attr(sub, "auto_upgrade") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE node pool %q has auto_upgrade disabled in management block", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_container_node_pool.%s", [r.name]),
	}
}
