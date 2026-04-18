# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/shielded_gke_nodes_disabled

package vulnetix.rules.kics_tf_gcp_gke_shielded_nodes_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-014",
	"name": "GKE cluster shielded nodes are disabled",
	"description": "GKE clusters should have Shielded GKE Nodes enabled to provide strong cryptographic identity for nodes.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "shielded"],
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	terraform.is_false(r.block, "enable_shielded_nodes")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has shielded nodes disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
