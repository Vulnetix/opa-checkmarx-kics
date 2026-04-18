# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/cluster_labels_disabled

package vulnetix.rules.kics_tf_gcp_gke_labels_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-038",
	"name": "GKE cluster labels are disabled",
	"description": "GKE clusters should have resource_labels defined for cost allocation and resource management.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": [],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "labels"],
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	not terraform.has_key(r.block, "resource_labels")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q does not have resource_labels defined", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "info",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
