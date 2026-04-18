# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/google_kubernetes_engine_cluster_has_alpha_features_enabled

package vulnetix.rules.kics_tf_gcp_gke_alpha_features

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-040",
	"name": "GKE cluster has alpha features enabled",
	"description": "GKE clusters should not use alpha features as they are not supported for production workloads and may cause instability.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "alpha"],
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	terraform.bool_attr(r.block, "enable_kubernetes_alpha") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has alpha features enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
