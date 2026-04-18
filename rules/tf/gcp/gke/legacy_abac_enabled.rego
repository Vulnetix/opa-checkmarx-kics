# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/gke_legacy_authorization_enabled

package vulnetix.rules.kics_tf_gcp_gke_legacy_abac

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-011",
	"name": "GKE cluster has legacy ABAC enabled",
	"description": "GKE clusters should not have legacy Attribute-Based Access Control (ABAC) enabled. ABAC is deprecated and RBAC should be used instead.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "abac"],
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	terraform.bool_attr(r.block, "enable_legacy_abac") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has legacy ABAC enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
