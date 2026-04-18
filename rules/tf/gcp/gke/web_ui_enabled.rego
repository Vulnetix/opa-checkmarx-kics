# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/kubernetes_web_ui_is_not_disabled

package vulnetix.rules.kics_tf_gcp_gke_web_ui_enabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-049",
	"name": "GKE cluster Kubernetes Dashboard is enabled",
	"description": "GKE clusters should have the Kubernetes Dashboard disabled as it can be a security risk and is deprecated.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "dashboard"],
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	some addon_block in terraform.sub_blocks(r.block, "addons_config")
	some dash_block in terraform.sub_blocks(addon_block, "kubernetes_dashboard")
	terraform.is_false(dash_block, "disabled")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has Kubernetes Dashboard enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
