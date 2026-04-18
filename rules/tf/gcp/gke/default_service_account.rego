# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/gke_using_default_service_account

package vulnetix.rules.kics_tf_gcp_gke_default_service_account

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-020",
	"name": "GKE cluster uses default service account",
	"description": "GKE clusters should use a dedicated service account instead of the default Compute Engine service account.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "service-account"],
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	subs := terraform.sub_blocks(r.block, "node_config")
	count(subs) > 0
	some sub in subs
	email := terraform.string_attr(sub, "service_account")
	regex.match(terraform.service_accounts, email)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q uses default service account %q", [r.name, email]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_container_node_pool")
	subs := terraform.sub_blocks(r.block, "node_config")
	count(subs) > 0
	some sub in subs
	email := terraform.string_attr(sub, "service_account")
	regex.match(terraform.service_accounts, email)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE node pool %q uses default service account %q", [r.name, email]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_container_node_pool.%s", [r.name]),
	}
}
