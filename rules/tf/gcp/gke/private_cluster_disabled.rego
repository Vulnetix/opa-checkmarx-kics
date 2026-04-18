# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/private_cluster_disabled

package vulnetix.rules.kics_tf_gcp_gke_private_cluster_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-013",
	"name": "GKE cluster private cluster is disabled",
	"description": "GKE clusters should be configured as private clusters with private nodes and private endpoints for enhanced security.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "private-cluster"],
}

# Check if private_cluster_config is missing
findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	not terraform.has_sub_block(r.block, "private_cluster_config")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q does not have private_cluster_config configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}

# Check if private features are not both enabled
findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	subs := terraform.sub_blocks(r.block, "private_cluster_config")
	count(subs) > 0
	some sub in subs
	not terraform.bool_attr(sub, "enable_private_endpoint")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has enable_private_endpoint disabled or not set", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	subs := terraform.sub_blocks(r.block, "private_cluster_config")
	count(subs) > 0
	some sub in subs
	not terraform.bool_attr(sub, "enable_private_nodes")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has enable_private_nodes disabled or not set", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
