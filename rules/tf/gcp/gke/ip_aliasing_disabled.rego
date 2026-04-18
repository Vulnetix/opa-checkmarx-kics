# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/ip_aliasing_disabled

package vulnetix.rules.kics_tf_gcp_gke_ip_aliasing_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-039",
	"name": "GKE cluster IP aliasing is disabled",
	"description": "GKE clusters should have IP aliasing enabled to provide better pod networking and security.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "networking"],
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	some block in terraform.sub_blocks(r.block, "ip_allocation_policy")
	not terraform.not_existing_or_true(block, "use_ip_aliases")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q has IP aliasing disabled in ip_allocation_policy", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	not terraform.has_sub_block(r.block, "ip_allocation_policy")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q does not have ip_allocation_policy configured for IP aliasing", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
