# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/ensure_gke_version_management_is_automated_using_release_channels

package vulnetix.rules.kics_tf_gcp_gke_release_channels

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-052",
	"name": "GKE cluster does not use release channels",
	"description": "GKE clusters should use release channels for automated version management to ensure timely security updates.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "release-channel"],
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	not terraform.has_sub_block(r.block, "release_channel")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q does not use release channels for version management", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_container_cluster")
	subs := terraform.sub_blocks(r.block, "release_channel")
	count(subs) > 0
	some sub in subs
	channel := terraform.string_attr(sub, "channel")
	channel == "UNSPECIFIED"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE cluster %q uses UNSPECIFIED release channel", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_cluster.%s", [r.name]),
	}
}
