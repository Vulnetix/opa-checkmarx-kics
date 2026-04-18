# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/cos_node_image_not_used

package vulnetix.rules.kics_tf_gcp_gke_cos_image_not_used

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-042",
	"name": "GKE node pool does not use Container-Optimized OS",
	"description": "GKE node pools should use Container-Optimized OS (COS) for enhanced security and minimal attack surface.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"tags": ["terraform", "gcp", "gke", "kubernetes", "cos"],
}

findings contains finding if {
	some r in terraform.resources("google_container_node_pool")
	some block in terraform.sub_blocks(r.block, "node_config")
	image := terraform.string_attr(block, "image_type")
	image != ""
	not startswith(lower(image), "cos")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("GKE node pool %q does not use Container-Optimized OS (current: %q)", [r.name, image]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_container_node_pool.%s", [r.name]),
	}
}
