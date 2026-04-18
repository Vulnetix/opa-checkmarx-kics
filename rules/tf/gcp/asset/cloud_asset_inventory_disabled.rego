# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/cloud_asset_inventory_disabled

package vulnetix.rules.kics_tf_gcp_cloud_asset_inventory_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-070",
	"name": "Cloud Asset Inventory is not enabled",
	"description": "GCP organizations should have Cloud Asset Inventory enabled for asset management and security monitoring.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"tags": ["terraform", "gcp", "asset-inventory", "logging"],
}

findings contains finding if {
	some r in terraform.resources("google_cloud_asset_organization_feed")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cloud Asset Organization feed %q is configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_cloud_asset_organization_feed.%s", [r.name]),
	}
}
