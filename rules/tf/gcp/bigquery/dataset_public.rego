# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/bigquery_dataset_is_public

package vulnetix.rules.kics_tf_gcp_bigquery_public

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-034",
	"name": "BigQuery dataset is publicly accessible",
	"description": "BigQuery datasets should not be accessible by allAuthenticatedUsers which grants access to any authenticated Google account.",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "bigquery", "public-access"],
}

findings contains finding if {
	some r in terraform.resources("google_bigquery_dataset")
	some access_block in terraform.sub_blocks(r.block, "access")
	special_group := terraform.string_attr(access_block, "special_group")
	special_group == "allAuthenticatedUsers"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("BigQuery dataset %q grants access to allAuthenticatedUsers", [r.name]),
		"artifact_uri": r.path,
		"severity": "critical",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_bigquery_dataset.%s", [r.name]),
	}
}

findings contains finding if {
	some r in terraform.resources("google_bigquery_dataset")
	some access_block in terraform.sub_blocks(r.block, "access")
	group_by_email := terraform.string_attr(access_block, "group_by_email")
	regex.match(`.*allAuthenticatedUsers.*`, group_by_email)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("BigQuery dataset %q grants access to allAuthenticatedUsers via group", [r.name]),
		"artifact_uri": r.path,
		"severity": "critical",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_bigquery_dataset.%s", [r.name]),
	}
}
