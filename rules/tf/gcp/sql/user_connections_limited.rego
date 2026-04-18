# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_with_limited_user_connections

package vulnetix.rules.kics_tf_gcp_sql_user_connections

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-064",
	"name": "SQL instance user connections are not limited",
	"description": "SQL database instances should limit the number of concurrent user connections to prevent resource exhaustion.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": [],
	"tags": ["terraform", "gcp", "sql", "configuration"],
}

findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	some settings in terraform.sub_blocks(r.block, "settings")
	some db_flags in terraform.sub_blocks(settings, "database_flags")
	name := terraform.string_attr(db_flags, "name")
	name == "user connections"
	value := terraform.string_attr(db_flags, "value")
	num := to_number(value)
	num > 0
	num > 1000
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL instance %q has high user connection limit: %v", [r.name, num]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "info",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
