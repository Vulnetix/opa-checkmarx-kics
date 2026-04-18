# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_with_minimum_log_duration

package vulnetix.rules.kics_tf_gcp_sql_min_log_duration

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-065",
	"name": "SQL instance minimum log statement duration not configured",
	"description": "SQL database instances should have a minimum duration configured for log_statement to avoid excessive logging.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": [],
	"tags": ["terraform", "gcp", "sql", "logging"],
}

findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	some settings in terraform.sub_blocks(r.block, "settings")
	some db_flags in terraform.sub_blocks(settings, "database_flags")
	name := terraform.string_attr(db_flags, "name")
	name == "log_min_duration_statement"
	value := terraform.string_attr(db_flags, "value")
	value == "0"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL instance %q has log_min_duration_statement set to 0 (logs all statements)", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "info",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
