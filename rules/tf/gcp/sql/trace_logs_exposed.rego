# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_with_exposed_trace_logs

package vulnetix.rules.kics_tf_gcp_sql_trace_logs_exposed

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-069",
	"name": "SQL instance trace logs are exposed",
	"description": "SQL database instances should have trace logs properly configured to avoid information disclosure.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": ["CWE-200"],
	"tags": ["terraform", "gcp", "sql", "logging"],
}

findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	some settings in terraform.sub_blocks(r.block, "settings")
	some db_flags in terraform.sub_blocks(settings, "database_flags")
	name := terraform.string_attr(db_flags, "name")
	name == "log_checkpoints"
	value := terraform.string_attr(db_flags, "value")
	value == "off"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL instance %q has checkpoint logging disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "info",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
