# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_with_global_user_options

package vulnetix.rules.kics_tf_gcp_sql_global_options

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-060",
	"name": "SQL Server instance has global user options set",
	"description": "SQL Server database instances should review and restrict global user options that could affect security.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": [],
	"tags": ["terraform", "gcp", "sql", "sqlserver"],
}

findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	version := terraform.string_attr(r.block, "database_version")
	contains(lower(version), "sqlserver")
	some settings in terraform.sub_blocks(r.block, "settings")
	some db_flags in terraform.sub_blocks(settings, "database_flags")
	name := terraform.string_attr(db_flags, "name")
	name == "user options"
	value := terraform.string_attr(db_flags, "value")
	value != ""
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Server instance %q has custom user options configured: %q", [r.name, value]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "info",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
