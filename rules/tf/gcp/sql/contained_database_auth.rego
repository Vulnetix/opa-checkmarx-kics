# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_with_contained_database_authentication

package vulnetix.rules.kics_tf_gcp_sql_contained_auth

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-057",
	"name": "SQL Server instance has contained database authentication enabled",
	"description": "SQL Server database instances should have contained database authentication disabled for security.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-287"],
	"tags": ["terraform", "gcp", "sql", "sqlserver", "authentication"],
}

findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	version := terraform.string_attr(r.block, "database_version")
	contains(lower(version), "sqlserver")
	some settings in terraform.sub_blocks(r.block, "settings")
	some db_flags in terraform.sub_blocks(settings, "database_flags")
	name := terraform.string_attr(db_flags, "name")
	name == "contained database authentication"
	value := terraform.string_attr(db_flags, "value")
	value != "off"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Server instance %q has contained database authentication enabled (value=%q)", [r.name, value]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
