# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_with_external_scripts_enabled

package vulnetix.rules.kics_tf_gcp_sql_external_scripts

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-056",
	"name": "SQL Server instance has external scripts enabled",
	"description": "SQL Server database instances should have external scripts disabled to prevent execution of external code.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-94"],
	"tags": ["terraform", "gcp", "sql", "sqlserver", "rce"],
}

findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	version := terraform.string_attr(r.block, "database_version")
	contains(lower(version), "sqlserver")
	some settings in terraform.sub_blocks(r.block, "settings")
	some db_flags in terraform.sub_blocks(settings, "database_flags")
	name := terraform.string_attr(db_flags, "name")
	name == "external scripts enabled"
	value := terraform.string_attr(db_flags, "value")
	value != "off"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Server instance %q has external scripts enabled (value=%q)", [r.name, value]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
