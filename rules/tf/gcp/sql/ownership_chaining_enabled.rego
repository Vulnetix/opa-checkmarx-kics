# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_with_ownership_chaining_enabled

package vulnetix.rules.kics_tf_gcp_sql_ownership_chaining

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-058",
	"name": "SQL Server instance has cross-database ownership chaining enabled",
	"description": "SQL Server database instances should have cross-database ownership chaining disabled for security.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "sql", "sqlserver"],
}

findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	version := terraform.string_attr(r.block, "database_version")
	contains(lower(version), "sqlserver")
	some settings in terraform.sub_blocks(r.block, "settings")
	some db_flags in terraform.sub_blocks(settings, "database_flags")
	name := terraform.string_attr(db_flags, "name")
	name == "cross db ownership chaining"
	value := terraform.string_attr(db_flags, "value")
	value == "on"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Server instance %q has cross-database ownership chaining enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
