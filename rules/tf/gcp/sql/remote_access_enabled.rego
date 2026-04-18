# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_with_remote_access_enabled

package vulnetix.rules.kics_tf_gcp_sql_remote_access

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-054",
	"name": "SQL Server instance has remote access enabled",
	"description": "SQL Server database instances should have remote access disabled to prevent remote connections.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "sql", "sqlserver", "remote-access"],
}

# Check for SQL Server instances with remote access enabled
findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	version := terraform.string_attr(r.block, "database_version")
	contains(lower(version), "sqlserver")
	some settings in terraform.sub_blocks(r.block, "settings")
	some db_flags in terraform.sub_blocks(settings, "database_flags")
	name := terraform.string_attr(db_flags, "name")
	name == "remote access"
	value := terraform.string_attr(db_flags, "value")
	value == "on"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Server instance %q has remote access enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
