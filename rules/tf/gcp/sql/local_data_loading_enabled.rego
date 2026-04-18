# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_with_local_data_loading_enabled

package vulnetix.rules.kics_tf_gcp_sql_local_data_loading

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-059",
	"name": "SQL Server instance has local infile data loading enabled",
	"description": "SQL Server database instances should have local_infile disabled to prevent loading data from local files.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-94"],
	"tags": ["terraform", "gcp", "sql", "sqlserver", "file-inclusion"],
}

findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	version := terraform.string_attr(r.block, "database_version")
	contains(lower(version), "sqlserver")
	some settings in terraform.sub_blocks(r.block, "settings")
	some db_flags in terraform.sub_blocks(settings, "database_flags")
	name := terraform.string_attr(db_flags, "name")
	name == "local_infile"
	value := terraform.string_attr(db_flags, "value")
	value == "on"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SQL Server instance %q has local_infile data loading enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
