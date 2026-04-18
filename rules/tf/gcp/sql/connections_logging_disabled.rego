# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_without_connections_logging

package vulnetix.rules.kics_tf_gcp_sql_connections_logging

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-066",
	"name": "SQL instance connection logging is not configured",
	"description": "SQL database instances should have connection logging enabled for security monitoring.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["terraform", "gcp", "sql", "logging"],
}

findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	version := terraform.string_attr(r.block, "database_version")
	contains(lower(version), "postgres")
	some settings in terraform.sub_blocks(r.block, "settings")
	some db_flags in terraform.sub_blocks(settings, "database_flags")
	name := terraform.string_attr(db_flags, "name")
	name == "log_connections"
	value := terraform.string_attr(db_flags, "value")
	value != "on"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL instance %q does not have log_connections enabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "medium",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
