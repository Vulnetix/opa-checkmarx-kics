# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_with_exposed_show_privileges

package vulnetix.rules.kics_tf_gcp_sql_exposed_show_privileges

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-068",
	"name": "SQL instance exposes SHOW privileges",
	"description": "SQL database instances should not expose unnecessary SHOW privileges that could reveal sensitive information.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": ["CWE-200"],
	"tags": ["terraform", "gcp", "sql", "information-disclosure"],
}

findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	version := terraform.string_attr(r.block, "database_version")
	contains(lower(version), "mysql")
	some settings in terraform.sub_blocks(r.block, "settings")
	some db_flags in terraform.sub_blocks(settings, "database_flags")
	name := terraform.string_attr(db_flags, "name")
	name == "skip_show_database"
	value := terraform.string_attr(db_flags, "value")
	value == "off"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MySQL instance %q has skip_show_database disabled (SHOW DATABASES privilege exposed)", [r.name]),
		"artifact_uri": r.path,
		"severity": "low",
		"level": "info",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
