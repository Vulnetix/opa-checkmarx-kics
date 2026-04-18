# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_backup_disabled

package vulnetix.rules.kics_tf_gcp_sql_backup_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-023",
	"name": "Cloud SQL instance backup is disabled",
	"description": "Cloud SQL database instances should have automated backups enabled for disaster recovery.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"tags": ["terraform", "gcp", "sql", "backup"],
}

# Check if backup_configuration is missing
findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	some block in terraform.sub_blocks(r.block, "settings")
	not terraform.has_sub_block(block, "backup_configuration")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cloud SQL instance %q does not have backup_configuration configured", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}

# Check if backup is explicitly disabled
findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	some block in terraform.sub_blocks(r.block, "settings")
	some backup_block in terraform.sub_blocks(block, "backup_configuration")
	terraform.bool_attr(backup_block, "enabled") == false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cloud SQL instance %q has automated backups disabled", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "warning",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
