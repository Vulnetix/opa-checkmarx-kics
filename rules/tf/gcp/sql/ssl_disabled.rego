# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_with_ssl_disabled

package vulnetix.rules.kics_tf_gcp_sql_ssl_disabled

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-022",
	"name": "Cloud SQL instance SSL is disabled",
	"description": "Cloud SQL database instances should require SSL/TLS for connections to encrypt data in transit.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319"],
	"tags": ["terraform", "gcp", "sql", "ssl", "tls"],
}

# Check if ip_configuration is missing
findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	some block in terraform.sub_blocks(r.block, "settings")
	not terraform.has_sub_block(block, "ip_configuration")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cloud SQL instance %q settings does not have ip_configuration configured for SSL", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}

# Check if require_ssl is explicitly false
findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	some block in terraform.sub_blocks(r.block, "settings")
	some ip_block in terraform.sub_blocks(block, "ip_configuration")
	terraform.is_false(ip_block, "require_ssl")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cloud SQL instance %q has require_ssl disabled in ip_configuration", [r.name]),
		"artifact_uri": r.path,
		"severity": "high",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
