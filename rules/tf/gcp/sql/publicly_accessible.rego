# Ported from Checkmarx KICS
# Source: assets/queries/terraform/gcp/sql_db_instance_is_publicly_accessible

package vulnetix.rules.kics_tf_gcp_sql_publicly_accessible

import rego.v1

import data.vulnetix.kics.tf as terraform

metadata := {
	"id": "KICS-TF-GCP-021",
	"name": "Cloud SQL instance is publicly accessible",
	"description": "Cloud SQL database instances should not be publicly accessible. Authorized networks should be restricted to trusted IP ranges.",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"tags": ["terraform", "gcp", "sql", "public-access"],
}

# Check if authorized_networks contains 0.0.0.0/0
findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	some block in terraform.sub_blocks(r.block, "settings")
	some ip_block in terraform.sub_blocks(block, "ip_configuration")
	some auth_block in terraform.sub_blocks(ip_block, "authorized_networks")
	value := terraform.string_attr(auth_block, "value")
	contains(value, "0.0.0.0")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cloud SQL instance %q allows access from unrestricted network %q", [r.name, value]),
		"artifact_uri": r.path,
		"severity": "critical",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}

# Check if ipv4_enabled is true without authorized_networks
findings contains finding if {
	some r in terraform.resources("google_sql_database_instance")
	some block in terraform.sub_blocks(r.block, "settings")
	some ip_block in terraform.sub_blocks(block, "ip_configuration")
	not terraform.has_sub_block(ip_block, "authorized_networks")
	terraform.bool_attr(ip_block, "ipv4_enabled") == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cloud SQL instance %q has ipv4_enabled without authorized_networks restriction", [r.name]),
		"artifact_uri": r.path,
		"severity": "critical",
		"level": "error",
		"start_line": 1,
		"snippet": sprintf("google_sql_database_instance.%s", [r.name]),
	}
}
