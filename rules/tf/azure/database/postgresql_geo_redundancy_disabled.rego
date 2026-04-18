# KICS-TF-AZURE-022
# Ported from: geo_redundancy_is_disabled
# Severity: Low

package vulnetix.rules.kics_tf_azure_postgresql_geo_redundancy_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-022",
	"name": "PostgreSQL geo-redundant backup disabled",
	"description": "Azure PostgreSQL server does not have geo-redundant backup enabled. Without geo-redundancy, backups are only stored in the primary region, leaving data vulnerable to regional disasters.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": ["CWE-1284"],
	"tags": ["azure", "database", "postgresql", "backup", "geo-redundancy", "disaster-recovery"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_postgresql_server")
	block := rb.block
	name := rb.name

	# geo_redundant_backup_enabled not defined
	not tf.has_key(block, "geo_redundant_backup_enabled")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server '%s' does not have geo-redundant backup enabled. Add geo_redundant_backup_enabled = true", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_postgresql_server")
	block := rb.block
	name := rb.name

	# geo_redundant_backup_enabled is false
	enabled := tf.bool_attr(block, "geo_redundant_backup_enabled")
	enabled == false

	line_num := tf.line_number(content, block, "geo_redundant_backup_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server '%s' has geo-redundant backup disabled (geo_redundant_backup_enabled = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
