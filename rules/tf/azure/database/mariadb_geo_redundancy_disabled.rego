# KICS-TF-AZURE-050
# Ported from: mariadb_server_georedundant_backup_disabled
# Severity: Low

package vulnetix.rules.kics_tf_azure_mariadb_geo_redundancy_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-050",
	"name": "MariaDB geo-redundant backup disabled",
	"description": "Azure Database for MariaDB does not have geo-redundant backup enabled. Without geo-redundancy, backups are only stored in the primary region, leaving data vulnerable to regional disasters.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": ["CWE-1284"],
	"tags": ["azure", "database", "mariadb", "backup", "geo-redundancy", "disaster-recovery"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_mariadb_server")
	block := rb.block
	name := rb.name

	# geo_redundant_backup_enabled not defined
	not tf.has_key(block, "geo_redundant_backup_enabled")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MariaDB server '%s' does not have geo-redundant backup configured. Add geo_redundant_backup_enabled = true", [name]),
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
	some rb in tf.resource_blocks(content, "azurerm_mariadb_server")
	block := rb.block
	name := rb.name

	# geo_redundant_backup_enabled is false
	enabled := tf.bool_attr(block, "geo_redundant_backup_enabled")
	enabled == false

	line_num := tf.line_number(content, block, "geo_redundant_backup_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MariaDB server '%s' has geo-redundant backup disabled", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
