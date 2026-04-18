# KICS-TF-AZURE-026
# Ported from: postgresql_server_without_connection_throttling
# Severity: Medium

package vulnetix.rules.kics_tf_azure_postgresql_connection_throttling

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-026",
	"name": "PostgreSQL connection throttling disabled",
	"description": "Azure PostgreSQL server does not have connection throttling configured. Connection throttling helps prevent denial-of-service attacks by limiting the number of concurrent connections per user.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-400", "CWE-770"],
	"tags": ["azure", "database", "postgresql", "connection-throttling", "dos"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_postgresql_server")
	block := rb.block
	name := rb.name

	# Check connection_throttle.enable in server configuration
	tf.has_sub_block(block, "server_configuration")
	sc_blocks := tf.sub_blocks(block, "server_configuration")
	some sc in sc_blocks

	# Check if connection_throttle.enable is set to off
	config_name := tf.string_attr(sc, "name")
	config_name == "connection_throttle.enable"
	config_value := tf.string_attr(sc, "value")
	config_value == "off"

	line_num := tf.line_number(content, sc, "value")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server '%s' has connection throttling disabled (connection_throttle.enable = off)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Also check in azurerm_postgresql_configuration resource
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_postgresql_configuration")
	block := rb.block
	name := rb.name

	config_name := tf.string_attr(block, "name")
	config_name == "connection_throttle.enable"
	config_value := tf.string_attr(block, "value")
	config_value == "off"

	line_num := tf.line_number(content, block, "value")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL configuration '%s' disables connection throttling (connection_throttle.enable = off)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
