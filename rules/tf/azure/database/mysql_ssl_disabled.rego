# KICS-TF-AZURE-007
# Ported from: mysql_ssl_connection_disabled
# Severity: High

package vulnetix.rules.kics_tf_azure_mysql_ssl_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-007",
	"name": "MySQL SSL enforcement disabled",
	"description": "Azure MySQL server has SSL enforcement disabled. Connections to the database are not encrypted, exposing data in transit to eavesdropping and man-in-the-middle attacks.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-319", "CWE-326"],
	"tags": ["azure", "database", "mysql", "ssl", "encryption", "tls"],
}

# For older azurerm_mysql_server resource (deprecated but still used)
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_mysql_server")
	block := rb.block
	name := rb.name

	# ssl_enforcement_enabled is false
	enabled := tf.bool_attr(block, "ssl_enforcement_enabled")
	enabled == false

	line_num := tf.line_number(content, block, "ssl_enforcement_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MySQL server '%s' has SSL enforcement disabled. Data in transit is unencrypted", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# For newer azurerm_mysql_flexible_server resource
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_mysql_flexible_server")
	block := rb.block
	name := rb.name

	# Check ssl block
	tf.has_sub_block(block, "ssl")
	ssl_block := tf.sub_blocks(block, "ssl")[0]

	# ssl_mode is Disabled or Prefer (not RequireSecure)
	ssl_mode := tf.string_attr(ssl_block, "mode")
	ssl_mode in ["Disabled", "Prefer"]

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MySQL flexible server '%s' has SSL mode set to '%s'. Use 'RequireSecure' instead", [name, ssl_mode]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
