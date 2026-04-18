# KICS-TF-AZURE-029
# Ported from: postgresql_log_disconnections_not_set
# Severity: Low

package vulnetix.rules.kics_tf_azure_postgresql_log_disconnections_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-029",
	"name": "PostgreSQL log disconnections disabled",
	"description": "Azure PostgreSQL server does not have disconnection logging enabled. Disconnection logs help track session lifecycle and can aid in security investigations.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["azure", "database", "postgresql", "logging", "disconnections", "audit"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_postgresql_configuration")
	block := rb.block
	name := rb.name

	config_name := tf.string_attr(block, "name")
	config_name == "log_disconnections"
	config_value := tf.string_attr(block, "value")
	config_value == "off"

	line_num := tf.line_number(content, block, "value")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL configuration '%s' has disconnection logging disabled (log_disconnections = off)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
