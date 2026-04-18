# KICS-TF-AZURE-027
# Ported from: postgresql_log_checkpoints_disabled
# Severity: Low

package vulnetix.rules.kics_tf_azure_postgresql_log_checkpoints_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-027",
	"name": "PostgreSQL log checkpoints disabled",
	"description": "Azure PostgreSQL server does not have checkpoint logging enabled. Checkpoint logs are important for diagnosing performance issues and understanding database activity.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"tags": ["azure", "database", "postgresql", "logging", "checkpoints", "audit"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_postgresql_configuration")
	block := rb.block
	name := rb.name

	config_name := tf.string_attr(block, "name")
	config_name == "log_checkpoints"
	config_value := tf.string_attr(block, "value")
	config_value == "off"

	line_num := tf.line_number(content, block, "value")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL configuration '%s' has checkpoint logging disabled (log_checkpoints = off)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
