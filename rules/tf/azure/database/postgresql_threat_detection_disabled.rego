# KICS-TF-AZURE-014
# Ported from: postgresql_server_threat_detection_policy_disabled
# Severity: Medium

package vulnetix.rules.kics_tf_azure_postgresql_threat_detection_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-014",
	"name": "PostgreSQL threat detection disabled",
	"description": "Azure PostgreSQL server does not have Advanced Threat Protection enabled. This feature detects anomalous activities indicating unusual and potentially harmful attempts to access or exploit databases.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778", "CWE-223"],
	"tags": ["azure", "database", "postgresql", "threat-detection", "security"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_postgresql_server")
	block := rb.block
	name := rb.name

	# threat_detection_policy block not defined
	not tf.has_sub_block(block, "threat_detection_policy")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server '%s' does not have threat detection policy configured. Add threat_detection_policy block", [name]),
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

	tf.has_sub_block(block, "threat_detection_policy")
	tdp_blocks := tf.sub_blocks(block, "threat_detection_policy")
	some tdp in tdp_blocks

	# enabled is false
	enabled := tf.bool_attr(tdp, "enabled")
	enabled == false

	line_num := tf.line_number(content, tdp, "enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("PostgreSQL server '%s' has threat detection policy disabled (enabled = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
