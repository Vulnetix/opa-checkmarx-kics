# KICS-TF-AZURE-010
# Ported from: mssql_server_auditing_disabled
# Severity: Medium

package vulnetix.rules.kics_tf_azure_mssql_auditing_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-010",
	"name": "MSSQL server auditing disabled",
	"description": "Azure SQL Server does not have auditing enabled. Without auditing, database activities are not logged, making it impossible to detect or investigate security breaches.",
	"languages": ["terraform", "hcl"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778", "CWE-223"],
	"tags": ["azure", "database", "mssql", "auditing", "logging"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_mssql_server")
	block := rb.block
	name := rb.name

	# Check if server_extended_auditing_policy block is missing
	not tf.has_sub_block(block, "extended_auditing_policy")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MSSQL Server '%s' does not have extended auditing policy configured. Add extended_auditing_policy block", [name]),
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
	some rb in tf.resource_blocks(content, "azurerm_mssql_server")
	block := rb.block
	name := rb.name

	# Check if extended_auditing_policy has enabled set to false
	tf.has_sub_block(block, "extended_auditing_policy")
	audit_blocks := tf.sub_blocks(block, "extended_auditing_policy")
	some ab in audit_blocks

	enabled := tf.bool_attr(ab, "enabled")
	enabled == false

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MSSQL Server '%s' has extended auditing policy disabled (enabled = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}

# Also check for azurerm_mssql_server_extended_auditing_policy standalone resource
findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_mssql_server_extended_auditing_policy")
	block := rb.block
	name := rb.name

	# enabled set to false
	enabled := tf.bool_attr(block, "enabled")
	enabled == false

	line_num := tf.line_number(content, block, "enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MSSQL Server extended auditing policy '%s' is disabled (enabled = false)", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
