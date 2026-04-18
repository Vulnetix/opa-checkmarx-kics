# KICS-TF-AZURE-002
# Ported from: mssql_server_public_network_access_enabled
# Severity: Critical

package vulnetix.rules.kics_tf_azure_mssql_server_public_access

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-002",
	"name": "MSSQL Server public network access enabled",
	"description": "Azure SQL Server has public network access enabled, exposing the database to potential attacks from the internet. Disable public network access and use private endpoints instead.",
	"languages": ["terraform", "hcl"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284", "CWE-306"],
	"tags": ["azure", "database", "mssql", "public-access", "network"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_mssql_server")
	block := rb.block
	name := rb.name

	# Check if public_network_access_enabled is not defined (defaults to true in older versions)
	not tf.has_key(block, "public_network_access_enabled")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 5)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MSSQL Server '%s' does not explicitly disable public network access. Add public_network_access_enabled = false", [name]),
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

	# Check if public_network_access_enabled = true
	tf.bool_attr(block, "public_network_access_enabled")

	line_num := tf.line_number(content, block, "public_network_access_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MSSQL Server '%s' has public network access enabled. Set public_network_access_enabled = false and use private endpoints", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
