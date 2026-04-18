# KICS-TF-AZURE-039
# Ported from: azure_cognitive_search_public_network_access_enabled
# Severity: High

package vulnetix.rules.kics_tf_azure_cognitive_search_public_access

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-039",
	"name": "Cognitive Search public network access enabled",
	"description": "Azure Cognitive Search service has public network access enabled. This exposes the search service to the internet. Use private endpoints for secure access.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284", "CWE-306"],
	"tags": ["azure", "search", "cognitive", "public-access", "network"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_search_service")
	block := rb.block
	name := rb.name

	# public_network_access_enabled not defined
	not tf.has_key(block, "public_network_access_enabled")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Search service '%s' does not explicitly disable public network access. Add public_network_access_enabled = false", [name]),
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
	some rb in tf.resource_blocks(content, "azurerm_search_service")
	block := rb.block
	name := rb.name

	# public_network_access_enabled is true
	enabled := tf.bool_attr(block, "public_network_access_enabled")
	enabled == true

	line_num := tf.line_number(content, block, "public_network_access_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Search service '%s' has public network access enabled. Set public_network_access_enabled = false", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
