# KICS-TF-AZURE-044
# Ported from: cosmosdb_account_ip_range_filter_not_set
# Severity: High

package vulnetix.rules.kics_tf_azure_cosmosdb_ip_filter_missing

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-044",
	"name": "Cosmos DB IP range filter not configured",
	"description": "Azure Cosmos DB account does not have IP range filter configured. Without IP restrictions, the database is accessible from any IP address, increasing exposure to attacks.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284", "CWE-306"],
	"tags": ["azure", "cosmosdb", "database", "ip-filter", "network"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_cosmosdb_account")
	block := rb.block
	name := rb.name

	# ip_range_filter not configured or empty
	not tf.has_key(block, "ip_range_filter")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cosmos DB account '%s' does not have IP range filter configured. Add ip_range_filter to restrict access", [name]),
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
	some rb in tf.resource_blocks(content, "azurerm_cosmosdb_account")
	block := rb.block
	name := rb.name

	# ip_range_filter is empty
	ip_filter := tf.string_attr(block, "ip_range_filter")
	ip_filter == ""

	line_num := tf.line_number(content, block, "ip_range_filter")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Cosmos DB account '%s' has empty IP range filter. Add valid IP ranges", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
