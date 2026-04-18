# KICS-TF-AZURE-006
# Ported from: key_vault_purge_protection_is_enabled
# Severity: High

package vulnetix.rules.kics_tf_azure_key_vault_purge_protection_disabled

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-006",
	"name": "Key Vault purge protection disabled",
	"description": "Azure Key Vault does not have purge protection enabled. Without purge protection, keys can be permanently deleted, leading to data loss and inability to recover encrypted resources.",
	"languages": ["terraform", "hcl"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-522", "CWE-312"],
	"tags": ["azure", "keyvault", "purge-protection", "recovery"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_key_vault")
	block := rb.block
	name := rb.name

	# purge_protection_enabled not defined
	not tf.has_key(block, "purge_protection_enabled")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 8)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault '%s' does not have purge protection enabled. Add purge_protection_enabled = true", [name]),
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
	some rb in tf.resource_blocks(content, "azurerm_key_vault")
	block := rb.block
	name := rb.name

	# purge_protection_enabled explicitly set to false
	enabled := tf.bool_attr(block, "purge_protection_enabled")
	enabled == false

	line_num := tf.line_number(content, block, "purge_protection_enabled")
	snippet := tf.extract_context(content, line_num, 3)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault '%s' has purge_protection_enabled = false. Secrets can be permanently deleted", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
