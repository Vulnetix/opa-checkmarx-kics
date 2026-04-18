# KICS-TF-AZURE-045
# Ported from: cosmos_db_account_without_tags (for Key Vault secrets)
# Severity: Low

package vulnetix.rules.kics_tf_azure_keyvault_secret_without_tags

import data.vulnetix.kics.tf as tf
import rego.v1

metadata := {
	"id": "KICS-TF-AZURE-045",
	"name": "Key Vault secret without tags",
	"description": "Azure Key Vault secret does not have tags defined. Tags help with resource organization, cost tracking, and compliance management.",
	"languages": ["terraform", "hcl"],
	"severity": "low",
	"level": "info",
	"kind": "iac",
	"cwe": [],
	"tags": ["azure", "keyvault", "secret", "tags", "governance"],
}

findings contains finding if {
	some path, content in input.file_contents
	tf.is_tf(path)
	some rb in tf.resource_blocks(content, "azurerm_key_vault_secret")
	block := rb.block
	name := rb.name

	# tags not configured
	not tf.has_key(block, "tags")

	line_num := tf.line_number_for_block(content, block)
	snippet := tf.extract_context(content, line_num, 5)

	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Key Vault secret '%s' does not have tags. Add tags for better resource management", [name]),
		"artifact_uri": path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line_num,
		"snippet": snippet,
	}
}
